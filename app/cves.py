"""Recent CVEs from NVD, enriched with CISA KEV, FIRST EPSS and public PoC/exploit sources."""
from __future__ import annotations

import asyncio
import csv
import io
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone

import httpx

from . import config
from .httpclient import get_client, github_headers

log = logging.getLogger("cti.cves")

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
NOMISEC_TREE = "https://api.github.com/repos/nomi-sec/PoC-in-GitHub/git/trees/master"
NOMISEC_RAW = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
EXPLOITDB_CSV = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
CACHE_FILE = config.DATA_DIR / "cves.json"


def _https(url: str) -> bool:
    return isinstance(url, str) and url.startswith(("https://", "http://"))


def _parse_nvd(v: dict) -> dict | None:
    c = v.get("cve", {})
    cid = c.get("id")
    if not cid or c.get("vulnStatus") == "Rejected":
        return None
    desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
    score = sev = vector = ver = None
    metrics = c.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key) or []
        if not arr:
            continue
        m = next((x for x in arr if x.get("type") == "Primary"), arr[0])
        d = m.get("cvssData", {})
        score, vector, ver = d.get("baseScore"), d.get("vectorString"), d.get("version")
        sev = d.get("baseSeverity") or m.get("baseSeverity")
        break
    cwes = sorted({
        d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
        if d.get("value", "").startswith("CWE-")
    })
    refs = [
        {"url": r["url"], "tags": r.get("tags", [])}
        for r in c.get("references", []) if _https(r.get("url"))
    ][:40]
    products: list[str] = []
    for conf in c.get("configurations", []):
        for node in conf.get("nodes", []):
            for match in node.get("cpeMatch", []):
                parts = match.get("criteria", "").split(":")
                if len(parts) > 5 and match.get("vulnerable", True):
                    p = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if p not in products:
                        products.append(p)
    pocs = [
        {"source": "NVD (Exploit ref)", "url": r["url"], "title": r["url"]}
        for r in refs if "Exploit" in r["tags"]
    ]
    return {
        "id": cid,
        "published": c.get("published"),
        "modified": c.get("lastModified"),
        "status": c.get("vulnStatus"),
        "description": desc,
        "score": score,
        "severity": (sev or "NONE").upper() if score is not None else "N/A",
        "vector": vector,
        "cvss_version": ver,
        "cwes": cwes,
        "products": products[:8],
        "refs": refs,
        "kev": None,
        "epss": None,
        "epss_pct": None,
        "pocs": pocs,
    }


class CVEService:
    def __init__(self) -> None:
        self.items: list[dict] = []
        self.last_updated: float | None = None
        self.errors: dict[str, str] = {}
        self._lock = asyncio.Lock()
        self._kev: dict[str, dict] = {}
        self._kev_at = 0.0
        self._edb: dict[str, list[dict]] = {}
        self._edb_at = 0.0
        self._nomisec_cache: dict[str, tuple[float, list[dict]]] = {}
        self._gh_search_cache: dict[str, tuple[float, list[dict]]] = {}
        if CACHE_FILE.is_file():
            try:
                data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
                self.items, self.last_updated = data["items"], data["last_updated"]
            except Exception:  # noqa: BLE001
                log.warning("CVE cache unreadable, ignoring")

    # --- NVD ---------------------------------------------------------------------
    async def _fetch_nvd(self) -> list[dict]:
        client = get_client()
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=config.CVE_DAYS)
        fmt = "%Y-%m-%dT%H:%M:%S.000"
        headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        delay = 1.0 if config.NVD_API_KEY else 6.5  # NVD public rate limit: 5 req / 30 s
        out: list[dict] = []
        start_index, total = 0, None
        while total is None or start_index < total:
            params = {
                "pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt),
                "resultsPerPage": 2000, "startIndex": start_index,
            }
            data = None
            for attempt in range(4):
                try:
                    r = await client.get(NVD_URL, params=params, headers=headers, timeout=90)
                    if r.status_code in (403, 429, 503):
                        raise httpx.HTTPStatusError("rate limited", request=r.request, response=r)
                    r.raise_for_status()
                    data = r.json()
                    break
                except (httpx.HTTPError, ValueError) as e:
                    log.warning("NVD request failed (attempt %d): %s", attempt + 1, e)
                    await asyncio.sleep(delay * (attempt + 2))
            if data is None:
                raise RuntimeError("NVD unreachable")
            total = data.get("totalResults", 0)
            for v in data.get("vulnerabilities", []):
                item = _parse_nvd(v)
                if item:
                    out.append(item)
            start_index += data.get("resultsPerPage", 2000) or 2000
            if start_index < total:
                await asyncio.sleep(delay)
        return out

    # --- CISA KEV ----------------------------------------------------------------
    async def _load_kev(self) -> None:
        if self._kev and time.time() - self._kev_at < 6 * 3600:
            return
        r = await get_client().get(KEV_URL)
        r.raise_for_status()
        self._kev = {v["cveID"]: v for v in r.json().get("vulnerabilities", [])}
        self._kev_at = time.time()

    # --- Exploit-DB ----------------------------------------------------------------
    async def _load_exploitdb(self) -> None:
        if self._edb and time.time() - self._edb_at < 24 * 3600:
            return
        r = await get_client().get(EXPLOITDB_CSV, timeout=120)
        r.raise_for_status()

        def parse(text: str) -> dict[str, list[dict]]:
            idx: dict[str, list[dict]] = {}
            for row in csv.DictReader(io.StringIO(text)):
                for code in (row.get("codes") or "").split(";"):
                    code = code.strip().upper()
                    if code.startswith("CVE-"):
                        idx.setdefault(code, []).append({
                            "source": "Exploit-DB",
                            "url": f"https://www.exploit-db.com/exploits/{row['id']}",
                            "title": row.get("description", "")[:200],
                            "verified": row.get("verified") == "1",
                        })
            return idx

        self._edb = await asyncio.to_thread(parse, r.text)
        self._edb_at = time.time()

    # --- EPSS --------------------------------------------------------------------
    async def _load_epss(self, ids: list[str]) -> dict[str, tuple[float, float]]:
        client = get_client()
        out: dict[str, tuple[float, float]] = {}
        for i in range(0, len(ids), 100):
            chunk = ids[i : i + 100]
            try:
                r = await client.get(EPSS_URL, params={"cve": ",".join(chunk), "limit": 100})
                r.raise_for_status()
                for d in r.json().get("data", []):
                    out[d["cve"]] = (float(d["epss"]), float(d["percentile"]))
            except (httpx.HTTPError, ValueError, KeyError) as e:
                log.warning("EPSS chunk failed: %s", e)
        return out

    # --- nomi-sec PoC-in-GitHub ----------------------------------------------------
    async def _load_nomisec(self, ids: list[str]) -> dict[str, list[dict]]:
        client = get_client()
        years = sorted({cid.split("-")[1] for cid in ids})
        r = await client.get(NOMISEC_TREE, headers=github_headers())
        r.raise_for_status()
        year_sha = {t["path"]: t["sha"] for t in r.json().get("tree", []) if t.get("type") == "tree"}
        available: set[str] = set()
        for y in years:
            if y not in year_sha:
                continue
            ry = await client.get(f"{NOMISEC_TREE.rsplit('/', 1)[0]}/{year_sha[y]}", headers=github_headers())
            if ry.status_code != 200:
                continue
            available.update(t["path"][:-5] for t in ry.json().get("tree", []) if t["path"].endswith(".json"))

        wanted = [cid for cid in ids if cid in available]
        out: dict[str, list[dict]] = {}
        sem = asyncio.Semaphore(8)
        now = time.time()

        async def one(cid: str):
            cached = self._nomisec_cache.get(cid)
            if cached and now - cached[0] < 6 * 3600:
                out[cid] = cached[1]
                return
            async with sem:
                try:
                    rr = await client.get(NOMISEC_RAW.format(year=cid.split("-")[1], cve=cid))
                    rr.raise_for_status()
                    repos = [
                        {
                            "source": "GitHub",
                            "url": x["html_url"],
                            "title": x.get("full_name") or x["html_url"],
                            "description": (x.get("description") or "")[:200],
                            "stars": x.get("stargazers_count", 0),
                        }
                        for x in rr.json() if _https(x.get("html_url"))
                    ]
                    repos.sort(key=lambda x: x["stars"], reverse=True)
                    self._nomisec_cache[cid] = (now, repos[:15])
                    out[cid] = repos[:15]
                except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
                    log.debug("nomi-sec %s failed: %s", cid, e)

        await asyncio.gather(*(one(c) for c in wanted))
        return out

    # --- Main refresh ----------------------------------------------------------------
    async def refresh(self) -> None:
        async with self._lock:
            self.errors = {}
            try:
                items = await self._fetch_nvd()
            except Exception as e:  # noqa: BLE001
                self.errors["nvd"] = str(e)
                log.exception("NVD fetch failed")
                return

            for name, loader in (("kev", self._load_kev), ("exploitdb", self._load_exploitdb)):
                try:
                    await loader()
                except Exception as e:  # noqa: BLE001
                    self.errors[name] = str(e)
                    log.warning("%s load failed: %s", name, e)

            by_id = {it["id"]: it for it in items}
            # Add CVEs recently added to KEV even if NVD published them earlier.
            kev_cutoff = (datetime.now(timezone.utc) - timedelta(days=config.CVE_DAYS)).date().isoformat()
            for cid, k in self._kev.items():
                if cid not in by_id and k.get("dateAdded", "") >= kev_cutoff:
                    by_id[cid] = {
                        "id": cid, "published": k.get("dateAdded") + "T00:00:00.000", "modified": None,
                        "status": "KEV (older CVE)", "description": k.get("shortDescription", ""),
                        "score": None, "severity": "N/A", "vector": None, "cvss_version": None,
                        "cwes": k.get("cwes", []) or [],
                        "products": [f"{k.get('vendorProject', '')} {k.get('product', '')}".strip()],
                        "refs": [], "kev": None, "epss": None, "epss_pct": None, "pocs": [],
                    }

            ids = list(by_id)
            for cid in ids:
                k = self._kev.get(cid)
                if k:
                    by_id[cid]["kev"] = {
                        "dateAdded": k.get("dateAdded"), "dueDate": k.get("dueDate"),
                        "ransomware": k.get("knownRansomwareCampaignUse"),
                        "name": k.get("vulnerabilityName"), "action": k.get("requiredAction"),
                    }

            epss, nomisec = await asyncio.gather(
                self._load_epss(ids), self._safe_nomisec(ids)
            )
            for cid, it in by_id.items():
                if cid in epss:
                    it["epss"], it["epss_pct"] = epss[cid]
                seen = {p["url"] for p in it["pocs"]}
                for p in nomisec.get(cid, []) + self._edb.get(cid, []):
                    if p["url"] not in seen:
                        it["pocs"].append(p)
                        seen.add(p["url"])

            self.items = sorted(by_id.values(), key=lambda x: x.get("published") or "", reverse=True)
            self.last_updated = time.time()
            await asyncio.to_thread(
                CACHE_FILE.write_text,
                json.dumps({"items": self.items, "last_updated": self.last_updated}),
                "utf-8",
            )
            log.info("CVE refresh: %d CVEs, %d with PoC", len(self.items), sum(1 for i in self.items if i["pocs"]))

    async def _safe_nomisec(self, ids: list[str]) -> dict[str, list[dict]]:
        try:
            return await self._load_nomisec(ids)
        except Exception as e:  # noqa: BLE001
            self.errors["nomisec"] = str(e)
            log.warning("nomi-sec load failed: %s", e)
            return {}

    async def github_search(self, cve_id: str) -> list[dict]:
        """On-demand GitHub repository search for a single CVE (cached 1h)."""
        cve_id = cve_id.upper()
        if not CVE_ID_RE.match(cve_id):
            raise ValueError("invalid CVE id")
        cached = self._gh_search_cache.get(cve_id)
        if cached and time.time() - cached[0] < 3600:
            return cached[1]
        r = await get_client().get(
            "https://api.github.com/search/repositories",
            params={"q": f'"{cve_id}"', "sort": "stars", "order": "desc", "per_page": 15},
            headers=github_headers(),
        )
        if r.status_code in (403, 429):
            raise RuntimeError("GitHub rate limit — GITHUB_TOKEN ayarlayın")
        r.raise_for_status()
        res = [
            {
                "source": "GitHub search", "url": x["html_url"], "title": x["full_name"],
                "description": (x.get("description") or "")[:200], "stars": x.get("stargazers_count", 0),
            }
            for x in r.json().get("items", []) if _https(x.get("html_url"))
        ]
        self._gh_search_cache[cve_id] = (time.time(), res)
        return res

    def snapshot(self) -> dict:
        return {
            "items": self.items, "last_updated": self.last_updated,
            "days": config.CVE_DAYS, "errors": self.errors,
        }
