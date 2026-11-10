"""MITRE ATT&CK data (STIX 2.1 from mitre-attack/attack-stix-data) -> compact matrix JSON."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time

from . import config
from .httpclient import get_client

log = logging.getLogger("cti.attack")

DOMAINS = {
    "enterprise-attack": "Enterprise",
    "mobile-attack": "Mobile",
    "ics-attack": "ICS",
}
STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{d}/{d}.json"
_CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
_MDLINK_RE = re.compile(r"\[([^\]]+)\]\([^)]+\)")


def _ext(obj: dict) -> tuple[str | None, str | None]:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"):
            return ref.get("external_id"), ref.get("url")
    return None, None


def _active(o: dict) -> bool:
    return not o.get("revoked") and not o.get("x_mitre_deprecated")


def _short(desc: str, n: int = 400) -> str:
    desc = _MDLINK_RE.sub(r"\1", _CITATION_RE.sub("", desc or ""))
    desc = " ".join(desc.split())
    return desc if len(desc) <= n else desc[:n].rsplit(" ", 1)[0] + "…"


def parse_bundle(bundle: dict, domain: str) -> dict:
    objs = bundle.get("objects", [])
    by_id = {o["id"]: o for o in objs if "id" in o}
    version = next((o.get("x_mitre_version") for o in objs if o.get("type") == "x-mitre-collection"), None)
    matrix = next(o for o in objs if o.get("type") == "x-mitre-matrix" and _active(o))

    tactics = []
    for ref in matrix.get("tactic_refs", []):
        t = by_id.get(ref)
        if t and _active(t):
            tid, url = _ext(t)
            tactics.append({"id": tid, "name": t["name"], "short": t["x_mitre_shortname"], "url": url})

    techniques: dict[str, dict] = {}
    stix_to_tid: dict[str, str] = {}
    for o in objs:
        if o.get("type") != "attack-pattern" or not _active(o):
            continue
        tid, url = _ext(o)
        if not tid:
            continue
        stix_to_tid[o["id"]] = tid
        techniques[tid] = {
            "id": tid,
            "name": o["name"],
            "sub": bool(o.get("x_mitre_is_subtechnique")),
            "tactics": [k["phase_name"] for k in o.get("kill_chain_phases", [])],
            "platforms": o.get("x_mitre_platforms", []),
            "desc": _short(o.get("description", "")),
            "url": url,
        }

    # Parent -> subtechniques
    subs: dict[str, list[str]] = {}
    for tid, t in techniques.items():
        if t["sub"]:
            subs.setdefault(tid.split(".")[0], []).append(tid)
    for parent, lst in subs.items():
        lst.sort()
        if parent in techniques:
            techniques[parent]["subs"] = lst

    # Groups / software / campaigns -> techniques (via "uses" relationships)
    actors: dict[str, dict] = {}
    for o in objs:
        if o.get("type") in ("intrusion-set", "malware", "tool", "campaign") and _active(o):
            aid, url = _ext(o)
            actors[o["id"]] = {
                "id": aid or o["id"], "name": o.get("name"), "type": o["type"],
                "aliases": [a for a in o.get("aliases", o.get("x_mitre_aliases", [])) if a != o.get("name")][:10],
                "url": url, "techniques": set(),
            }
    for o in objs:
        if (
            o.get("type") == "relationship" and o.get("relationship_type") == "uses" and _active(o)
            and o.get("source_ref") in actors and o.get("target_ref") in stix_to_tid
        ):
            actors[o["source_ref"]]["techniques"].add(stix_to_tid[o["target_ref"]])

    groups, software, campaigns = [], [], []
    for a in actors.values():
        if not a["techniques"]:
            continue
        a["techniques"] = sorted(a["techniques"])
        {"intrusion-set": groups, "campaign": campaigns}.get(a["type"], software).append(a)
    for lst in (groups, software, campaigns):
        lst.sort(key=lambda x: x["name"].lower())

    platforms = sorted({p for t in techniques.values() for p in t["platforms"]})
    return {
        "domain": domain,
        "name": DOMAINS[domain],
        "version": version,
        "tactics": tactics,
        "techniques": techniques,
        "platforms": platforms,
        "groups": groups,
        "software": software,
        "campaigns": campaigns,
        "generated": time.time(),
    }


class AttackService:
    def __init__(self) -> None:
        self._data: dict[str, bytes] = {}  # domain -> serialized JSON
        self._locks = {d: asyncio.Lock() for d in DOMAINS}

    def _cache_path(self, domain: str):
        return config.DATA_DIR / f"attack-{domain}.json"

    async def get(self, domain: str) -> bytes:
        if domain not in DOMAINS:
            raise KeyError(domain)
        if domain in self._data:
            return self._data[domain]
        async with self._locks[domain]:
            if domain in self._data:
                return self._data[domain]
            path = self._cache_path(domain)
            if path.is_file():
                self._data[domain] = await asyncio.to_thread(path.read_bytes)
                return self._data[domain]
            await self.refresh(domain)
            return self._data[domain]

    async def refresh(self, domain: str) -> None:
        log.info("Downloading ATT&CK %s ...", domain)
        r = await get_client().get(STIX_URL.format(d=domain), timeout=180)
        r.raise_for_status()

        def build(raw: bytes) -> bytes:
            return json.dumps(parse_bundle(json.loads(raw), domain), separators=(",", ":")).encode()

        blob = await asyncio.to_thread(build, r.content)
        await asyncio.to_thread(self._cache_path(domain).write_bytes, blob)
        self._data[domain] = blob
        log.info("ATT&CK %s ready (%d KB)", domain, len(blob) // 1024)

    async def refresh_stale(self) -> None:
        """Refresh cached domains older than ATTACK_REFRESH_DAYS."""
        for domain in DOMAINS:
            path = self._cache_path(domain)
            if not path.is_file():
                continue
            if time.time() - path.stat().st_mtime > config.ATTACK_REFRESH_DAYS * 86400:
                async with self._locks[domain]:
                    try:
                        await self.refresh(domain)
                    except Exception:  # noqa: BLE001
                        log.exception("ATT&CK refresh failed for %s", domain)
