"""CTI news aggregation: RSS/Atom feeds -> cleaned text -> summary + tags (SQLite-backed)."""
from __future__ import annotations

import asyncio
import calendar
import hashlib
import json
import logging
import re
import sqlite3
import threading
import time

import feedparser
from bs4 import BeautifulSoup

from . import config, llm
from .httpclient import get_client

log = logging.getLogger("cti.news")

# (name, url) — edit freely, or override with a NEWS_FEEDS_FILE json: [["Name","url"], ...]
FEEDS: list[tuple[str, str]] = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("The Record", "https://therecord.media/feed"),
    ("Unit 42", "https://unit42.paloaltonetworks.com/feed/"),
    ("Cisco Talos", "https://blog.talosintelligence.com/rss/"),
    ("Microsoft Security", "https://www.microsoft.com/en-us/security/blog/feed/"),
    ("Google Threat Intelligence", "https://cloudblog.withgoogle.com/topics/threat-intelligence/rss/"),
    ("Securelist (Kaspersky)", "https://securelist.com/feed/"),
    ("WeLiveSecurity (ESET)", "https://feeds.feedburner.com/eset/blog"),
    ("Check Point Research", "https://research.checkpoint.com/feed/"),
    ("SANS ISC", "https://isc.sans.edu/rssfeed_full.xml"),
    ("Recorded Future", "https://www.recordedfuture.com/feed"),
    ("SentinelOne Labs", "https://www.sentinelone.com/labs/feed/"),
]

_feeds_file = config.ROOT_DIR / "feeds.json"
if _feeds_file.is_file():
    try:
        FEEDS = [(str(n), str(u)) for n, u in json.loads(_feeds_file.read_text(encoding="utf-8"))]
    except Exception:  # noqa: BLE001
        log.exception("feeds.json could not be parsed; using built-in feed list")

# --- Rule-based tagging -------------------------------------------------------
# (tag, regex, case_sensitive)
TAG_RULES: list[tuple[str, str, bool]] = [
    ("Ransomware", r"ransomware|extortion|double extortion", False),
    ("APT", r"\bAPT\s?-?\d+\b|state[- ]sponsored|nation[- ]state|advanced persistent threat", False),
    ("Espionage", r"espionage", False),
    ("Phishing", r"phishing|smishing|vishing|credential harvest|business email compromise|\bBEC\b", False),
    ("Zero-Day", r"zero[- ]day|0-day", False),
    ("Actively Exploited", r"actively exploited|exploited in the wild|under active exploitation|known exploited", False),
    ("Vulnerability", r"vulnerabilit|\bCVE-\d{4}-\d{4,}\b|\bflaws?\b|\bRCE\b|remote code execution", False),
    ("Patch", r"patch tuesday|security updates?|patche[sd]|hotfix", False),
    ("Malware", r"malware|trojan|backdoor|\bloader\b|botnet|rootkit|wiper|\bRAT\b|implant", False),
    ("Infostealer", r"stealer", False),
    ("Supply Chain", r"supply[- ]chain|malicious (npm|pypi|package)|\bnpm\b|\bPyPI\b|dependency confusion", False),
    ("Data Breach", r"data breach|breach(ed)?\b|data leak|leaked|stolen data|exposed data", False),
    ("DDoS", r"\bDDoS\b", False),
    ("Cloud", r"\bAWS\b|\bAzure\b|\bGCP\b|google cloud|kubernetes|\bSaaS\b|\bEntra\b|\bOkta\b|\bM365\b", False),
    ("ICS/OT", r"\bICS\b|\bOT\b|SCADA|industrial control|\bPLC\b", True),
    ("Mobile", r"\bAndroid\b|\biOS\b|iPhone|mobile malware|spyware", False),
    ("AI", r"\bAI\b|\bLLM\b|ChatGPT|generative AI|artificial intelligence|deepfake", True),
    ("Crypto", r"cryptocurrenc|bitcoin|crypto wallet|blockchain|\bDeFi\b|crypto exchange", False),
    ("Law Enforcement", r"arrested|indicted|sentenced|takedown|seized|Europol|\bFBI\b|\bDOJ\b|extradit", False),
    ("Advisory", r"advisory|\bICSA-\d", False),
    ("Identity/Auth", r"account takeover|authentication bypass|\bMFA\b|\b2FA\b|password|credential|\bSSO\b|\bOAuth\b|session hijack", False),
    # Sectors
    ("Healthcare", r"healthcare|hospital|medical|patient|pharma", False),
    ("Finance", r"\bbank(s|ing)?\b|financial|fintech|payment|credit card", False),
    ("Government", r"government|ministry|federal agenc|municipal|military|defen[cs]e (contractor|sector)", False),
    ("Education", r"universit|school|education|college", False),
    ("Automotive", r"automaker|automotive|connected car|\bcars?\b|vehicle", False),
    ("Telecom", r"telecom|\bISP\b|carrier|\b5G\b", False),
    ("Energy", r"energy|power grid|utility|utilities|oil and gas|pipeline operator", False),
    # Attribution
    ("Russia", r"\bRussia(n)?\b", False),
    ("China", r"\bChina\b|\bChinese\b", False),
    ("North Korea", r"North Korea(n)?|\bDPRK\b", False),
    ("Iran", r"\bIran(ian)?\b", False),
    # Vendors
    ("Microsoft", r"\bMicrosoft\b|\bWindows\b|Exchange Server|SharePoint", False),
    ("Google", r"\bGoogle\b|\bChrome\b", False),
    ("Apple", r"\bApple\b|\bmacOS\b|\bSafari\b", False),
    ("Cisco", r"\bCisco\b", False),
    ("Fortinet", r"Fortinet|FortiGate|FortiOS|FortiWeb", False),
    ("Ivanti", r"\bIvanti\b", False),
    ("Palo Alto", r"Palo Alto|PAN-OS|GlobalProtect", False),
    ("VMware", r"VMware|ESXi|vCenter", False),
    ("Citrix", r"Citrix|NetScaler", False),
    ("Linux", r"\bLinux\b", False),
]

# Known actors / malware families (case-insensitive, word-bounded). Displayed with original casing.
ACTORS = [
    "Lazarus", "Kimsuky", "Andariel", "APT28", "APT29", "APT31", "APT41", "APT40", "Fancy Bear", "Cozy Bear",
    "Sandworm", "Turla", "Gamaredon", "Volt Typhoon", "Salt Typhoon", "Flax Typhoon", "Silk Typhoon",
    "Midnight Blizzard", "Forest Blizzard", "Scattered Spider", "Lapsus$", "ShinyHunters", "FIN7", "FIN8",
    "Cl0p", "Clop", "LockBit", "BlackCat", "ALPHV", "Akira", "Black Basta", "Qilin", "RansomHub", "Medusa",
    "Rhysida", "BlackSuit", "Play ransomware", "INC Ransom", "MuddyWater", "OilRig", "APT34", "APT35",
    "Charming Kitten", "Mustang Panda", "Winnti", "Earth Lusca", "TA505", "TA577", "Evil Corp",
    "Lumma", "LummaC2", "RedLine", "Vidar", "StealC", "Raccoon", "Emotet", "QakBot", "Qbot", "IcedID",
    "Pikabot", "DarkGate", "Latrodectus", "Cobalt Strike", "Sliver", "Brute Ratel", "Mimikatz", "AsyncRAT",
    "Remcos", "njRAT", "Agent Tesla", "Formbook", "XWorm", "SocGholish", "Mirai", "Pegasus", "Predator",
]
_ACTOR_RE = re.compile(r"(?<![\w$])(" + "|".join(re.escape(a) for a in ACTORS) + r")(?![\w$])", re.I)
_ACTOR_CANON = {a.lower(): a for a in ACTORS}
_DYN_ACTOR_RE = re.compile(r"\b(?:UNC\d{3,5}|Storm-\d{4}|TA\d{3,4}|APT-?C-\d{2})\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_TTP_RE = re.compile(r"\bT1\d{3}(?:\.\d{3})?\b")
_COMPILED_RULES = [(t, re.compile(p, 0 if cs else re.I)) for t, p, cs in TAG_RULES]


def extract_tags(text: str) -> tuple[list[str], list[str], list[str]]:
    """Return (tags, cves, attack_ids)."""
    tags = [t for t, rx in _COMPILED_RULES if rx.search(text)]
    actors: list[str] = []
    for m in _ACTOR_RE.finditer(text):
        name = _ACTOR_CANON.get(m.group(1).lower(), m.group(1))
        if name not in actors:
            actors.append(name)
    for m in _DYN_ACTOR_RE.finditer(text):
        if m.group(0) not in actors:
            actors.append(m.group(0))
    cves = list(dict.fromkeys(c.upper() for c in _CVE_RE.findall(text)))[:20]
    ttps = list(dict.fromkeys(_TTP_RE.findall(text)))[:20]
    return tags + actors[:8], cves, ttps


# --- Text helpers -------------------------------------------------------------
_BOILERPLATE = [
    re.compile(r"The post .{0,300}? appeared first on .{0,120}?\.", re.S),
    re.compile(r"Continue reading.*$", re.S | re.I),
    re.compile(r"Read more.*$", re.S | re.I),
]


def html_to_text(raw: str) -> str:
    if not raw:
        return ""
    text = BeautifulSoup(raw, "html.parser").get_text(" ")
    for rx in _BOILERPLATE:
        text = rx.sub("", text)
    return " ".join(text.split())


def extractive_summary(text: str, limit: int = 420) -> str:
    sentences = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9\"'(])", text)
    out = ""
    for s in sentences:
        if len(out) + len(s) > limit and out:
            break
        out = f"{out} {s}".strip()
    if len(out) > limit:
        out = out[:limit].rsplit(" ", 1)[0]
    if out and out[-1] not in ".!?…\"'”":
        out += "…"
    return out


# --- Storage --------------------------------------------------------------------
class NewsStore:
    def __init__(self, path):
        self._lock = threading.Lock()
        self._db = sqlite3.connect(path, check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute(
            """CREATE TABLE IF NOT EXISTS articles (
                id TEXT PRIMARY KEY, source TEXT, title TEXT, link TEXT, published REAL,
                text TEXT, summary TEXT, summary_llm INTEGER DEFAULT 0, llm_tried INTEGER DEFAULT 0,
                tags TEXT, cves TEXT, ttps TEXT, fetched REAL)"""
        )
        self._db.execute("CREATE INDEX IF NOT EXISTS idx_pub ON articles(published)")
        self._db.commit()

    def existing_ids(self, ids: list[str]) -> set[str]:
        if not ids:
            return set()
        with self._lock:
            found: set[str] = set()
            for i in range(0, len(ids), 500):
                chunk = ids[i : i + 500]
                q = "SELECT id FROM articles WHERE id IN (%s)" % ",".join("?" * len(chunk))
                found.update(r[0] for r in self._db.execute(q, chunk))
            return found

    def insert(self, rows: list[dict]) -> None:
        with self._lock:
            self._db.executemany(
                """INSERT OR IGNORE INTO articles
                   (id, source, title, link, published, text, summary, tags, cves, ttps, fetched)
                   VALUES (:id,:source,:title,:link,:published,:text,:summary,:tags,:cves,:ttps,:fetched)""",
                rows,
            )
            self._db.commit()

    def pending_llm(self, limit: int) -> list[tuple]:
        with self._lock:
            return list(
                self._db.execute(
                    "SELECT id, source, title, text, tags FROM articles "
                    "WHERE summary_llm=0 AND llm_tried=0 ORDER BY published DESC LIMIT ?",
                    (limit,),
                )
            )

    def set_llm(self, art_id: str, summary: str | None, tags: list[str] | None) -> None:
        with self._lock:
            if summary:
                self._db.execute(
                    "UPDATE articles SET summary=?, tags=?, summary_llm=1, llm_tried=1 WHERE id=?",
                    (summary, json.dumps(tags or []), art_id),
                )
            else:
                self._db.execute("UPDATE articles SET llm_tried=1 WHERE id=?", (art_id,))
            self._db.commit()

    def prune(self, min_ts: float) -> None:
        with self._lock:
            self._db.execute("DELETE FROM articles WHERE published < ?", (min_ts,))
            self._db.commit()

    def recent(self, limit: int) -> list[dict]:
        with self._lock:
            rows = list(
                self._db.execute(
                    "SELECT id, source, title, link, published, summary, summary_llm, tags, cves, ttps "
                    "FROM articles ORDER BY published DESC LIMIT ?",
                    (limit,),
                )
            )
        return [
            {
                "id": r[0], "source": r[1], "title": r[2], "link": r[3], "published": r[4],
                "summary": r[5], "ai": bool(r[6]), "tags": json.loads(r[7] or "[]"),
                "cves": json.loads(r[8] or "[]"), "ttps": json.loads(r[9] or "[]"),
            }
            for r in rows
        ]


# --- Service --------------------------------------------------------------------
class NewsService:
    def __init__(self) -> None:
        self.store = NewsStore(config.DATA_DIR / "news.db")
        self.items: list[dict] = self.store.recent(config.NEWS_MAX_ITEMS)
        self.last_updated: float | None = time.time() if self.items else None
        self.feed_status: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def _fetch_feed(self, name: str, url: str) -> list[dict]:
        client = get_client()
        try:
            r = await client.get(url, headers={"Accept": "application/rss+xml, application/atom+xml, */*"})
            r.raise_for_status()
            parsed = await asyncio.to_thread(feedparser.parse, r.content)
        except Exception as e:  # noqa: BLE001
            self.feed_status[name] = {"ok": False, "error": type(e).__name__, "at": time.time()}
            log.warning("Feed %s failed: %s", name, e)
            return []
        min_ts = time.time() - config.NEWS_MAX_AGE_DAYS * 86400
        out = []
        for e in parsed.entries[:60]:
            link = (e.get("link") or "").strip()
            title = html_to_text(e.get("title") or "")
            if not link.startswith(("http://", "https://")) or not title:
                continue
            st = e.get("published_parsed") or e.get("updated_parsed")
            ts = float(calendar.timegm(st)) if st else time.time()
            ts = min(ts, time.time())
            if ts < min_ts:
                continue
            body = ""
            if e.get("content"):
                body = e["content"][0].get("value", "")
            body = body or e.get("summary") or e.get("description") or ""
            out.append({"source": name, "title": title, "link": link, "published": ts, "raw": body})
        self.feed_status[name] = {"ok": True, "count": len(out), "at": time.time()}
        return out

    async def refresh(self) -> None:
        async with self._lock:
            sem = asyncio.Semaphore(8)

            async def run(n, u):
                async with sem:
                    return await self._fetch_feed(n, u)

            results = await asyncio.gather(*(run(n, u) for n, u in FEEDS))
            entries = [e for batch in results for e in batch]
            for e in entries:
                e["id"] = hashlib.sha1(e["link"].encode()).hexdigest()
            known = self.store.existing_ids([e["id"] for e in entries])
            new_rows, seen = [], set()
            for e in entries:
                if e["id"] in known or e["id"] in seen:
                    continue
                seen.add(e["id"])
                text = await asyncio.to_thread(html_to_text, e["raw"])
                tags, cves, ttps = extract_tags(f"{e['title']} {text}")
                new_rows.append({
                    "id": e["id"], "source": e["source"], "title": e["title"][:500], "link": e["link"],
                    "published": e["published"], "text": text[:8000],
                    "summary": extractive_summary(text) or e["title"],
                    "tags": json.dumps(tags), "cves": json.dumps(cves), "ttps": json.dumps(ttps),
                    "fetched": time.time(),
                })
            if new_rows:
                self.store.insert(new_rows)
            self.store.prune(time.time() - config.NEWS_MAX_AGE_DAYS * 86400)
            self.items = self.store.recent(config.NEWS_MAX_ITEMS)
            self.last_updated = time.time()
            log.info("News refresh: %d entries, %d new", len(entries), len(new_rows))

        if config.LLM_ENABLED and config.LLM_MAX_PER_CYCLE > 0:
            await self._llm_pass()

    async def _llm_pass(self) -> None:
        pending = self.store.pending_llm(config.LLM_MAX_PER_CYCLE)
        if not pending:
            return
        sem = asyncio.Semaphore(config.LLM_CONCURRENCY)

        async def one(row):
            art_id, source, title, text, tags_json = row
            async with sem:
                res = await llm.summarize_article(title, source, text or title)
            if res:
                rule_tags = json.loads(tags_json or "[]")
                merged = list(dict.fromkeys(rule_tags + [t for t in res["tags"] if t.lower() not in {x.lower() for x in rule_tags}]))
                self.store.set_llm(art_id, res["summary"], merged[:14])
            else:
                self.store.set_llm(art_id, None, None)

        await asyncio.gather(*(one(r) for r in pending))
        self.items = self.store.recent(config.NEWS_MAX_ITEMS)
        log.info("LLM summarized %d articles", len(pending))

    def snapshot(self) -> dict:
        return {
            "items": self.items,
            "last_updated": self.last_updated,
            "sources": [n for n, _ in FEEDS],
            "feed_status": self.feed_status,
            "llm_enabled": config.LLM_ENABLED,
        }
