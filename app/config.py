"""Central configuration, read from environment variables (or a .env file)."""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ROOT_DIR = BASE_DIR.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines); real env vars take precedence."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


_load_dotenv(ROOT_DIR / ".env")


def _int(name: str, default: int, lo: int | None = None, hi: int | None = None) -> int:
    try:
        val = int(os.getenv(name, default))
    except ValueError:
        val = default
    if lo is not None:
        val = max(lo, val)
    if hi is not None:
        val = min(hi, val)
    return val


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


DATA_DIR = Path(os.getenv("DATA_DIR", ROOT_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# --- Server -----------------------------------------------------------------
HOST = os.getenv("HOST", "0.0.0.0")
PORT = _int("PORT", 8000, 1, 65535)
# Only trust X-Forwarded-* headers from these proxy IPs (comma separated, "*" = any).
FORWARDED_ALLOW_IPS = os.getenv("FORWARDED_ALLOW_IPS", "127.0.0.1")

# --- Auth (HTTP Basic) ------------------------------------------------------
APP_USERNAME = os.getenv("APP_USERNAME", "")
APP_PASSWORD = os.getenv("APP_PASSWORD", "")
# Default: no authentication. Set ALLOW_NO_AUTH=0 (plus APP_USERNAME/APP_PASSWORD) to enable Basic Auth.
ALLOW_NO_AUTH = _bool("ALLOW_NO_AUTH", True)
AUTH_ENABLED = bool(APP_USERNAME and APP_PASSWORD) and not ALLOW_NO_AUTH
LOGIN_MAX_FAILURES = _int("LOGIN_MAX_FAILURES", 10, 1)
LOGIN_BLOCK_SECONDS = _int("LOGIN_BLOCK_SECONDS", 900, 60)

# --- External API keys (all optional) ----------------------------------------
NVD_API_KEY = os.getenv("NVD_API_KEY", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# --- LLM summaries (optional, Claude) ---------------------------------------
# "auto" = enabled when ANTHROPIC_API_KEY is set.
_llm = os.getenv("LLM_SUMMARY", "auto").strip().lower()
LLM_ENABLED = bool(os.getenv("ANTHROPIC_API_KEY")) if _llm == "auto" else _llm in {"1", "true", "yes", "on"}
CLAUDE_MODEL = os.getenv("CLAUDE_MODEL", "claude-opus-5-5")
CLAUDE_EFFORT = os.getenv("CLAUDE_EFFORT", "low")
SUMMARY_LANGUAGE = os.getenv("SUMMARY_LANGUAGE", "Turkish")
LLM_MAX_PER_CYCLE = _int("LLM_MAX_PER_CYCLE", 40, 0)
LLM_CONCURRENCY = _int("LLM_CONCURRENCY", 4, 1, 16)

# --- Refresh cadence / windows ------------------------------------------------
NEWS_REFRESH_MINUTES = _int("NEWS_REFRESH_MINUTES", 30, 5)
NEWS_MAX_AGE_DAYS = _int("NEWS_MAX_AGE_DAYS", 14, 1, 90)
NEWS_MAX_ITEMS = _int("NEWS_MAX_ITEMS", 800, 50, 5000)
CVE_REFRESH_MINUTES = _int("CVE_REFRESH_MINUTES", 60, 15)
CVE_DAYS = _int("CVE_DAYS", 7, 1, 120)  # NVD allows max 120-day ranges
ATTACK_REFRESH_DAYS = _int("ATTACK_REFRESH_DAYS", 7, 1)

USER_AGENT = os.getenv("USER_AGENT", "CTI-Dashboard/1.0 (+self-hosted)")
