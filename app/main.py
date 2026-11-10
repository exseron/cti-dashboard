"""CTI Dashboard — FastAPI application."""
from __future__ import annotations

import asyncio
import base64
import binascii
import logging
import secrets
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.gzip import GZipMiddleware

from . import config
from .attack import DOMAINS, AttackService
from .cves import CVE_ID_RE, CVEService
from .httpclient import close_client
from .news import NewsService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cti")

news = NewsService()
cves = CVEService()
attack = AttackService()
_last_manual: dict[str, float] = {}


async def _periodic(name: str, fn, interval_s: int, initial_delay: float = 0) -> None:
    await asyncio.sleep(initial_delay)
    while True:
        try:
            await fn()
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001
            log.exception("Scheduled job %s failed", name)
        await asyncio.sleep(interval_s)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not config.AUTH_ENABLED and not config.ALLOW_NO_AUTH:
        raise RuntimeError(
            "APP_USERNAME/APP_PASSWORD ayarlanmamış. İnternete açık bir servis için kimlik doğrulama gerekli "
            "(yalnızca yerel test için ALLOW_NO_AUTH=1 kullanın)."
        )
    if not config.AUTH_ENABLED:
        log.warning("Kimlik doğrulama KAPALI (ALLOW_NO_AUTH=1) — panel herkese açık.")
    elif len(config.APP_PASSWORD) < 12:
        log.warning("APP_PASSWORD 12 karakterden kısa — daha güçlü bir parola kullanın.")
    tasks = [
        asyncio.create_task(_periodic("news", news.refresh, config.NEWS_REFRESH_MINUTES * 60, 1)),
        asyncio.create_task(_periodic("cves", cves.refresh, config.CVE_REFRESH_MINUTES * 60, 5)),
        asyncio.create_task(_periodic("attack", attack.refresh_stale, 6 * 3600, 60)),
    ]
    log.info("CTI Dashboard started (auth=%s, llm=%s)", config.AUTH_ENABLED, config.LLM_ENABLED)
    yield
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    await close_client()


app = FastAPI(title="CTI Dashboard", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


# --- Auth + security headers ------------------------------------------------------
class _LoginLimiter:
    def __init__(self) -> None:
        self.failures: dict[str, list[float]] = {}

    def blocked(self, ip: str) -> bool:
        now = time.time()
        hits = [t for t in self.failures.get(ip, []) if now - t < config.LOGIN_BLOCK_SECONDS]
        self.failures[ip] = hits
        return len(hits) >= config.LOGIN_MAX_FAILURES

    def fail(self, ip: str) -> None:
        self.failures.setdefault(ip, []).append(time.time())
        if len(self.failures) > 10000:  # bound memory
            self.failures.clear()


limiter = _LoginLimiter()
_USER = config.APP_USERNAME.encode()
_PASS = config.APP_PASSWORD.encode()


def _check_basic(header: str | None) -> bool:
    if not header or not header.lower().startswith("basic "):
        return False
    try:
        user, _, pw = base64.b64decode(header[6:].strip(), validate=True).partition(b":")
    except (binascii.Error, ValueError):
        return False
    ok_user = secrets.compare_digest(user, _USER)
    ok_pass = secrets.compare_digest(pw, _PASS)
    return ok_user and ok_pass


CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.url.path != "/healthz" and config.AUTH_ENABLED:
        ip = request.client.host if request.client else "unknown"
        if limiter.blocked(ip):
            return JSONResponse({"detail": "Çok fazla hatalı giriş. Daha sonra tekrar deneyin."}, status_code=429)
        auth = request.headers.get("authorization")
        if not _check_basic(auth):
            if auth:
                limiter.fail(ip)
            return Response(status_code=401, headers={"WWW-Authenticate": 'Basic realm="CTI Dashboard", charset="UTF-8"'})
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


app.add_middleware(GZipMiddleware, minimum_size=1024)


# --- Routes -----------------------------------------------------------------------
STATIC_DIR = config.BASE_DIR / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.get("/healthz", include_in_schema=False)
async def healthz():
    return {"ok": True}


@app.get("/api/news")
async def api_news():
    return news.snapshot()


@app.get("/api/cves")
async def api_cves():
    return cves.snapshot()


@app.get("/api/cves/{cve_id}/github")
async def api_cve_github(cve_id: str):
    cve_id = cve_id.upper()
    if not CVE_ID_RE.match(cve_id):
        raise HTTPException(400, "Geçersiz CVE ID")
    try:
        return {"items": await cves.github_search(cve_id)}
    except RuntimeError as e:
        raise HTTPException(429, str(e)) from e
    except Exception as e:  # noqa: BLE001
        log.warning("GitHub search failed: %s", e)
        raise HTTPException(502, "GitHub araması başarısız") from e


@app.get("/api/attack/{domain}")
async def api_attack(domain: str):
    if domain not in DOMAINS:
        raise HTTPException(404, "Bilinmeyen domain")
    try:
        blob = await attack.get(domain)
    except Exception as e:  # noqa: BLE001
        log.exception("ATT&CK load failed")
        raise HTTPException(502, "ATT&CK verisi indirilemedi") from e
    return Response(blob, media_type="application/json")


@app.post("/api/refresh/{what}")
async def api_refresh(what: str, request: Request):
    # Custom header blocks cross-site form posts (CSRF) — browsers can't set it without CORS.
    if request.headers.get("x-requested-with") != "cti-dashboard":
        raise HTTPException(403, "Forbidden")
    jobs = {"news": news.refresh, "cves": cves.refresh}
    if what not in jobs:
        raise HTTPException(404, "Bilinmeyen kaynak")
    if time.time() - _last_manual.get(what, 0) < 120:
        raise HTTPException(429, "Yenileme için 2 dakika bekleyin")
    _last_manual[what] = time.time()
    asyncio.create_task(jobs[what]())
    return {"started": True}
