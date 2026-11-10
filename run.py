"""Entry point: python run.py

Runs a single uvicorn worker on purpose — background refresh jobs and caches live
in-process, so multiple workers would duplicate work and API calls.
"""
import uvicorn

from app import config

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        workers=1,
        proxy_headers=True,
        forwarded_allow_ips=config.FORWARDED_ALLOW_IPS,
        server_header=False,
        log_level="info",
    )
