"""Aegis SOC server — FastAPI application entry point."""
import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config
from .api import alerts, crypto, events, health, ingest, secure_ingest, stream
from .auth import require_api_key, require_read_auth
from .database import Base, engine
from .middleware import RateLimitMiddleware, RequestLogMiddleware

log = logging.getLogger("aegis.server")

# Dev/test: auto-create tables. In production use AEGIS_AUTO_CREATE=0 + Alembic.
if config.AUTO_CREATE:
    Base.metadata.create_all(bind=engine)

if not config.API_KEYS:
    log.warning("AEGIS_API_KEYS is not set — API auth DISABLED (for local/demo use only).")

app = FastAPI(title=config.API_TITLE, version=config.API_VERSION)

# CORS: only allowed origins (default UI port).
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, limit_per_min=config.RATE_LIMIT_PER_MIN)
# Added last -> outermost: logs every request (including rate-limited 429s) with a correlation id.
app.add_middleware(RequestLogMiddleware)

# Event-injecting endpoints always require an API key (when auth is enabled).
app.include_router(ingest.router, dependencies=[Depends(require_api_key)])
app.include_router(secure_ingest.router, dependencies=[Depends(require_api_key)])

# Read endpoints: open by default (demo dashboard); protected when AEGIS_REQUIRE_AUTH_READS=1
# (the dependency checks the flag per-request).
read_deps = [Depends(require_read_auth)]
app.include_router(events.router, dependencies=read_deps)
app.include_router(alerts.router, dependencies=read_deps)
app.include_router(crypto.router, dependencies=read_deps)
app.include_router(stream.router, dependencies=read_deps)

# Health check stays unauthenticated for orchestrator liveness probes.
app.include_router(health.router)


@app.get("/")
def root():
    return {
        "name": config.API_TITLE,
        "version": config.API_VERSION,
        "status": "ok",
        "docs": "/docs",
    }
