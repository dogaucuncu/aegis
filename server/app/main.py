"""Aegis SOC server — FastAPI application entry point."""
import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config
from .api import (
    agents,
    alerts,
    attest,
    auth_login,
    blocklist,
    canary,
    crypto,
    events,
    health,
    ingest,
    rules,
    secure_ingest,
    stats,
    stream,
)
from .auth import require_api_key, require_read_auth
from .database import Base, engine
from .middleware import (
    BlocklistMiddleware,
    RateLimitMiddleware,
    RequestInspectionMiddleware,
    RequestLogMiddleware,
)

log = logging.getLogger("aegis.server")

# Dev/test: auto-create tables. In production use AEGIS_AUTO_CREATE=0 + Alembic.
if config.AUTO_CREATE:
    Base.metadata.create_all(bind=engine)

# Load the persisted IP blocklist into the responder's in-memory mirror (Milestone 6).
try:
    from . import responder
    from .database import SessionLocal

    _boot_db = SessionLocal()
    try:
        responder.load_blocked(_boot_db)
    finally:
        _boot_db.close()
except Exception:  # noqa: BLE001 — never block startup on the blocklist warm-up
    log.warning("blocklist warm-up skipped (table not ready yet)")

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
# WAF-style request inspection (opt-in via AEGIS_WAF_DETECT); detection-only, never blocks.
app.add_middleware(RequestInspectionMiddleware, enabled=config.WAF_DETECT)
# Auto-response: reject IPs on the blocklist (empty unless something was blocked).
app.add_middleware(BlocklistMiddleware)
# Added last -> outermost: logs every request (including 429/403s) with a correlation id.
app.add_middleware(RequestLogMiddleware)

# Event-injecting endpoints always require an API key (when auth is enabled).
app.include_router(ingest.router, dependencies=[Depends(require_api_key)])
app.include_router(secure_ingest.router, dependencies=[Depends(require_api_key)])

# Read endpoints: open by default (demo dashboard); protected when AEGIS_REQUIRE_AUTH_READS=1
# (the dependency checks the flag per-request).
read_deps = [Depends(require_read_auth)]
app.include_router(events.router, dependencies=read_deps)
app.include_router(alerts.router, dependencies=read_deps)
app.include_router(agents.router, dependencies=read_deps)
app.include_router(crypto.router, dependencies=read_deps)
app.include_router(stream.router, dependencies=read_deps)
app.include_router(stats.router, dependencies=read_deps)
app.include_router(blocklist.router, dependencies=read_deps)

# Rule hot-reload (state-changing routes carry their own require_api_key dependency).
app.include_router(rules.router)

# Auth: /login must be reachable without a key (it IS the auth mechanism); /register inside this
# router carries its own require_api_key dependency.
app.include_router(auth_login.router)

# Canary tokens are tripwires — reachable without auth so an intruder can trip them.
app.include_router(canary.router)

# TPM 2.0 attestation: /quote + /challenge are cryptographically verified (open); /enroll defines
# the trust baseline and carries its own require_api_key dependency.
app.include_router(attest.router)

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
