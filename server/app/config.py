"""Aegis server configuration.

Can be overridden via environment variables; the defaults are for local/SQLite development.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Phase 0: SQLite. To switch to PostgreSQL in Phase 5, only this URL will change.
DATABASE_URL = os.getenv(
    "AEGIS_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'aegis.db').as_posix()}"
)

API_TITLE = "Aegis SOC Server"
API_VERSION = "0.1.0"


def _split(env: str, default: str) -> list[str]:
    return [x.strip() for x in os.getenv(env, default).split(",") if x.strip()]


# WP3: auto-create tables (dev/test). In production use 0 + Alembic.
AUTO_CREATE = os.getenv("AEGIS_AUTO_CREATE", "1") != "0"

# WP4: CORS allowed origins.
CORS_ORIGINS = _split(
    "AEGIS_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
)

# WP4: API keys (comma-separated). If empty, auth is DISABLED (demo compatibility) — a warning is logged.
API_KEYS = set(_split("AEGIS_API_KEYS", ""))

# Require an API key on the read endpoints too (alerts/events/integrity/crypto/stream).
# Default OFF so the demo dashboard keeps working without a key; turn ON in production.
REQUIRE_AUTH_READS = os.getenv("AEGIS_REQUIRE_AUTH_READS", "0") != "0"

# WP4: requests-per-minute limit (0 = disabled).
RATE_LIMIT_PER_MIN = int(os.getenv("AEGIS_RATE_LIMIT_PER_MIN", "0"))

# Retention window in days for the prune job (0 = keep everything). Used by scripts/prune.py.
RETENTION_DAYS = int(os.getenv("AEGIS_RETENTION_DAYS", "0"))

# Slack-compatible webhook for new high-severity alerts (empty = notifications disabled).
WEBHOOK_URL = os.getenv("AEGIS_WEBHOOK_URL", "").strip()
