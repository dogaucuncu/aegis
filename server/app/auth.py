"""API key authentication.

If `AEGIS_API_KEYS` is not set, auth is DISABLED (demo compatibility); if set, state-changing
endpoints require a valid `X-API-Key` header. When `AEGIS_REQUIRE_AUTH_READS=1` the read
endpoints are protected too (see main.py).
"""
import hmac
import logging
from typing import Optional

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from . import config

log = logging.getLogger("aegis.auth")

# Declared so the X-API-Key requirement shows up in the OpenAPI schema (the /docs "Authorize"
# button). auto_error=False lets us keep the demo "auth disabled" path working.
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _valid(key: Optional[str]) -> bool:
    if not key:
        return False
    # Constant-time comparison against each configured key (avoids timing side-channels).
    return any(hmac.compare_digest(key, k) for k in config.API_KEYS)


def require_api_key(x_api_key: Optional[str] = Security(_api_key_header)) -> None:
    if not config.API_KEYS:
        return  # auth disabled
    if not _valid(x_api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key (X-API-Key)",
        )


def require_read_auth(x_api_key: Optional[str] = Security(_api_key_header)) -> None:
    """Auth for read endpoints — enforced only when AEGIS_REQUIRE_AUTH_READS=1.

    Evaluated per-request (not at app-build time) so the flag can be toggled in tests/runtime.
    """
    if not config.REQUIRE_AUTH_READS:
        return  # reads open (demo default)
    require_api_key(x_api_key)
