"""API key authentication.

If `AEGIS_API_KEYS` is not set, auth is DISABLED (demo compatibility); if set, state-changing
endpoints require a valid `X-API-Key` header.
"""
import logging
from typing import Optional

from fastapi import Header, HTTPException, status

from . import config

log = logging.getLogger("aegis.auth")


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if not config.API_KEYS:
        return  # auth disabled
    if x_api_key not in config.API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key (X-API-Key)",
        )
