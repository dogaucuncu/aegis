"""API anahtarı kimlik doğrulama.

`AEGIS_API_KEYS` tanımlı değilse auth KAPALI (demo uyumu); tanımlıysa state-değiştiren
uçlar geçerli bir `X-API-Key` başlığı ister.
"""
import logging
from typing import Optional

from fastapi import Header, HTTPException, status

from . import config

log = logging.getLogger("aegis.auth")


def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    if not config.API_KEYS:
        return  # auth kapalı
    if x_api_key not in config.API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Geçersiz veya eksik API anahtarı (X-API-Key)",
        )
