"""Aegis SOC sunucusu — FastAPI uygulama girişi."""
import logging

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from . import config
from .api import alerts, crypto, events, ingest, secure_ingest, stream
from .auth import require_api_key
from .database import Base, engine
from .middleware import RateLimitMiddleware

log = logging.getLogger("aegis.server")

# Dev/test: tabloları otomatik oluştur. Üretimde AEGIS_AUTO_CREATE=0 + Alembic.
if config.AUTO_CREATE:
    Base.metadata.create_all(bind=engine)

if not config.API_KEYS:
    log.warning("AEGIS_API_KEYS tanımlı değil — API auth KAPALI (yalnızca yerel/demo için).")

app = FastAPI(title=config.API_TITLE, version=config.API_VERSION)

# CORS: yalnızca izinli origin'ler (varsayılan UI portu).
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware, limit_per_min=config.RATE_LIMIT_PER_MIN)

# Olay enjekte eden uçlar API anahtarı ister (auth açıksa). Okuma uçları açık.
app.include_router(ingest.router, dependencies=[Depends(require_api_key)])
app.include_router(secure_ingest.router, dependencies=[Depends(require_api_key)])
app.include_router(events.router)
app.include_router(alerts.router)
app.include_router(crypto.router)
app.include_router(stream.router)


@app.get("/")
def root():
    return {
        "name": config.API_TITLE,
        "version": config.API_VERSION,
        "status": "ok",
        "docs": "/docs",
    }
