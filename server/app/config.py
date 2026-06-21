"""Aegis sunucu yapılandırması.

Ortam değişkenleriyle override edilebilir; varsayılanlar yerel/SQLite geliştirme içindir.
"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("AEGIS_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Faz 0: SQLite. Faz 5'te PostgreSQL'e geçiş için sadece bu URL değişecek.
DATABASE_URL = os.getenv(
    "AEGIS_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'aegis.db').as_posix()}"
)

API_TITLE = "Aegis SOC Server"
API_VERSION = "0.1.0"


def _split(env: str, default: str) -> list[str]:
    return [x.strip() for x in os.getenv(env, default).split(",") if x.strip()]


# WP3: tabloları otomatik oluştur (dev/test). Üretimde 0 + Alembic kullan.
AUTO_CREATE = os.getenv("AEGIS_AUTO_CREATE", "1") != "0"

# WP4: CORS izinli origin'ler.
CORS_ORIGINS = _split(
    "AEGIS_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
)

# WP4: API anahtarları (virgüllü). Boş ise auth KAPALI (demo uyumu) — uyarı loglanır.
API_KEYS = set(_split("AEGIS_API_KEYS", ""))

# WP4: dakika başına istek limiti (0 = kapalı).
RATE_LIMIT_PER_MIN = int(os.getenv("AEGIS_RATE_LIMIT_PER_MIN", "0"))
