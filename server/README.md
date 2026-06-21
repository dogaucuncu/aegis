# aegis-server — SOC sunucusu (FastAPI)

Telemetri alımı, kural motoru, hash-zinciri bütünlüğü, güvenli (ECDH/imzalı) ingestion ve REST API.

## Çalıştırma
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --port 8000      # /docs
```

## Yapı
- `app/api/` — uçlar: `ingest`, `secure_ingest`, `events`, `alerts`, `crypto`
- `app/rules.py` + `app/detection_rules/*.yml` — YAML (Sigma-benzeri) kural motoru
- `app/integrity.py` — SHA-256 hash-zinciri (tamper-evident)
- `app/keystore.py` — ECDH (X25519) anahtar türetme + Ed25519 doğrulama
- `app/auth.py`, `app/middleware.py` — API anahtarı + rate limit
- `alembic/` — şema migration'ları (`alembic upgrade head`)

## Ortam değişkenleri
Bkz. kök [.env.example](../.env.example): `AEGIS_DATABASE_URL`, `AEGIS_API_KEYS`,
`AEGIS_CORS_ORIGINS`, `AEGIS_RATE_LIMIT_PER_MIN`, `AEGIS_AUTO_CREATE`.
