# aegis-server — SOC server (FastAPI)

Telemetry ingestion, rule engine, hash-chain integrity, secure (ECDH/signed) ingestion and a REST API.

## Running
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --port 8000      # /docs
```

## Structure
- `app/api/` — endpoints: `ingest`, `secure_ingest`, `events`, `alerts`, `crypto`
- `app/rules.py` + `app/detection_rules/*.yml` — YAML (Sigma-like) rule engine
- `app/integrity.py` — SHA-256 hash chain (tamper-evident)
- `app/keystore.py` — ECDH (X25519) key derivation + Ed25519 verification
- `app/auth.py`, `app/middleware.py` — API key + rate limit
- `alembic/` — schema migrations (`alembic upgrade head`)

## Environment variables
See the root [.env.example](../.env.example): `AEGIS_DATABASE_URL`, `AEGIS_API_KEYS`,
`AEGIS_CORS_ORIGINS`, `AEGIS_RATE_LIMIT_PER_MIN`, `AEGIS_AUTO_CREATE`.
