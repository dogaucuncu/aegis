# Aegis — Modular Mini-SOC (Security Operations Platform)

Aegis is a self-hosted, modular security operations platform that collects telemetry from
endpoints, scores events with rules + ML, actively scans assets, and cryptographically
protects the entire log stream.

It combines four cybersecurity domains in a single project:

| Domain | Module | Status |
|--------|--------|--------|
| 🛡️ Defensive (Blue) | Agent telemetry (process/network/**FIM**/**failed-login**) + rule engine + SIEM | ✅ Phase 0–1 |
| 🔐 Cryptography | mTLS + AES-GCM + Ed25519 signatures + hash-chain | ✅ Phase 2 |
| ⚔️ Offensive (Red) | Port + web scanner (**SQLi/XSS/open-redirect**) + lab target | ✅ Phase 3 |
| 🤖 ML | NIDS anomaly + phishing classifier (microservice) | ✅ Phase 4 |

## Architecture
```
[Agent] --HTTP / mTLS+ECDH+sign--> [FastAPI Server] --> [YAML Rule Engine] --> [SQLite/PostgreSQL]
                                                     \-> [Hash-chain (tamper-evident log)]
                                                                           |
                                               [React Dashboard] <--SSE (real-time)--
```
The dashboard receives alerts in real time over **SSE (`/api/stream`)** (polling is only a fallback).

## Quick start (Windows / PowerShell)

### 1) Server
```powershell
cd F:\aegis\server
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```
API docs: http://127.0.0.1:8000/docs

### 2) Agent (separate terminal)
```powershell
cd F:\aegis\agent
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m aegis_agent.main --config config.yaml
```

### 3) Generate demo alerts
```powershell
cd F:\aegis
python scripts\simulate.py --server http://127.0.0.1:8000
```
Then inspect the alerts:
- http://127.0.0.1:8000/api/alerts
- Log integrity: http://127.0.0.1:8000/api/integrity/verify

## Project layout
```
aegis/
  server/   FastAPI server, YAML rule engine, hash-chain, auth, alembic, API
  agent/    psutil-based endpoint agent (plain / secure mode)
  scanner/  port + web (SQLi/XSS) vulnerability scanner
  ml/       NIDS + phishing ML microservice
  crypto/   aegis_crypto: Ed25519 + AES-GCM + X25519/ECDH (shared library)
  ui/       React + TS + Tailwind SOC dashboard
  lab/      intentionally vulnerable target (no Docker required)
  tests/    pytest suite (server/crypto/scanner/ml/auth)
  scripts/  demo + provision + seed + dataset + cert tools
  docs/     architecture + sequence diagram + threat model
```

## Secure mode (Phase 2 — Cryptography)
Agent↔server traffic is encrypted with AES-GCM (the key is derived via **X25519 ECDH + HKDF** —
no plaintext AES key is stored on disk), every event is signed with Ed25519, and logs are
protected against tampering with a hash-chain. **Replay protection:** timestamp freshness
(±5 min) + nonce-reuse rejection.

```powershell
# 1) Generate ECDH + signing keys for the agent (also registers them with the server)
cd F:\aegis
F:\aegis\agent\.venv\Scripts\python.exe scripts\provision_agent.py --agent-id agent-local

# 2) Secure-flow demo (valid=200, forged signature=401, wrong key=400, replay=409)
F:\aegis\agent\.venv\Scripts\python.exe scripts\secure_demo.py

# 3) Re-verify the signatures stored in the repository
#    GET http://127.0.0.1:8000/api/crypto/verify-signatures
```

Run the agent **live** in secure mode (ready-made config):
```powershell
cd F:\aegis\agent
.\.venv\Scripts\python.exe -m aegis_agent.main --config config.secure.yaml
```
`config.secure.yaml` contains the ECDH + signing key paths; the agent signs and encrypts
real telemetry and sends it to `/api/ingest/secure`. Verify with
`GET /api/crypto/verify-signatures` (all signatures should be valid).

Secure ingestion flow: [docs/secure-ingestion-sequence.svg](docs/secure-ingestion-sequence.svg).

### mTLS (mutual TLS)
```powershell
# Generate certificates (CA + server + client)
F:\aegis\server\.venv\Scripts\python.exe scripts\gen_certs.py

# Verify certificates + mutual authentication
F:\aegis\server\.venv\Scripts\python.exe scripts\mtls_selftest.py

# Start the server with mTLS
cd F:\aegis\server
uvicorn app.main:app --port 8443 --ssl-keyfile ..\certs\server.key `
  --ssl-certfile ..\certs\server.pem --ssl-ca-certs ..\certs\ca.pem --ssl-cert-reqs 2
```
> ⚠️ **Note:** On this machine Norton intercepts and re-signs localhost TLS too, so a client
> going over the network cannot verify the server certificate with `verify=ca.pem`.
> `mtls_selftest.py` bypasses this interception (in-memory) to prove the logic is correct.

## Offensive scanning (Phase 3 — Red Team)
The scanner finds port + web (SQLi/XSS) vulnerabilities and reports them to the SOC as alerts.
First start the lab target (see [lab/README.md](lab/README.md)), then:
```powershell
# Lab target (separate terminal): http://127.0.0.1:5001
cd F:\aegis\lab\vulnerable_app; .\.venv\Scripts\Activate.ps1; python app.py

# Scanner
cd F:\aegis\scanner; .\.venv\Scripts\Activate.ps1
python -m aegis_scanner.main --target 127.0.0.1
# Findings: alerts on the dashboard (vuln-sqli/vuln-xss) + open ports in telemetry
```
> ⚠️ **Ethics:** Use only against targets you own / are authorized to test. The lab app is
> **intentionally vulnerable** — do not run it in production.

## ML engine (Phase 4 — NIDS + phishing)
A separate microservice (port 8001) provides NIDS network-anomaly and phishing URL scoring;
detections are reported to the SOC as alerts. Hybrid data: if real data exists under
`ml/data/` (NSL-KDD / phishing.csv) it is used, otherwise synthetically generated data is used.

```powershell
cd F:\aegis\ml
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python ..\scripts\fetch_datasets.py  # (optional) download real NSL-KDD (via truststore)
python -m aegis_ml.train            # train the models
uvicorn service:app --port 8001     # ML microservice

# Demo (with SOC on 8000 + ML on 8001 running):
F:\aegis\ml\.venv\Scripts\python.exe ..\scripts\ml_demo.py
# URLs/flows are scored; phishing & attack detections become ML alerts on the dashboard
```
With real data: NIDS (NSL-KDD) F1 ~**0.99**; phishing (live feed + popular domains) F1 ~**0.97**.
Models live in `ml/models/*.joblib`, metrics in `ml/models/*_metrics.json`.

## Deployment and demo (Phase 5)

### Rich demo data in a single command
Fills the dashboard with all four domains without running the services one by one
(with the SOC running):
```powershell
python scripts\seed_demo.py            # 16 events, 9 alerts (blue+red+ML)
```

### Start all services with one command (local)
```powershell
F:\aegis\scripts\start_all.ps1         # SOC + ML + UI in separate windows
```

### Full demo (services + four domains + dashboard)
```powershell
F:\aegis\scripts\demo.ps1              # see docs/DEMO.md (GIF recording instructions)
```

### Switching to PostgreSQL
The data layer is switched with `AEGIS_DATABASE_URL` (SQLite ↔ PostgreSQL); `create_all`
works the same on both.
```powershell
# Create the database (with PG running)
$env:PGPASSWORD = "<password>"
python scripts\init_postgres.py --user postgres --dbname aegis

# Start the server with PG
$env:AEGIS_DATABASE_URL = "postgresql+psycopg://postgres:<password>@127.0.0.1:5432/aegis"
cd F:\aegis\server; uvicorn app.main:app --port 8000
```
> ℹ️ PostgreSQL 18 is installed on this machine but the service is stopped and requires admin,
> so it was not tested live; the driver and dialect (`postgresql+psycopg`) are validated and
> the code is ready.

### Docker (containerized)
```powershell
docker compose up --build      # db (postgres) + soc + ml
```
> ⚠️ Not tested live because Docker is not installed on this machine.

## Development, Testing & Security Hardening
A single "dev" venv installs all packages + test tools:
```powershell
cd F:\aegis
py -3.13 -m venv .venv-dev
.\.venv-dev\Scripts\python.exe -m pip install -r requirements-dev.txt -e crypto
.\.venv-dev\Scripts\python.exe -m pytest -q        # 25 tests
.\.venv-dev\Scripts\python.exe -m ruff check .     # lint
```
- **Tests:** `tests/` — rule engine, crypto round-trip + forged signature, hash-chain,
  secure ingestion (valid/forged/wrong-key/replay/stale), auth, scanner SQLi/XSS, ML.
- **CI:** [.github/workflows/ci.yml](.github/workflows/ci.yml) — ruff + pytest + ml-train smoke.
- **Migrations:** `cd server; alembic upgrade head` (use `AEGIS_AUTO_CREATE=0` in production).
- **API security:** `AEGIS_API_KEYS` (X-API-Key), `AEGIS_CORS_ORIGINS`, `AEGIS_RATE_LIMIT_PER_MIN`
  — see [.env.example](.env.example). All env vars control auth/CORS/rate-limit.

Hardening applied: deprecation cleanup, pytest+CI, API-key auth + CORS + rate-limit, replay
protection, ECDH key management, YAML rule engine, real NSL-KDD data, alert correlation/dedup
(repeated findings become a single alert + counter), real-time SSE dashboard.

## Documentation
- Architecture: [docs/architecture.svg](docs/architecture.svg)
- Secure ingestion flow: [docs/secure-ingestion-sequence.svg](docs/secure-ingestion-sequence.svg)
- Threat model: [docs/threat-model.md](docs/threat-model.md)
- Module READMEs: [server](server/README.md) · [agent](agent/README.md) · [scanner](scanner/README.md) · [ml](ml/README.md) · [crypto](crypto/README.md)

## Roadmap
- [x] **Phase 0** — Skeleton: server + agent + SQLite + event stream
- [x] **Phase 1** — Blue: rule engine + React dashboard
- [x] **Phase 2** — Crypto: mTLS + AES-GCM + Ed25519 signatures + hash-chain
- [x] **Phase 3** — Red: port + web (SQLi/XSS) scanner + lab target → findings to the SOC
- [x] **Phase 4** — ML: NIDS anomaly + phishing microservice → detections to the SOC
- [x] **Phase 5** — Polish: PostgreSQL support, one-command seed/startup, Docker, architecture diagram

## License
Released under the [MIT License](LICENSE).

## ⚠️ Legal Disclaimer
This project is provided **for research and educational purposes only**. It includes
offensive security tooling (a port/web vulnerability scanner) and an **intentionally
vulnerable** lab application that must never be deployed in production or used against any
system you do not own or are not explicitly authorized to test.

You are solely responsible for how you use this software and for complying with all
applicable laws and regulations in your jurisdiction. The author(s) and contributors
**accept no liability whatsoever** for any direct or indirect damage, data loss, misuse, or
unlawful activity arising from the use of this project. The software is provided **"as is"**,
without warranty of any kind, express or implied (see the [MIT License](LICENSE)).

By using, cloning, or forking this repository you acknowledge and accept these terms.

> ⚠️ **Ethics:** The offensive scanner must only be used against lab targets you own / are
> authorized to test.
