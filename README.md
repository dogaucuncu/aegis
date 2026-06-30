# Aegis — Modular Mini-SOC (Security Operations Platform)

Aegis is a self-hosted, modular security operations platform that collects telemetry from
endpoints, scores events with rules + ML, actively scans assets, and cryptographically
protects the entire log stream.

It combines four cybersecurity domains in a single project — every offensive capability ships
with its matching blue-team detection, so the platform teaches the full *attack → detect →
respond* loop:

| Domain | Module | Capabilities |
|--------|--------|--------------|
| 🛡️ Defensive (Blue) | Agent telemetry + rule engine + SIEM | process / network / FIM / failed-login, **ARP-spoof & flood detection**, server-side **WAF** signatures, **canary/honeypot** tripwires, **auto-response IP blocklist**, threat-hunting stats, hot-reload rules |
| ⚔️ Offensive (Red) | Port + web scanner + lab target | SQLi (error/blind), XSS, open-redirect, **command-injection, SSTI, path-traversal, SSRF, IDOR, CSRF, web-LLM prompt-injection**, **brute-force/spray**, **JWT alg=none**, MITRE-tagged findings |
| 🔐 Cryptography | `aegis_crypto` shared library + secure channel | mTLS, AES-GCM, Ed25519, X25519/ECDH, hash-chain, **Argon2 + JWT + TOTP login**, **Perfect Forward Secrecy (ephemeral ECDH)**, **cert pinning**, **key rotation**, padding-oracle/weak-crypto demos |
| 🤖 ML | NIDS + phishing + UEBA + DGA microservice | network-anomaly, phishing URL, **UEBA login-anomaly**, **DGA/C2 domain** detection, per-prediction **explainability**, model **versioning** (`/model-info`), **adversarial-robustness** testing |

Built across six expansion milestones (**M1–M6**) on top of Phases 0–5 — see [Expanded capabilities](#expanded-capabilities-m1m6).

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
  server/   FastAPI server, YAML rule engine, hash-chain, auth/login, WAF + blocklist,
            canary/stats/rules APIs, responder (auto-response), alembic
  agent/    psutil endpoint agent (plain/secure) + ARP, flood & canary detectors
  scanner/  port + web (SQLi/XSS/cmdi/SSTI/SSRF/IDOR/CSRF/LLM) + brute-force + JWT attacks
  ml/       NIDS + phishing + UEBA + DGA microservice (+ explainability, adversarial)
  crypto/   aegis_crypto: Ed25519/AES-GCM/X25519 + Argon2/JWT/TOTP/PFS/cert-pin/weak-crypto
  ui/       React + TS + Tailwind SOC dashboard (threat overview, blocklist, live SSE)
  lab/      intentionally vulnerable target (no Docker required)
  tests/    pytest suite — 115 tests across all domains
  scripts/  demo + provision + seed + killchain + arp_spoof + honeypot + adversarial + rotate
  docs/     architecture + sequence diagram + threat model
```

## Expanded capabilities (M1–M6)

Six milestones extend the four domains. Every red capability is paired with a blue detection
(the `event → YAML rule → alert` contract), and the risky items (DDoS, MITM) are **detection-first**,
hard-bound to `127.0.0.1` / the lab. Full pytest + ruff green (**115 tests**).

| Milestone | Theme | Highlights |
|-----------|-------|-----------|
| **M1** | Credential-attack kill chain | Brute-force scanner + lab `/login`; hardened `/api/auth/login` (Argon2 + JWT + TOTP + lockout); UEBA login-anomaly ML; new rule ops (`gte`/`lt`/`regex_match`) + `correlation` rule type |
| **M2** | Web vuln expansion | Lab `/exec` (cmdi), `/greet` (SSTI), `/file` (traversal), `/fetch` (SSRF), `/account` (IDOR), `/transfer` (CSRF), `/ai-assistant` (**web-LLM prompt injection**); scanner detectors for all + blind SQLi; per-finding MITRE; opt-in **WAF** middleware |
| **M3** | Network detection-first | Agent **ARP-spoof/MITM** + **flood** detectors; server volumetric detection; `arp_spoof_sim.py`, `flood_lab.py` (capped, loopback-only) |
| **M4** | Crypto deepening | **PFS** ephemeral-static ECDH (envelope v2); **JWT alg=none** attack vs hardened verify; **padding-oracle** attack + ECB/weak-hash demos; **cert pinning** + **key rotation** |
| **M5** | ML / AI security | **DGA/C2** detector; per-prediction **explainability** (`top_features`); **versioning** (`/model-info`, sha256); **adversarial** evasion testing |
| **M6** | Blue-team & platform | **Canary tokens** (`/api/canary/{token}`) + **honeypot** decoy service; **auto-response** IP blocklist; threat-hunting **`/api/stats`**; rule **hot-reload** (`/api/rules/reload`); dashboard panels |

```powershell
# Credential kill chain (M1): brute-force -> detection -> hardened login -> UEBA
python scripts\killchain_demo.py

# Web + JWT attacks (M2/M4): start the lab, then scan it (cmdi/ssti/ssrf/idor/csrf/llm/jwt)
cd lab\vulnerable_app; python app.py            # lab :5001
cd ..\..\scanner; python -m aegis_scanner.main --server http://127.0.0.1:8000

# Network deception & response (M3/M6)
python scripts\arp_spoof_sim.py                 # MITM/ARP detection (no packets sent)
python scripts\honeypot.py --port 2222          # decoy service -> canary alerts
#   set AEGIS_AUTO_BLOCK=1 on the server to auto-block attacker IPs (see /api/blocklist)

# ML/AI security (M5): train, score (incl. DGA), and test model robustness
cd ml; python -m aegis_ml.train; uvicorn service:app --port 8001
python ..\scripts\ml_demo.py                     # phishing + DGA detections -> SOC
python ..\scripts\adversarial_test.py            # evasion rate -> ml_evasion alert

# Crypto extras (M4)
python scripts\rotate_keys.py                     # rotate server X25519 (old key archived)
```

The dashboard surfaces all of this: a **MITRE threat overview** (tactic distribution + top rules),
the **auto-response blocklist** (with unblock), agent inventory, and live alerts over SSE.

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
docker compose up --build      # db (postgres) + soc + ml + ui (nginx, :8080)
```
The compose stack uses a persistent `pgdata` volume, `pg_isready`/`/health` healthchecks,
`depends_on: service_healthy`, and restart policies; the UI is built and served by nginx on
**:8080**. Validated with `docker compose config` (YAML).
> ⚠️ Not tested live because Docker is not installed on this machine.

## Development, Testing & Security Hardening
A single "dev" venv installs all packages + test tools:
```powershell
cd F:\aegis
py -3.13 -m venv .venv-dev
.\.venv-dev\Scripts\python.exe -m pip install -r requirements-dev.txt -e crypto
.\.venv-dev\Scripts\python.exe -m pytest -q        # 115 tests
.\.venv-dev\Scripts\python.exe -m ruff check .     # lint
```
- **Tests:** `tests/` — rule engine, crypto round-trip/forged-signature/**PFS**/**padding-oracle**,
  hash-chain, secure ingestion (valid/forged/wrong-key/replay/stale), auth + **brute-force**,
  scanner (SQLi/XSS/**cmdi/SSTI/SSRF/IDOR/CSRF/web-LLM/JWT**), **network detection** (ARP/flood),
  ML (phishing/UEBA/**DGA**/adversarial), and **M6** (canary/blocklist/stats/reload).
- **CI:** [.github/workflows/ci.yml](.github/workflows/ci.yml) — ruff + pytest + ml-train smoke +
  `pip-audit`; plus [CodeQL](.github/workflows/codeql.yml) (SAST) and [Dependabot](.github/dependabot.yml).
- **Migrations:** `cd server; alembic upgrade head` (use `AEGIS_AUTO_CREATE=0` in production).
- **API security:** `AEGIS_API_KEYS` (X-API-Key, constant-time compare, shown in `/docs`),
  `AEGIS_REQUIRE_AUTH_READS` (also gate read endpoints), `AEGIS_CORS_ORIGINS`,
  `AEGIS_RATE_LIMIT_PER_MIN` — see [.env.example](.env.example).
- **Operations:** `GET /health` (DB ping, for liveness probes); `X-Request-ID` correlation id on
  every response; alert status changes are written to an audit log.
- **Retention:** `AEGIS_RETENTION_DAYS` + `python scripts/prune.py --days N` (optionally
  `--include-events`; integrity verification re-anchors on the earliest retained event).

### SOC features
- **Agent inventory:** every ingest updates an agent heartbeat; `GET /api/agents` + a dashboard
  panel show which agents are online (last-seen) and their event counts.
- **Triage:** assignee / note / tags via `POST /api/alerts/{id}/triage`; alert status uses the
  `open / acknowledged / resolved / closed` workflow.
- **Notifications:** set `AEGIS_WEBHOOK_URL` to receive a Slack-compatible webhook on each new
  high-severity alert.
- **MITRE ATT&CK:** detection rules carry `tactic`/`technique`, surfaced on alerts and as a UI badge.
- **Filtering:** `/api/alerts` & `/api/events` accept `q` (text), `since`, `until`; the alerts
  table has a severity/status/search filter bar.

Hardening applied: deprecation cleanup, pytest+CI (+pip-audit/CodeQL/Dependabot), API-key auth
(constant-time) + optional read-auth + CORS + rate-limit, replay protection, ECDH key management,
YAML rule engine with MITRE mapping, real NSL-KDD data, alert correlation/dedup + triage workflow,
agent heartbeat inventory, webhook notifications, retention pruning, structured request logging +
audit trail, real-time SSE dashboard.

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
- [x] **M1** — Credential-attack kill chain (brute-force ↔ detection ↔ Argon2/JWT/TOTP ↔ UEBA)
- [x] **M2** — Web vuln expansion (cmdi/SSTI/traversal/SSRF/IDOR/CSRF/web-LLM) + WAF
- [x] **M3** — Network detection-first (ARP/MITM + flood/DDoS)
- [x] **M4** — Crypto deepening (PFS, JWT attacks, padding-oracle, cert pinning, key rotation)
- [x] **M5** — ML/AI security (DGA, explainability, versioning, adversarial robustness)
- [x] **M6** — Blue-team & platform (canary/honeypot, auto-response blocklist, threat-hunting)

## License
Released under the [MIT License](LICENSE).

## ⚠️ Legal Disclaimer & Authorized-Use Policy

This project is provided **strictly for research, education, and authorized defensive-security
testing**. It deliberately bundles **offensive and dual-use tooling** alongside an
**intentionally vulnerable** lab. Beyond the original port/web scanner, this now includes:

- a web/application scanner — SQL injection (error-based + blind), XSS, command injection, SSTI,
  path traversal, SSRF, IDOR, CSRF, open-redirect, and **web-LLM prompt injection**;
- credential attacks — dictionary **brute-force** and **password spraying** — and **JWT `alg=none`** forgery;
- network-attack **simulations** — ARP-spoof / MITM and volumetric **flood** — plus a capped load generator;
- cryptographic-attack **demonstrations** — AES-CBC **padding oracle**, ECB / weak-hash;
- an **intentionally vulnerable** lab app that executes attacker-controlled input (including OS
  commands) and a honeypot / decoy service.

### Authorized use only
- Use these tools **only** against systems you **own** or have **explicit, written authorization**
  to test. Unauthorized scanning, brute-forcing, or exploitation may be a **criminal offense**
  (e.g. the U.S. CFAA, the UK Computer Misuse Act, and national equivalents such as Türkiye's
  TCK 243–245).
- The lab app, honeypot, and offensive scripts are **loopback-bound (`127.0.0.1`) by design** and
  must **never** be exposed to a network or deployed in production. Do not repoint their bind
  address or `--target`/`--url` at hosts you are not authorized to test.
- The destructive / dual-use features (MITM, DDoS) are implemented **detection-first** and
  hard-capped on purpose; do not modify them into unbounded or internet-facing attack tools.

### No warranty, no liability
You are **solely responsible** for how you use this software and for complying with all
applicable laws and regulations in your jurisdiction. The author(s) and contributors
**accept no liability whatsoever** for any direct, indirect, incidental, or consequential
damage, data loss, service disruption, misuse, or unlawful activity arising from its use. The
software is provided **"AS IS"**, without warranty of any kind, express or implied (see the
[MIT License](LICENSE)). Nothing in this repository constitutes legal advice.

By using, cloning, or forking this repository you acknowledge that you have read, understood,
and accepted these terms.
