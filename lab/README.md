# Aegis Lab — victim targets

⚠️ For local/educational use only. These targets are intentionally vulnerable.

## Option A — Local vulnerable app (without Docker)
```powershell
cd F:\aegis\lab\vulnerable_app
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5001
```
Vulnerable endpoints:
- `GET /user?id=1` → SQL injection (error-based + boolean)
- `GET /search?q=test` → reflected XSS

## Option B — Docker victim containers
```powershell
docker compose -f lab/docker-compose.yml up -d
# OWASP Juice Shop: http://127.0.0.1:3000
# DVWA:            http://127.0.0.1:8081
```

## Scanning
```powershell
cd F:\aegis\scanner
.\.venv\Scripts\Activate.ps1
python -m aegis_scanner.main --target 127.0.0.1
# Findings -> http://127.0.0.1:8000/api/alerts and the dashboard
```
