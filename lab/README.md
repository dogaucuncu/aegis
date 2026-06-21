# Aegis Lab — kurban hedefler

⚠️ Yalnızca yerel/eğitim amaçlıdır. Bu hedefler kasıtlı zafiyetlidir.

## Seçenek A — Yerel zafiyetli uygulama (Docker'sız)
```powershell
cd F:\aegis\lab\vulnerable_app
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py            # http://127.0.0.1:5001
```
Zafiyetli uçlar:
- `GET /user?id=1` → SQL injection (hata-tabanlı + boolean)
- `GET /search?q=test` → yansıyan XSS

## Seçenek B — Docker kurban konteynerleri
```powershell
docker compose -f lab/docker-compose.yml up -d
# OWASP Juice Shop: http://127.0.0.1:3000
# DVWA:            http://127.0.0.1:8081
```

## Tarama
```powershell
cd F:\aegis\scanner
.\.venv\Scripts\Activate.ps1
python -m aegis_scanner.main --target 127.0.0.1
# Bulgular -> http://127.0.0.1:8000/api/alerts ve dashboard
```
