# aegis-scanner — zafiyet tarayıcı (Red Team)

Port tarama (TCP connect + servis tespiti) ve web zafiyet tarama (**SQLi / XSS /
open-redirect**). Bulguları SOC'a olay olarak gönderir (`vuln_finding`, `open_port`).

> ⚠️ **Etik:** Yalnızca sahip olduğunuz / yetkili olduğunuz hedeflere karşı kullanın.

## Çalıştırma
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m aegis_scanner.main --target 127.0.0.1 \
  --web-url "http://127.0.0.1:5001/user?id=1"
```
Lab hedefi için bkz. [../lab/README.md](../lab/README.md).
