# aegis-scanner — vulnerability scanner (Red Team)

Port scanning (TCP connect + service detection) and web vulnerability scanning (**SQLi / XSS /
open-redirect**). Sends findings to the SOC as events (`vuln_finding`, `open_port`).

> ⚠️ **Ethics:** Use only against targets you own / are authorized to test.

## Running
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m aegis_scanner.main --target 127.0.0.1 \
  --web-url "http://127.0.0.1:5001/user?id=1"
```
For a lab target see [../lab/README.md](../lab/README.md).
