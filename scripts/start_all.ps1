# Aegis — start all services in a single command (local development).
# Each service opens in a separate PowerShell window.
$root = "F:\aegis"

Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\server; .\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000"

Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\ml; .\.venv\Scripts\python.exe -m uvicorn service:app --port 8001"

Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\ui; npm run dev"

Write-Host "Aegis started:"
Write-Host "  SOC API   -> http://127.0.0.1:8000/docs"
Write-Host "  ML Engine -> http://127.0.0.1:8001/health"
Write-Host "  Dashboard -> http://127.0.0.1:5173"
Write-Host "Demo data: python scripts\seed_demo.py"
