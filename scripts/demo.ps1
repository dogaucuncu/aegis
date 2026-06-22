# Aegis — FULL demo in a single command: starts all services, populates the four domains, opens the dashboard.
# Prerequisite: all venvs installed and ML models trained (see docs/DEMO.md).
$root = "F:\aegis"
$env:PYTHONIOENCODING = "utf-8"

Write-Host "[demo] Starting services in separate windows (SOC + ML + Lab + UI)..."
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\server; .\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\ml; .\.venv\Scripts\python.exe -m uvicorn service:app --port 8001"
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\lab\vulnerable_app; .\.venv\Scripts\python.exe app.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\ui; npm run dev"

Write-Host "[demo] Waiting for the services to be ready (~10s)..."
Start-Sleep -Seconds 10

Write-Host "[demo] BLUE: simulation + secure agent single round..."
& $root\agent\.venv\Scripts\python.exe $root\scripts\seed_demo.py

Write-Host "[demo] RED: vulnerability scan (SQLi/XSS/open-redirect + ports)..."
Push-Location $root\scanner
& .\.venv\Scripts\python.exe -m aegis_scanner.main --target 127.0.0.1
Pop-Location

Write-Host "[demo] ML: URL/flow scoring -> detections to the SOC..."
& $root\ml\.venv\Scripts\python.exe $root\scripts\ml_demo.py

Write-Host "[demo] CRYPTO: tamper with an event -> integrity break..."
& $root\server\.venv\Scripts\python.exe $root\scripts\tamper_demo.py --id 1

Write-Host ""
Write-Host "[demo] Ready. Dashboard: http://localhost:5173"
Write-Host "       Integrity:  http://127.0.0.1:8000/api/crypto/verify-signatures"
Start-Process "http://localhost:5173"
