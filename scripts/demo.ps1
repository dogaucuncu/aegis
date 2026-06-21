# Aegis — tek komutla TAM demo: tüm servisleri başlatır, dört alanı doldurur, dashboard'u açar.
# Ön koşul: tüm venv'ler kurulu ve ML modelleri eğitilmiş (bkz. docs/DEMO.md).
$root = "F:\aegis"
$env:PYTHONIOENCODING = "utf-8"

Write-Host "[demo] Servisler ayri pencerelerde baslatiliyor (SOC + ML + Lab + UI)..."
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\server; .\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\ml; .\.venv\Scripts\python.exe -m uvicorn service:app --port 8001"
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\lab\vulnerable_app; .\.venv\Scripts\python.exe app.py"
Start-Process powershell -ArgumentList "-NoExit", "-Command",
  "Set-Location $root\ui; npm run dev"

Write-Host "[demo] Servislerin hazir olmasi bekleniyor (~10s)..."
Start-Sleep -Seconds 10

Write-Host "[demo] BLUE: simulasyon + secure ajan tek tur..."
& $root\agent\.venv\Scripts\python.exe $root\scripts\seed_demo.py

Write-Host "[demo] RED: zafiyet taramasi (SQLi/XSS/open-redirect + portlar)..."
Push-Location $root\scanner
& .\.venv\Scripts\python.exe -m aegis_scanner.main --target 127.0.0.1
Pop-Location

Write-Host "[demo] ML: URL/akis skorlama -> tespitler SOC'a..."
& $root\ml\.venv\Scripts\python.exe $root\scripts\ml_demo.py

Write-Host "[demo] KRIPTO: bir olayi kurcala -> butunluk kirilmasi..."
& $root\server\.venv\Scripts\python.exe $root\scripts\tamper_demo.py --id 1

Write-Host ""
Write-Host "[demo] Hazir. Dashboard: http://localhost:5173"
Write-Host "       Butunluk:  http://127.0.0.1:8000/api/crypto/verify-signatures"
Start-Process "http://localhost:5173"
