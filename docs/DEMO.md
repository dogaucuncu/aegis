# Aegis — Demo Guide (for recording a GIF/screenshot)

This guide showcases the four SOC domains + hardening features in a single flow.
For screen recording: **Windows** → `Win+G` (Xbox Game Bar) or [ScreenToGif](https://www.screentogif.com/).
You can save the recording under `docs/screenshots/`.

## Prerequisite (one-time)
```powershell
# venv + dependencies for each module (see README), and the ML models:
cd F:\aegis\ml
python scripts\..\..\scripts\fetch_datasets.py   # (opt.) real data
python -m aegis_ml.train
```

## Full demo with a single command
```powershell
F:\aegis\scripts\demo.ps1
```
Starts the services (SOC 8000 · ML 8001 · Lab 5001 · UI 5173), populates the four domains,
triggers crypto tampering and opens the dashboard.

## Demo scenarios (what to narrate while recording)
1. **Blue (detection):** `seed_demo` → brute-force, suspicious command/process alerts on the dashboard.
   Repeated brute-force is aggregated into a single alert with an **×N** counter (correlation/dedup).
2. **Red (offensive):** scanner → **SQLi · XSS · Open-Redirect** + open ports; shown in the
   "Scan & Assets" panel.
3. **ML:** `ml_demo` → phishing (score ~0.94) + NIDS anomaly (~0.98) in the "ML Detections" panel.
4. **Crypto:** when a log record is altered via `tamper_demo`, a **"⚠️ Tampered!"** badge +
   `/api/crypto/verify-signatures` reports the invalid signature.
5. **Real-time:** when a new alert arrives the page updates instantly via **SSE** → "⚡ live" in the header.
6. **Secure agent + FIM/auth:** run the agent with `--config config.secure.yaml` and
   modify `lab/watched/critical.conf` → **file-integrity** alert; add a failed login line to
   `lab/auth.log` → **brute-force** alert (over the signed/encrypted channel).

## Manual step-by-step
```powershell
# 1) Services (4 separate windows) — or scripts\start_all.ps1
# 2) Blue:  python scripts\seed_demo.py
# 3) Red:   cd scanner; python -m aegis_scanner.main --target 127.0.0.1
# 4) ML:    python scripts\ml_demo.py
# 5) Crypto: python scripts\tamper_demo.py --id 1   (then /api/integrity/verify)
# 6) FIM/auth: cd agent; python -m aegis_agent.main --config config.secure.yaml
```

## Suggested recording frame
- Dashboard top cards (alert counts + 🔒 integrity), Severity Distribution bar,
  Scan & Assets + ML Detections panels, Alerts table (×N + status), Telemetry stream (🔒 secure).
