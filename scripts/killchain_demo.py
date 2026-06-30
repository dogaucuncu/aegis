"""Milestone 1 demo — the credential-attack kill chain, end to end.

Tells one story across all four domains against the local SOC:
  RED    brute-force a login (lab /login if it is up, otherwise synthesized attempts)
  BLUE   the SOC raises web-bruteforce + bruteforce-success alerts
  CRYPTO the hardened /api/auth/login resists with Argon2 + account lockout
  ML     an anomalous login is scored and raised as ml-ueba-anomaly

Usage:
    python scripts/killchain_demo.py --server http://127.0.0.1:8000 \
        --lab http://127.0.0.1:5001

Requires only the SOC to be running; the lab and ML engine are optional.
"""
import argparse
import sys
from pathlib import Path

import requests

# Make the scanner package importable so the demo uses the real red-team module.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner"))
from aegis_scanner import bruteforce  # noqa: E402


def _post_events(server, events):
    r = requests.post(f"{server}/api/ingest", json={"events": events}, timeout=10)
    r.raise_for_status()
    return r.json()


def _synth_attempts(user, target, fails=5):
    seq = [{"agent_id": "scanner-01", "event_type": "auth_attempt",
            "data": {"target": target, "username": user, "success": False}} for _ in range(fails)]
    seq.append({"agent_id": "scanner-01", "event_type": "auth_attempt",
                "data": {"target": target, "username": user, "success": True}})
    return seq


def main():
    ap = argparse.ArgumentParser(description="Aegis credential-attack kill-chain demo")
    ap.add_argument("--server", default="http://127.0.0.1:8000")
    ap.add_argument("--lab", default="http://127.0.0.1:5001")
    args = ap.parse_args()
    server = args.server.rstrip("/")

    print(f"[*] SOC: {server}")
    requests.get(f"{server}/health", timeout=5).raise_for_status()

    # --- RED + BLUE: brute-force a login ---
    lab_login = f"{args.lab.rstrip('/')}/login"
    lab_up = False
    try:
        requests.get(args.lab, timeout=2)
        lab_up = True
    except requests.RequestException:
        pass

    if lab_up:
        print(f"[RED] brute-forcing lab login {lab_login}")
        events = bruteforce.scan(lab_login, "admin")  # lab seeds admin/s3cr3t
        hit = next((e for e in events if e["data"]["success"]), None)
        print(f"      {len(events)} attempts, "
              + ("CRACKED" if hit else "no hit (is the lab seeded?)"))
        _post_events(server, events)
    else:
        print("[RED] lab not reachable — synthesizing brute-force attempts")
        _post_events(server, _synth_attempts("admin", lab_login))

    # --- CRYPTO: hardened login resists brute-force (lockout) ---
    print("[CRYPTO] hammering the hardened /api/auth/login")
    requests.post(f"{server}/api/auth/register", json={"username": "victim", "password": "S3cure!pw"}, timeout=10)
    codes = []
    for _ in range(6):
        rr = requests.post(f"{server}/api/auth/login", json={"username": "victim", "password": "guess"}, timeout=10)
        codes.append(rr.status_code)
    locked = 423 in codes
    print(f"      statuses={codes} -> {'LOCKED OUT (good)' if locked else 'not locked'}")

    # --- ML: anomalous login behavior ---
    print("[ML] reporting an anomalous login (UEBA)")
    _post_events(server, [{
        "agent_id": "ml-engine", "event_type": "ueba_anomaly",
        "data": {"username": "admin", "score": 0.94, "note": "night-time, many IPs, high failure rate"},
    }])

    # --- Show the kill chain on the SOC ---
    alerts = requests.get(f"{server}/api/alerts", timeout=10).json()
    wanted = {"web-bruteforce", "bruteforce-success", "ml-ueba-anomaly"}
    print("\n[SOC] kill-chain alerts:")
    for a in alerts:
        if a["rule_id"] in wanted:
            print(f"  - [{a['severity']}] {a['rule_id']}: {a['title']}")
    missing = wanted - {a["rule_id"] for a in alerts}
    if missing:
        print(f"  (not raised: {', '.join(sorted(missing))})")
    print("\nDone. Open the dashboard or GET /api/alerts to explore.")


if __name__ == "__main__":
    main()
