"""Adversarial robustness test for the phishing model (Milestone 5).

Loads the trained phishing model, probes it with evasion variants of known phishing URLs, and
reports the evasion rate / robustness. If the evasion rate is high it sends an `ml_evasion`
event to the SOC (raising the ml-evasion alert). Tests your OWN model — no external target.

Usage:
    python scripts/adversarial_test.py --soc http://127.0.0.1:8000
"""
import argparse
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "ml"))

from aegis_ml import adversarial, serve  # noqa: E402  (after sys.path setup)

PHISHING_SAMPLES = [
    "http://paypal.secure-login.verify.tk/index",
    "http://192.0.2.55/account-confirm.php?cmd=login",
    "http://apple.account-confirm.bank-signin.ga/index",
    "http://secure-bank-verify.xyz/login",
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--soc", default="http://127.0.0.1:8000")
    parser.add_argument("--threshold", type=float, default=0.3)
    args = parser.parse_args()

    try:
        bundle = serve.load("phishing")
    except FileNotFoundError:
        sys.exit("phishing model not found — run: python -m aegis_ml.train --only phishing")

    report = adversarial.evasion_rate(bundle, PHISHING_SAMPLES)
    print(f"[adversarial] tested={report['tested']} evaded={report['evaded']} "
          f"evasion_rate={report['evasion_rate']} robustness={report['robustness']}")

    if report["evasion_rate"] >= args.threshold:
        event = {"agent_id": "ml-engine", "event_type": "ml_evasion",
                 "data": {"model": "phishing", **report}}
        resp = requests.post(args.soc + "/api/ingest", json={"events": [event]}, timeout=10)
        resp.raise_for_status()
        print(f"[adversarial] evasion rate >= {args.threshold} -> ml_evasion alert sent to {args.soc}")
    else:
        print("[adversarial] model is robust against these probes (no alert).")


if __name__ == "__main__":
    main()
