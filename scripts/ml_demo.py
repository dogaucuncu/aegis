"""Phase 4 ML demo: scores URLs/flows and sends the detections to the SOC as alerts.

First: the ML service (8001) and the SOC server (8000) must be running, models must be trained.
Usage: python scripts/ml_demo.py
"""
import argparse

import requests

URLS = [
    "https://www.github.com/user/repo",          # benign
    "https://www.google.com/search?q=test",        # benign
    "http://paypal.secure-login.verify.tk/index",  # phishing
    "http://192.0.2.55/account-confirm.php?cmd=login",  # phishing
]

FLOWS = [
    ("normal", {"duration": 5, "src_bytes": 900, "dst_bytes": 2200, "count": 4,
                "srv_count": 4, "serror_rate": 0.02, "same_srv_rate": 0.95, "dst_host_count": 35}),
    ("attack", {"duration": 0.2, "src_bytes": 100, "dst_bytes": 60, "count": 130,
                "srv_count": 120, "serror_rate": 0.8, "same_srv_rate": 0.1, "dst_host_count": 230}),
]

DOMAINS = [
    "secureshop.com",                 # benign
    "kq3x9zr7vw2htb8s.top",           # DGA / C2
    "x7gh21qwerty9zxc.ru",            # DGA / C2
]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ml", default="http://127.0.0.1:8001")
    parser.add_argument("--soc", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    detections = []

    print("=== Phishing URL scoring ===")
    for url in URLS:
        r = requests.post(args.ml + "/score/url", json={"url": url}, timeout=10).json()
        print(f"  [{r['label']:8}] {r['score']:.3f}  {url}")
        if r["label"] == "phishing":
            detections.append({"event_type": "phishing", "data": {"url": url, "score": r["score"]}})

    print("\n=== NIDS flow scoring ===")
    for expected, flow in FLOWS:
        r = requests.post(args.ml + "/score/flow", json={"features": flow}, timeout=10).json()
        print(f"  expected={expected:6} -> [{r['label']:6}] {r['score']:.3f}")
        if r["label"] == "attack":
            detections.append({"event_type": "ml_anomaly",
                               "data": {"source": "flow-demo", "score": r["score"], "note": "high count/serror"}})

    print("\n=== DGA domain scoring ===")
    for domain in DOMAINS:
        r = requests.post(args.ml + "/score/domain", json={"domain": domain}, timeout=10).json()
        print(f"  [{r['label']:6}] {r['score']:.3f}  {domain}")
        if r["label"] == "dga":
            detections.append({"event_type": "dga_detection",
                               "data": {"domain": domain, "score": r["score"]}})

    if detections:
        payload = {"events": [{"agent_id": "ml-engine", **d} for d in detections]}
        resp = requests.post(args.soc + "/api/ingest", json=payload, timeout=10)
        resp.raise_for_status()
        print(f"\n[report] {len(detections)} ML detections sent to the SOC -> {args.soc}/api/alerts")


if __name__ == "__main__":
    main()
