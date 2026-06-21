"""Tek komutla zengin demo verisi — dört alanı da doldurur (Faz 5).

Servisleri tek tek çalıştırmadan dashboard'u dolu göstermek için /api/ingest'e
küratörlü bir olay batch'i gönderir.
Kullanım: python scripts/seed_demo.py --server http://127.0.0.1:8000
"""
import argparse

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    args = parser.parse_args()

    events = []

    # --- Blue: süreçler (benign + şüpheli) ---
    events += [
        {"agent_id": "ws-01", "event_type": "process",
         "data": {"name": "chrome.exe", "cmdline": "chrome.exe --type=renderer", "username": "alice"}},
        {"agent_id": "ws-01", "event_type": "process",
         "data": {"name": "powershell.exe", "cmdline": "powershell -nop -w hidden -enc SQBFAFgA", "username": "alice"}},
        {"agent_id": "ws-02", "event_type": "process",
         "data": {"name": "mimikatz.exe", "cmdline": "mimikatz.exe sekurlsa::logonpasswords", "username": "svc"}},
    ]
    # --- Blue: brute-force (eşik 5/60s) ---
    events += [
        {"agent_id": "srv-ssh", "event_type": "auth_failure",
         "data": {"username": "root", "source_ip": "203.0.113.7"}} for _ in range(6)
    ]
    # --- Blue: ağ ---
    events.append({"agent_id": "ws-01", "event_type": "network",
                   "data": {"laddr": "10.0.0.10:51000", "raddr": "140.82.112.3:443", "status": "ESTABLISHED"}})

    # --- Red: tarama bulguları ---
    events += [
        {"agent_id": "scanner-01", "event_type": "open_port", "data": {"host": "10.0.0.5", "port": 22, "service": "ssh"}},
        {"agent_id": "scanner-01", "event_type": "open_port", "data": {"host": "10.0.0.5", "port": 3306, "service": "mysql"}},
        {"agent_id": "scanner-01", "event_type": "vuln_finding",
         "data": {"type": "sqli", "url": "http://10.0.0.5/user?id=1", "param": "id",
                  "payload": "' OR '1'='1", "evidence": "SQL hata mesaji yansidi", "severity": "high"}},
        {"agent_id": "scanner-01", "event_type": "vuln_finding",
         "data": {"type": "xss", "url": "http://10.0.0.5/search?q=test", "param": "q",
                  "payload": "<svg/onload=alert(1)>", "evidence": "Payload kacissiz yansidi", "severity": "medium"}},
    ]

    # --- ML: tespitler ---
    events += [
        {"agent_id": "ml-engine", "event_type": "phishing",
         "data": {"url": "http://paypal.secure-login.verify.tk/index", "score": 0.94}},
        {"agent_id": "ml-engine", "event_type": "ml_anomaly",
         "data": {"source": "flow-10.0.0.5", "score": 0.98, "note": "yuksek count/serror"}},
    ]

    resp = requests.post(args.server.rstrip("/") + "/api/ingest", json={"events": events}, timeout=15)
    resp.raise_for_status()
    result = resp.json()
    print(f"[seed] {result['ingested']} olay, {result['alerts_created']} alarm olusturuldu.")
    print(f"[seed] Dashboard: {args.server}  |  Alarmlar: {args.server}/api/alerts")


if __name__ == "__main__":
    main()
