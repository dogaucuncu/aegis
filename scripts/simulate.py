"""Demo simülasyonu: kural motorunu tetikleyecek sentetik olaylar gönderir.

Gerçek saldırı aracı çalıştırmadan dashboard'da alarm üretmek için kullanılır.
Kullanım:
    python scripts/simulate.py --server http://127.0.0.1:8000
"""
import argparse

import requests


def post(url, events):
    resp = requests.post(url + "/api/ingest", json={"events": events}, timeout=10)
    resp.raise_for_status()
    return resp.json()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    url = args.server.rstrip("/")
    agent = "sim-endpoint-01"

    # 1) Şüpheli komut satırı (encoded PowerShell)
    print("[sim] Şüpheli PowerShell süreci...")
    print(post(url, [{
        "agent_id": agent,
        "event_type": "process",
        "data": {
            "pid": 6666,
            "name": "powershell.exe",
            "cmdline": "powershell.exe -nop -w hidden -enc SQBFAFgAKAB...",
            "username": "victim",
        },
    }]))

    # 2) Bilinen saldırı aracı
    print("[sim] Mimikatz...")
    print(post(url, [{
        "agent_id": agent,
        "event_type": "process",
        "data": {"pid": 7777, "name": "mimikatz.exe", "cmdline": "mimikatz.exe sekurlsa::logonpasswords"},
    }]))

    # 3) Brute-force (eşik = 5 / 60s)
    print("[sim] Brute-force serisi...")
    fails = [{
        "agent_id": agent,
        "event_type": "auth_failure",
        "data": {"username": "admin", "source_ip": "203.0.113.7"},
    } for _ in range(6)]
    print(post(url, fails))

    # 4) Port tarama
    print("[sim] Port tarama...")
    print(post(url, [{
        "agent_id": agent,
        "event_type": "port_scan",
        "data": {"source_ip": "203.0.113.7", "target": "10.0.0.5",
                 "ports": list(range(20, 35))},
    }]))

    print("\n[sim] Tamamlandı. Alarmları gör: " + url + "/api/alerts")


if __name__ == "__main__":
    main()
