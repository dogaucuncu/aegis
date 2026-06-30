"""ARP-spoofing SIMULATION (lab-only) — demonstrates MITM detection without touching the network.

It writes a benign ARP table to a JSON fixture, baselines the ARPMonitor on it, then 'poisons'
the fixture (the gateway's MAC is swapped to the attacker, who also claims a second host). The
detector picks up the change and the arp_change events are sent to the SOC, raising alerts.

No packets are sent — this only edits a local file the detector reads.

Usage:
    python scripts/arp_spoof_sim.py --server http://127.0.0.1:8000
"""
import argparse
import json
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "agent"))

from aegis_agent.arp_monitor import ARPMonitor  # noqa: E402  (after sys.path setup)

BENIGN = {
    "192.168.1.1": "aa:bb:cc:00:00:01",   # gateway
    "192.168.1.10": "aa:bb:cc:00:00:10",
    "192.168.1.20": "aa:bb:cc:00:00:20",
}
ATTACKER_MAC = "de:ad:be:ef:13:37"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    parser.add_argument("--fixture", default=str(ROOT / "lab" / "arp_table.json"))
    args = parser.parse_args()
    url = args.server.rstrip("/")
    fixture = Path(args.fixture)
    fixture.parent.mkdir(parents=True, exist_ok=True)

    # 1) benign baseline
    fixture.write_text(json.dumps(BENIGN), encoding="utf-8")
    monitor = ARPMonitor(str(fixture))
    print(f"[arp-sim] baseline captured: {len(BENIGN)} hosts")

    # 2) poison: gateway now answers with the attacker MAC, which also claims another host.
    poisoned = dict(BENIGN)
    poisoned["192.168.1.1"] = ATTACKER_MAC
    poisoned["192.168.1.20"] = ATTACKER_MAC  # one MAC -> multiple IPs
    fixture.write_text(json.dumps(poisoned), encoding="utf-8")
    print(f"[arp-sim] poisoned: gateway 192.168.1.1 -> {ATTACKER_MAC}")

    # 3) detect + report to the SOC
    events = monitor.collect()
    for e in events:
        e["agent_id"] = "agent-mitm-lab"
    print(f"[arp-sim] detector produced {len(events)} arp_change event(s)")
    resp = requests.post(url + "/api/ingest", json={"events": events}, timeout=10)
    resp.raise_for_status()
    print("[arp-sim] SOC:", resp.json(), "-> view:", url + "/api/alerts")


if __name__ == "__main__":
    main()
