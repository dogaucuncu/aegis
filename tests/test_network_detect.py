"""Network-layer detection tests (Milestone 3): ARP spoofing + flood, agent-side and via the API."""
import json

from aegis_agent.arp_monitor import ARPMonitor
from aegis_agent.flood_detector import FloodDetector


def test_arp_mac_change_detected(tmp_path):
    f = tmp_path / "arp.json"
    f.write_text(json.dumps({"192.168.1.1": "aa:aa:aa:aa:aa:aa"}))
    mon = ARPMonitor(str(f))
    f.write_text(json.dumps({"192.168.1.1": "de:ad:be:ef:13:37"}))
    events = mon.collect()
    assert all(e["event_type"] == "arp_change" for e in events)
    assert "mac_changed" in {e["data"]["risk"] for e in events}


def test_arp_duplicate_mac_detected(tmp_path):
    f = tmp_path / "arp.json"
    f.write_text(json.dumps({"10.0.0.1": "aa:aa:aa:aa:aa:aa"}))
    mon = ARPMonitor(str(f))
    f.write_text(json.dumps({"10.0.0.1": "de:ad:be:ef:13:37", "10.0.0.2": "de:ad:be:ef:13:37"}))
    assert "duplicate_mac" in {e["data"]["risk"] for e in mon.collect()}


def test_arp_no_change_no_events(tmp_path):
    f = tmp_path / "arp.json"
    f.write_text(json.dumps({"10.0.0.1": "aa:aa:aa:aa:aa:aa"}))
    mon = ARPMonitor(str(f))
    assert mon.collect() == []


def test_flood_detector_threshold():
    det = FloodDetector(window_sec=60, threshold=10)
    net = [{"data": {"raddr": "9.9.9.9:443"}} for _ in range(12)]
    events = det.analyze(net)
    assert len(events) == 1
    assert events[0]["event_type"] == "flood_detected"
    assert events[0]["data"]["target_ip"] == "9.9.9.9"
    assert det.analyze(net) == []  # re-alert throttled within the window


def test_flood_detector_below_threshold():
    det = FloodDetector(window_sec=60, threshold=10)
    assert det.analyze([{"data": {"raddr": "9.9.9.9:443"}} for _ in range(3)]) == []


def test_arp_rule_alerts(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "a", "event_type": "arp_change",
         "data": {"ip": "192.168.1.1", "old_mac": "aa:aa", "new_mac": "de:ad", "risk": "mac_changed"}}
    ]})
    ids = {a["rule_id"] for a in client.get("/api/alerts").json()}
    assert "arp-spoofing" in ids


def test_flood_rule_alerts(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "a", "event_type": "flood_detected",
         "data": {"target_ip": "9.9.9.9", "connection_count": 120, "window_sec": 60, "source": "agent-outbound"}}
    ]})
    ids = {a["rule_id"] for a in client.get("/api/alerts").json()}
    assert "network-flood" in ids


def test_portscan_summary_rule_alerts(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "scanner", "event_type": "port_scan",
         "data": {"target": "127.0.0.1", "source_ip": "scanner", "ports": list(range(1, 15))}}
    ]})
    ids = {a["rule_id"] for a in client.get("/api/alerts").json()}
    assert "port-scan" in ids
