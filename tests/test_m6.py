"""Milestone 6 tests: canary tokens, auto-response blocklist, stats, rule hot-reload."""
import pytest


@pytest.fixture(autouse=True)
def _clean_blocklist():
    from app import responder
    responder._blocked.clear()
    yield
    responder._blocked.clear()


# ---------------- canary / deception ----------------
def test_web_canary_triggers_alert(client):
    r = client.get("/api/canary/secret-admin-panel")
    assert r.status_code == 200  # believable decoy response
    ids = {a["rule_id"] for a in client.get("/api/alerts").json()}
    assert "canary-triggered" in ids


def test_agent_canary_file_detection(tmp_path):
    from aegis_agent.collector import TelemetryCollector

    decoy = tmp_path / "passwords.xlsx"
    decoy.write_text("decoy contents")
    collector = TelemetryCollector(canary_paths=[str(decoy)])
    assert collector.collect_canary() == []          # unchanged -> silent
    decoy.write_text("touched by an intruder")
    events = collector.collect_canary()
    assert len(events) == 1
    assert events[0]["event_type"] == "canary_triggered"
    assert events[0]["data"]["action"] == "modified" and events[0]["data"]["kind"] == "file"


# ---------------- auto-response / blocklist ----------------
def test_manual_blocklist_api(client):
    assert client.post("/api/blocklist/9.9.9.9").json()["blocked"] is True
    assert "9.9.9.9" in [b["ip"] for b in client.get("/api/blocklist").json()]
    client.delete("/api/blocklist/9.9.9.9")
    assert "9.9.9.9" not in [b["ip"] for b in client.get("/api/blocklist").json()]


def test_blocklist_middleware_rejects_blocked_ip(client):
    from app import responder
    from app.middleware import BlocklistMiddleware
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app2 = FastAPI()
    app2.add_middleware(BlocklistMiddleware)

    @app2.get("/x")
    def _x():
        return {"ok": True}

    c = TestClient(app2)
    assert c.get("/x").status_code == 200          # TestClient host not blocked
    responder._blocked.add("testclient")
    assert c.get("/x").status_code == 403          # now rejected by the middleware


def test_auto_block_policy_on_bruteforce(client, monkeypatch):
    from app import config, responder
    monkeypatch.setattr(config, "AUTO_BLOCK", True)
    monkeypatch.setattr(config, "AUTO_BLOCK_RULES", {"web-bruteforce"})

    ev = {"agent_id": "x", "event_type": "auth_attempt",
          "data": {"username": "admin", "success": False, "source_ip": "203.0.113.50",
                   "target": "/login"}}
    client.post("/api/ingest", json={"events": [ev] * 5})  # crosses the brute-force threshold
    assert "203.0.113.50" in responder.list_blocked()


# ---------------- threat-hunting ----------------
def test_stats_endpoint(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "a", "event_type": "process", "data": {"name": "mimikatz.exe"}}
    ]})
    s = client.get("/api/stats").json()
    assert s["alerts_total"] >= 1
    assert s["events_by_type"].get("process", 0) >= 1
    assert "by_severity" in s and "by_tactic" in s and "top_agents" in s


def test_rules_hot_reload(client):
    r = client.post("/api/rules/reload")
    assert r.status_code == 200 and r.json()["reloaded"] is True and r.json()["rules"] > 0
