"""Brute-force module tests (red) + end-to-end detection (blue)."""
import pytest
from aegis_scanner import bruteforce


# ---------------- scanner module (red) ----------------
def test_loopback_guard_blocks_remote():
    with pytest.raises(PermissionError):
        bruteforce.scan("http://example.com/login", "admin", ["x"])


def test_scan_stops_at_first_success(monkeypatch):
    monkeypatch.setattr(bruteforce, "_attempt", lambda url, u, p, timeout=5.0: p == "s3cr3t")
    events = bruteforce.scan("http://127.0.0.1:5001/login", "admin", ["a", "b", "s3cr3t", "c"])
    assert len(events) == 3  # stops at the hit; "c" is never tried
    assert all(e["event_type"] == "auth_attempt" for e in events)
    assert events[-1]["data"]["success"] is True


def test_spray_one_password_many_users(monkeypatch):
    monkeypatch.setattr(bruteforce, "_attempt", lambda url, u, p, timeout=5.0: u == "admin")
    events = bruteforce.spray("http://127.0.0.1/login", ["alice", "admin", "bob"], "Spring2024!")
    assert [e["data"]["success"] for e in events] == [False, True, False]


# ---------------- end-to-end detection (blue) ----------------
def _attempt(success, user="admin", agent="scanner-01"):
    return {
        "agent_id": agent,
        "event_type": "auth_attempt",
        "data": {"target": "http://127.0.0.1:5001/login", "username": user, "success": success},
    }


def test_bruteforce_kill_chain_alerts(client):
    batch = [_attempt(False) for _ in range(5)] + [_attempt(True)]
    r = client.post("/api/ingest", json={"events": batch})
    assert r.status_code == 200
    ids = {a["rule_id"] for a in client.get("/api/alerts").json()}
    assert "web-bruteforce" in ids       # windowed threshold on failed attempts
    assert "bruteforce-success" in ids   # correlation: success after >=5 failures


def test_few_failures_no_alert(client):
    batch = [_attempt(False) for _ in range(3)]
    r = client.post("/api/ingest", json={"events": batch})
    assert r.json()["alerts_created"] == 0
