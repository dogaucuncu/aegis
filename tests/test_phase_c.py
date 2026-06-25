"""Phase C tests: agent inventory, triage, MITRE mapping, filters, webhook."""


def _ingest(client, agent_id, name):
    return client.post("/api/ingest", json={"events": [
        {"agent_id": agent_id, "event_type": "process", "data": {"name": name}}
    ]})


def test_agent_inventory_heartbeat(client):
    _ingest(client, "ws-01", "chrome.exe")
    _ingest(client, "ws-01", "code.exe")
    _ingest(client, "ws-02", "bash")

    agents = {a["agent_id"]: a for a in client.get("/api/agents").json()}
    assert set(agents) == {"ws-01", "ws-02"}
    assert agents["ws-01"]["event_count"] == 2
    assert agents["ws-02"]["event_count"] == 1
    assert agents["ws-01"]["last_seen"]


def test_mitre_mapping_on_alert(client):
    _ingest(client, "ws-02", "mimikatz.exe")
    alert = client.get("/api/alerts").json()[0]
    assert alert["tactic"] == "Credential Access"
    assert alert["technique"] == "T1003"


def test_alert_triage(client):
    _ingest(client, "ws-02", "mimikatz.exe")
    alert_id = client.get("/api/alerts").json()[0]["id"]

    r = client.post(
        f"/api/alerts/{alert_id}/triage",
        json={"assignee": "alice", "tags": "ir,priority"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["assignee"] == "alice"
    assert body["tags"] == "ir,priority"
    assert body["note"] is None  # untouched (exclude_unset)


def test_alert_filters(client):
    _ingest(client, "ws-02", "mimikatz.exe")   # high
    _ingest(client, "ws-03", "nmap")           # benign, no alert

    # text query matches the suspicious-process title
    hits = client.get("/api/alerts?q=mimikatz").json()
    assert len(hits) == 1
    # severity filter
    assert all(a["severity"] == "high" for a in client.get("/api/alerts?severity=high").json())
    # event text filter
    evs = client.get("/api/events?q=ws-03").json()
    assert evs and all(e["agent_id"] == "ws-03" for e in evs)


def test_webhook_fires_for_high_severity(client, monkeypatch):
    from app import config, notifications

    captured = []
    monkeypatch.setattr(notifications, "_deliver", lambda url, payload: captured.append((url, payload)))
    monkeypatch.setattr(config, "WEBHOOK_URL", "http://hook.local/test")

    _ingest(client, "ws-02", "mimikatz.exe")  # high-severity alert
    assert len(captured) == 1
    assert "mimikatz" in captured[0][1]["text"].lower()


def test_webhook_disabled_by_default(client, monkeypatch):
    from app import notifications

    captured = []
    monkeypatch.setattr(notifications, "_deliver", lambda url, payload: captured.append((url, payload)))
    # WEBHOOK_URL empty by default -> no delivery
    _ingest(client, "ws-02", "mimikatz.exe")
    assert captured == []
