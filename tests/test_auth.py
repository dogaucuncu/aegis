"""API key auth tests (WP4)."""


def test_auth_off_by_default(client):
    # AEGIS_API_KEYS not set -> ingest works without a key (demo compatibility)
    r = client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "x"}}
    ]})
    assert r.status_code == 200


def test_auth_enforced_when_configured(client, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "API_KEYS", {"secret123"})
    body = {"events": [{"agent_id": "t", "event_type": "process", "data": {"name": "x"}}]}

    assert client.post("/api/ingest", json=body).status_code == 401
    assert client.post("/api/ingest", json=body, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.post("/api/ingest", json=body, headers={"X-API-Key": "secret123"}).status_code == 200
    # Read endpoints stay open (dashboard polling)
    assert client.get("/api/alerts").status_code == 200


def test_alert_status_change_requires_key(client, monkeypatch):
    from app import config

    # first produce an alert (while auth is off)
    client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "mimikatz.exe"}}
    ]})
    alert_id = client.get("/api/alerts").json()[0]["id"]

    monkeypatch.setattr(config, "API_KEYS", {"k"})
    assert client.post(f"/api/alerts/{alert_id}/status?status=closed").status_code == 401
    assert client.post(
        f"/api/alerts/{alert_id}/status?status=closed", headers={"X-API-Key": "k"}
    ).status_code == 200
