"""Phase A hardening tests: /health, alert status enum, read-endpoint auth."""


def test_health_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["db"] is True


def test_alert_status_enum_validation(client):
    # Produce an alert.
    client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "mimikatz.exe"}}
    ]})
    alert_id = client.get("/api/alerts").json()[0]["id"]

    # Invalid status -> 422 (no longer a free-form string).
    assert client.post(f"/api/alerts/{alert_id}/status?status=bogus").status_code == 422

    # Valid status -> 200 and persisted.
    r = client.post(f"/api/alerts/{alert_id}/status?status=acknowledged")
    assert r.status_code == 200
    assert r.json()["status"] == "acknowledged"


def test_read_auth_enforced_when_configured(client, monkeypatch):
    from app import config

    monkeypatch.setattr(config, "API_KEYS", {"k"})
    monkeypatch.setattr(config, "REQUIRE_AUTH_READS", True)

    # Reads now require a key.
    assert client.get("/api/alerts").status_code == 401
    assert client.get("/api/alerts", headers={"X-API-Key": "k"}).status_code == 200
    assert client.get("/api/events", headers={"X-API-Key": "k"}).status_code == 200

    # Health stays open for liveness probes.
    assert client.get("/health").status_code == 200


def test_reads_open_by_default(client, monkeypatch):
    from app import config

    # Even with API keys set, reads stay open unless AEGIS_REQUIRE_AUTH_READS=1.
    monkeypatch.setattr(config, "API_KEYS", {"k"})
    assert client.get("/api/alerts").status_code == 200
