"""Hash-chain integrity (tamper-evident log) tests."""


def test_integrity_valid_then_detects_tamper(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "a"}},
        {"agent_id": "t", "event_type": "process", "data": {"name": "b"}},
    ]})
    assert client.get("/api/integrity/verify").json()["valid"] is True

    # Manually modify an event in the DB (tampering)
    from app import models
    from app.database import SessionLocal

    db = SessionLocal()
    ev = db.query(models.Event).order_by(models.Event.id.asc()).first()
    ev.data = {"tampered": True}
    db.commit()
    tampered_id = ev.id
    db.close()

    res = client.get("/api/integrity/verify").json()
    assert res["valid"] is False
    assert res["broken_at_event_id"] == tampered_id
