"""Phase B tests: request-id header, audit logging, retention pruning."""
import datetime as dt
import logging


def test_request_id_header_present(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.headers.get("X-Request-ID")


def test_request_id_propagated(client):
    r = client.get("/health", headers={"X-Request-ID": "abc123"})
    assert r.headers.get("X-Request-ID") == "abc123"


def test_audit_log_on_status_change(client, caplog):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "mimikatz.exe"}}
    ]})
    alert_id = client.get("/api/alerts").json()[0]["id"]

    with caplog.at_level(logging.INFO, logger="aegis.audit"):
        r = client.post(f"/api/alerts/{alert_id}/status?status=resolved")
    assert r.status_code == 200
    assert any("alert_status_change" in rec.message for rec in caplog.records)


def test_prune_old_closed_alerts(client):
    from app import maintenance, models
    from app.database import SessionLocal
    from app.utils import now_utc

    client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "mimikatz.exe"}}
    ]})

    db = SessionLocal()
    try:
        alert = db.query(models.Alert).first()
        alert.status = "closed"
        alert.created_at = now_utc() - dt.timedelta(days=40)
        db.commit()

        # Within retention window -> nothing removed.
        assert maintenance.prune(db, retention_days=90)["alerts_deleted"] == 0
        # Older than window -> removed.
        assert maintenance.prune(db, retention_days=30)["alerts_deleted"] == 1
        assert db.query(models.Alert).count() == 0
    finally:
        db.close()


def test_prune_disabled_is_noop(client):
    from app import maintenance
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        assert maintenance.prune(db, retention_days=0) == {"alerts_deleted": 0, "events_deleted": 0}
    finally:
        db.close()
