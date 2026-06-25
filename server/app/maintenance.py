"""Retention/pruning maintenance for events and alerts.

Hash-chain note: pruning old events removes the chain *prefix*. `verify_integrity` anchors on
the earliest **remaining** event's stored `prev_hash`, so the retained window stays verifiable
(the pruned prefix is gone and is no longer attestable — that is the intended retention trade-off).
"""
import datetime as dt
from typing import Dict

from sqlalchemy.orm import Session

from . import models
from .utils import now_utc


def prune(db: Session, retention_days: int, include_events: bool = False) -> Dict[str, int]:
    """Delete data older than `retention_days`.

    - Always: alerts in a terminal state (closed/resolved) older than the cutoff.
    - Optional (`include_events`): raw events older than the cutoff. Referencing alerts are
      detached (event_id -> NULL) first to respect the FK on PostgreSQL.
    """
    if retention_days <= 0:
        return {"alerts_deleted": 0, "events_deleted": 0}

    cutoff = now_utc() - dt.timedelta(days=retention_days)

    alerts_deleted = (
        db.query(models.Alert)
        .filter(
            models.Alert.created_at < cutoff,
            models.Alert.status.in_(["closed", "resolved"]),
        )
        .delete(synchronize_session=False)
    )

    events_deleted = 0
    if include_events:
        old_events = db.query(models.Event.id).filter(models.Event.timestamp < cutoff)
        db.query(models.Alert).filter(models.Alert.event_id.in_(old_events)).update(
            {"event_id": None}, synchronize_session=False
        )
        events_deleted = (
            db.query(models.Event)
            .filter(models.Event.timestamp < cutoff)
            .delete(synchronize_session=False)
        )

    db.commit()
    return {"alerts_deleted": alerts_deleted, "events_deleted": events_deleted}
