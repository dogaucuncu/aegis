"""Event persistence service: hash chain + rule evaluation.

Both the plain (`/api/ingest`) and secure (`/api/ingest/secure`) paths use this.
"""
import datetime as dt
import threading
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from . import integrity, models, rules
from .utils import now_utc

# The hash chain is global; to prevent concurrent appends from forking the chain,
# serialize the critical section (read last hash → append → commit) with an in-process lock.
# A multi-process/PG deployment requires a row-level DB lock (SELECT FOR UPDATE).
_chain_lock = threading.Lock()


def _coerce_ts(ts: Any) -> dt.datetime:
    if ts is None:
        return now_utc()
    if isinstance(ts, dt.datetime):
        return ts
    return dt.datetime.fromisoformat(str(ts))


def persist_events(
    db: Session,
    events: List[Dict[str, Any]],
    signatures: Optional[List[Optional[str]]] = None,
) -> Tuple[int, int]:
    """events: [{agent_id, event_type, timestamp, data}, ...]; returns (ingested, alerts)."""
    with _chain_lock:
        return _append_locked(db, events, signatures)


def _chain_head(db: Session) -> models.ChainHead:
    """Returns the chain head; locks the row on PostgreSQL (FOR UPDATE)."""
    q = db.query(models.ChainHead).filter_by(id=1)
    if db.bind.dialect.name == "postgresql":
        q = q.with_for_update()
    head = q.first()
    if head is None:
        # First time: bootstrap from the current last event for continuity.
        last = db.query(models.Event).order_by(models.Event.id.desc()).first()
        head = models.ChainHead(id=1, last_hash=last.hash if last else None)
        db.add(head)
        db.flush()
    return head


def _append_locked(
    db: Session,
    events: List[Dict[str, Any]],
    signatures: Optional[List[Optional[str]]],
) -> Tuple[int, int]:
    ingested = 0
    alerts_created = 0

    head = _chain_head(db)
    prev_hash = head.last_hash

    for i, ev in enumerate(events):
        ts = _coerce_ts(ev.get("timestamp"))
        data = ev.get("data", {}) or {}
        agent_id = ev["agent_id"]
        event_type = ev["event_type"]
        h = integrity.compute_hash(prev_hash, agent_id, event_type, ts, data)
        sig = signatures[i] if signatures and i < len(signatures) else None

        obj = models.Event(
            agent_id=agent_id,
            event_type=event_type,
            timestamp=ts,
            data=data,
            prev_hash=prev_hash,
            hash=h,
            signature=sig,
        )
        db.add(obj)
        db.flush()
        prev_hash = h
        ingested += 1

        for alert in rules.evaluate(obj, db):
            existing = (
                db.query(models.Alert)
                .filter(
                    models.Alert.dedup_key == alert.dedup_key,
                    models.Alert.status == "open",
                )
                .first()
            )
            if existing is not None:
                # Correlation: do not duplicate the same OPEN alert, increment the seen count.
                existing.count += 1
                existing.last_seen = now_utc()
                existing.event_id = obj.id
            else:
                alert.event_id = obj.id
                alert.agent_id = obj.agent_id
                alert.last_seen = now_utc()
                db.add(alert)
                alerts_created += 1

    head.last_hash = prev_hash
    db.commit()
    return ingested, alerts_created
