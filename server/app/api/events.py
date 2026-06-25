"""Event query endpoints + log integrity verification."""
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from .. import integrity, models, schemas
from ..database import get_db

router = APIRouter(prefix="/api", tags=["events"])


@router.get("/events", response_model=List[schemas.EventOut])
def list_events(
    agent_id: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
):
    q = db.query(models.Event)
    if agent_id:
        q = q.filter(models.Event.agent_id == agent_id)
    if event_type:
        q = q.filter(models.Event.event_type == event_type)
    return q.order_by(models.Event.id.desc()).limit(limit).all()


@router.get("/integrity/verify", response_model=schemas.IntegrityResult)
def verify_integrity(db: Session = Depends(get_db)):
    """Recomputes the hash chain over retained events and reports whether tampering occurred.

    Anchors on the earliest remaining event's stored prev_hash so the chain stays verifiable
    after retention pruning (see maintenance.prune)."""
    events = db.query(models.Event).order_by(models.Event.id.asc()).all()
    prev_hash = events[0].prev_hash if events else None
    for ev in events:
        expected = integrity.compute_hash(
            prev_hash, ev.agent_id, ev.event_type, ev.timestamp, ev.data
        )
        if expected != ev.hash:
            return schemas.IntegrityResult(
                total_events=len(events),
                valid=False,
                broken_at_event_id=ev.id,
                message=f"Chain broken: event #{ev.id} may have been tampered with.",
            )
        prev_hash = ev.hash
    return schemas.IntegrityResult(
        total_events=len(events),
        valid=True,
        message="The entire log chain integrity was verified.",
    )
