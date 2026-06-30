"""SOC summary stats (Milestone 6) — powers dashboard panels and threat-hunting.

One call returns alert counts by severity/tactic/rule, event counts by type, and the busiest
agents, so the UI does not have to derive them client-side.
"""
from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db

router = APIRouter(prefix="/api", tags=["stats"])


def _counts(rows):
    return {str(k): int(v) for k, v in rows if k is not None}


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    a = models.Alert
    e = models.Event
    by_rule = (
        db.query(a.rule_id, func.count()).group_by(a.rule_id)
        .order_by(func.count().desc()).limit(10).all()
    )
    top_agents = (
        db.query(e.agent_id, func.count()).group_by(e.agent_id)
        .order_by(func.count().desc()).limit(8).all()
    )
    return {
        "alerts_total": db.query(func.count(a.id)).scalar() or 0,
        "alerts_open": db.query(func.count(a.id)).filter(a.status == "open").scalar() or 0,
        "events_total": db.query(func.count(e.id)).scalar() or 0,
        "blocked_ips": db.query(func.count(models.BlockedIP.ip)).scalar() or 0,
        "by_severity": _counts(db.query(a.severity, func.count()).group_by(a.severity).all()),
        "by_tactic": _counts(db.query(a.tactic, func.count()).group_by(a.tactic).all()),
        "by_rule": _counts(by_rule),
        "events_by_type": _counts(db.query(e.event_type, func.count()).group_by(e.event_type).all()),
        "top_agents": _counts(top_agents),
    }
