"""Alert query and status update endpoints."""
import hashlib
import logging
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import models, schemas
from ..auth import require_api_key
from ..database import get_db

router = APIRouter(prefix="/api", tags=["alerts"])
audit = logging.getLogger("aegis.audit")


def _actor(request: Request) -> str:
    """Best-effort actor id for the audit trail (no user accounts yet)."""
    key = request.headers.get("X-API-Key")
    if key:
        return "key:" + hashlib.sha256(key.encode()).hexdigest()[:8]
    return "anonymous"


@router.get("/alerts", response_model=List[schemas.AlertOut])
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    q: Optional[str] = Query(None, description="case-insensitive match on title/description"),
    since: Optional[datetime] = None,
    until: Optional[datetime] = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
):
    query = db.query(models.Alert)
    if severity:
        query = query.filter(models.Alert.severity == severity)
    if status:
        query = query.filter(models.Alert.status == status)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(models.Alert.title.ilike(like), models.Alert.description.ilike(like))
        )
    if since:
        query = query.filter(models.Alert.created_at >= since)
    if until:
        query = query.filter(models.Alert.created_at <= until)
    return query.order_by(models.Alert.id.desc()).limit(limit).all()


@router.post(
    "/alerts/{alert_id}/status",
    response_model=schemas.AlertOut,
    dependencies=[Depends(require_api_key)],
)
def update_status(
    alert_id: int,
    status: schemas.AlertStatus,
    request: Request,
    db: Session = Depends(get_db),
):
    alert = db.get(models.Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    old = alert.status
    alert.status = status.value
    db.commit()
    db.refresh(alert)
    audit.info(
        "alert_status_change alert_id=%s %s->%s actor=%s rid=%s",
        alert_id, old, status.value, _actor(request),
        getattr(request.state, "request_id", "-"),
    )
    return alert


@router.post(
    "/alerts/{alert_id}/triage",
    response_model=schemas.AlertOut,
    dependencies=[Depends(require_api_key)],
)
def update_triage(
    alert_id: int,
    body: schemas.TriageIn,
    request: Request,
    db: Session = Depends(get_db),
):
    alert = db.get(models.Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    fields = body.model_dump(exclude_unset=True)
    for field, value in fields.items():
        setattr(alert, field, value)
    db.commit()
    db.refresh(alert)
    audit.info(
        "alert_triage alert_id=%s fields=%s actor=%s rid=%s",
        alert_id, ",".join(fields.keys()) or "-", _actor(request),
        getattr(request.state, "request_id", "-"),
    )
    return alert
