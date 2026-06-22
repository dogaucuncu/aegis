"""Alert query and status update endpoints."""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import models, schemas
from ..auth import require_api_key
from ..database import get_db

router = APIRouter(prefix="/api", tags=["alerts"])


@router.get("/alerts", response_model=List[schemas.AlertOut])
def list_alerts(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(100, le=1000),
    db: Session = Depends(get_db),
):
    q = db.query(models.Alert)
    if severity:
        q = q.filter(models.Alert.severity == severity)
    if status:
        q = q.filter(models.Alert.status == status)
    return q.order_by(models.Alert.id.desc()).limit(limit).all()


@router.post(
    "/alerts/{alert_id}/status",
    response_model=schemas.AlertOut,
    dependencies=[Depends(require_api_key)],
)
def update_status(alert_id: int, status: str, db: Session = Depends(get_db)):
    alert = db.get(models.Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = status
    db.commit()
    db.refresh(alert)
    return alert
