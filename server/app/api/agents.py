"""Agent inventory endpoint (heartbeat-based)."""
from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models, schemas
from ..database import get_db

router = APIRouter(prefix="/api", tags=["agents"])


@router.get("/agents", response_model=List[schemas.AgentOut])
def list_agents(db: Session = Depends(get_db)):
    return (
        db.query(models.Agent)
        .order_by(models.Agent.last_seen.desc())
        .all()
    )
