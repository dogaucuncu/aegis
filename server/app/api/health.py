"""Liveness/readiness endpoint: process status + database connectivity.

Used by container orchestrators (Docker/k8s) for health checks. Unauthenticated by design.
"""
import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import get_db

log = logging.getLogger("aegis.health")
router = APIRouter(tags=["health"])


@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        log.exception("health DB ping failed")
        db_ok = False
    return {"status": "ok" if db_ok else "degraded", "db": db_ok}
