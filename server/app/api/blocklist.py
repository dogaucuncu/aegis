"""IP blocklist management (Milestone 6, auto-response).

GET    /api/blocklist        — list currently blocked IPs (read endpoint).
POST   /api/blocklist/{ip}    — manually block an IP (state-changing, needs an API key).
DELETE /api/blocklist/{ip}    — unblock an IP (state-changing, needs an API key).
"""
import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import models, responder
from ..auth import require_api_key
from ..database import get_db

router = APIRouter(prefix="/api", tags=["blocklist"])
audit = logging.getLogger("aegis.audit")


@router.get("/blocklist")
def list_blocklist(db: Session = Depends(get_db)):
    rows = db.query(models.BlockedIP).order_by(models.BlockedIP.created_at.desc()).all()
    return [
        {"ip": r.ip, "reason": r.reason, "rule_id": r.rule_id,
         "created_at": r.created_at} for r in rows
    ]


@router.post("/blocklist/{ip}", dependencies=[Depends(require_api_key)])
def block(ip: str, request: Request, db: Session = Depends(get_db)):
    created = responder.block_ip(db, ip, reason="manual", rule_id=None)
    db.commit()
    return {"ip": ip, "blocked": True, "newly_added": created}


@router.delete("/blocklist/{ip}", dependencies=[Depends(require_api_key)])
def unblock(ip: str, db: Session = Depends(get_db)):
    removed = responder.unblock_ip(db, ip)
    db.commit()
    return {"ip": ip, "blocked": False, "was_blocked": removed}
