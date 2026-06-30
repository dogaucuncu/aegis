"""Canary token endpoint (Milestone 6) — a deception tripwire.

A canary token is a URL that has no legitimate use. Any request to it is, by definition,
reconnaissance or an intruder poking around, so it raises a high-severity `canary_triggered`
alert. The response is a believable decoy so the attacker does not realize they tripped a wire.
"""
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from .. import ingest_service
from ..database import get_db

router = APIRouter(prefix="/api", tags=["canary"])


@router.api_route("/canary/{token}", methods=["GET", "POST"])
def canary(token: str, request: Request, db: Session = Depends(get_db)):
    source_ip = request.client.host if request.client else "unknown"
    ingest_service.persist_events(db, [{
        "agent_id": "canary",
        "event_type": "canary_triggered",
        "timestamp": None,
        "data": {
            "token": token, "kind": "web", "source_ip": source_ip,
            "path": str(request.url.path), "user_agent": request.headers.get("user-agent", ""),
        },
    }])
    # Decoy response — looks like an ordinary (boring) resource.
    return {"status": "ok", "data": []}
