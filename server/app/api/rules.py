"""Detection-rule management (Milestone 6, threat-hunting).

POST /api/rules/reload  — hot-reload the YAML rules from disk without a server restart, so an
                          analyst can tune detections live. State-changing -> requires an API key.
"""
from fastapi import APIRouter, Depends

from .. import rules as rules_engine
from ..auth import require_api_key

router = APIRouter(prefix="/api", tags=["rules"])


@router.post("/rules/reload", dependencies=[Depends(require_api_key)])
def reload_rules():
    count = rules_engine.reload_rules()
    return {"reloaded": True, "rules": count}
