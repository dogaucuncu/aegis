"""Hash-chain helpers for a tamper-evident log.

Each event's hash is computed over its own content + the previous event's hash.
Any retroactive change breaks the chain. (An Ed25519 signature is added in Phase 2.)
"""
import datetime as dt
import hashlib
import json
from typing import Any, Dict, Optional


def compute_hash(
    prev_hash: Optional[str],
    agent_id: str,
    event_type: str,
    timestamp: dt.datetime,
    data: Dict[str, Any],
) -> str:
    payload = json.dumps(
        {
            "prev": prev_hash or "",
            "agent_id": agent_id,
            "event_type": event_type,
            "timestamp": timestamp.isoformat(),
            "data": data,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
