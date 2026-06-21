"""Kurcalanmaya-dayanıklı log için hash-zinciri yardımcıları.

Her olayın hash'i, kendi içeriği + bir önceki olayın hash'i üzerinden hesaplanır.
Geçmişe dönük herhangi bir değişiklik zinciri kırar. (Faz 2'de Ed25519 imza eklenecek.)
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
