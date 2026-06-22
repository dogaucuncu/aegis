"""Deterministic (canonical) JSON serialization.

Signing and encryption must operate on the same byte sequence; therefore keys are sorted
and no whitespace is used. The bytes produced by the signer (agent) and the verifier
(server) must be byte-for-byte identical.
"""
import json
from typing import Any


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode(
        "utf-8"
    )


def event_canonical(agent_id: str, event_type: str, timestamp: Any, data: Any) -> bytes:
    """Canonical byte representation of an event to be signed/verified.

    The agent and the server use THIS function to produce byte-for-byte identical bytes.
    `timestamp` must be an ISO-8601 string on both sides.
    """
    return canonical_bytes(
        {
            "agent_id": agent_id,
            "event_type": event_type,
            "timestamp": str(timestamp),
            "data": data,
        }
    )
