"""Pydantic schemas (request/response contracts)."""
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class EventIn(BaseModel):
    agent_id: str
    event_type: str
    timestamp: Optional[datetime] = None
    data: Dict[str, Any] = {}


class EventBatch(BaseModel):
    events: List[EventIn]


class EventOut(BaseModel):
    id: int
    agent_id: str
    event_type: str
    timestamp: datetime
    data: Dict[str, Any]
    prev_hash: Optional[str] = None
    hash: Optional[str] = None
    signed: bool = False

    model_config = ConfigDict(from_attributes=True)


class AlertOut(BaseModel):
    id: int
    created_at: datetime
    rule_id: str
    severity: str
    title: str
    description: str
    agent_id: Optional[str] = None
    event_id: Optional[int] = None
    status: str
    count: int = 1
    last_seen: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class IngestResult(BaseModel):
    ingested: int
    alerts_created: int


class IntegrityResult(BaseModel):
    total_events: int
    valid: bool
    broken_at_event_id: Optional[int] = None
    message: str


class SecureEnvelope(BaseModel):
    """Secure ingestion envelope: an AES-GCM encrypted batch of events.

    Decrypted content: {"events": [{agent_id, event_type, timestamp, data, signature}, ...]}
    The signatures are inside the encrypted content (confidential in transit too).
    """

    agent_id: str
    nonce: str
    ciphertext: str


class SignatureAudit(BaseModel):
    total_signed: int
    valid: int
    invalid: int
    invalid_event_ids: List[int]
    message: str
