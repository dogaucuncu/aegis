"""Database models: Event (raw telemetry) and Alert (rule matches)."""
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.types import JSON

from .database import Base
from .utils import now_utc


class Event(Base):
    """A single telemetry event from the agents.

    The `prev_hash` + `hash` fields form a tamper-evident hash chain.
    An Ed25519 signature is added to this in Phase 2.
    """

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(128), index=True, nullable=False)
    event_type = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime, default=now_utc, index=True)
    data = Column(JSON, nullable=False, default=dict)

    prev_hash = Column(String(64), nullable=True)
    hash = Column(String(64), nullable=True, index=True)

    # Phase 2: the agent's Ed25519 signature (base64). Populated in secure mode, NULL in plain mode.
    signature = Column(String(128), nullable=True)

    @property
    def signed(self) -> bool:
        """Did the event arrive over the secure (signed) channel?"""
        return self.signature is not None


class ChainHead(Base):
    """Hash chain head (single row, id=1).

    The lock point to prevent the chain from forking on concurrent appends:
    on PostgreSQL the row is locked with `SELECT ... FOR UPDATE` (multi-process/distributed);
    on SQLite an in-process threading lock is sufficient.
    """

    __tablename__ = "chain_head"

    id = Column(Integer, primary_key=True)
    last_hash = Column(String(64), nullable=True)


class SeenNonce(Base):
    """Replay protection: processed secure-envelope nonces (with TTL).

    Resending an envelope with the same AES-GCM nonce (replay) is rejected.
    """

    __tablename__ = "seen_nonces"

    id = Column(Integer, primary_key=True)
    agent_id = Column(String(128), index=True, nullable=False)
    nonce = Column(String(64), unique=True, nullable=False)
    created_at = Column(DateTime, default=now_utc, index=True)


class Alert(Base):
    """An alert produced by the rule engine from an event."""

    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=now_utc, index=True)
    rule_id = Column(String(64), index=True, nullable=False)
    severity = Column(String(16), index=True, default="medium")
    title = Column(String(256), nullable=False)
    description = Column(Text, default="")
    agent_id = Column(String(128), index=True)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=True)
    status = Column(String(16), default="open", index=True)

    # Correlation/dedup: an OPEN alert with the same dedup_key is not re-created; count is incremented.
    dedup_key = Column(String(160), index=True)
    count = Column(Integer, default=1, nullable=False)
    last_seen = Column(DateTime, default=now_utc, index=True)
