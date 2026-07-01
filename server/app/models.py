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


class Agent(Base):
    """Endpoint agent inventory + heartbeat.

    Upserted on every ingest (plain + secure share ingest_service), so the dashboard can show
    which agents are online and when they were last seen.
    """

    __tablename__ = "agents"

    agent_id = Column(String(128), primary_key=True)
    first_seen = Column(DateTime, default=now_utc)
    last_seen = Column(DateTime, default=now_utc, index=True)
    version = Column(String(32), nullable=True)
    event_count = Column(Integer, default=0, nullable=False)


class User(Base):
    """A dashboard/API user account for the hardened login flow.

    Passwords are stored as Argon2id hashes (never plaintext). `failed_attempts` + `locked_until`
    implement account lockout; an optional `totp_secret` enables RFC-6238 second factor.
    """

    __tablename__ = "users"

    username = Column(String(128), primary_key=True)
    password_hash = Column(String(256), nullable=False)
    totp_secret = Column(String(64), nullable=True)
    failed_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=now_utc)


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

    # Triage workflow (set by analysts via /api/alerts/{id}/triage).
    assignee = Column(String(128), nullable=True)
    note = Column(Text, nullable=True)
    tags = Column(String(256), nullable=True)  # comma-separated

    # MITRE ATT&CK mapping carried from the matching rule.
    tactic = Column(String(64), nullable=True)
    technique = Column(String(32), nullable=True)


class AttestationBaseline(Base):
    """Enrolled 'known-good' measured-boot state for an endpoint (Milestone 7 — TPM 2.0).

    Set once from a trusted golden image; later attestation Quotes are compared against it. Drift
    means the boot chain changed (firmware / bootloader / kernel / Secure-Boot policy) — the
    fingerprint of a bootkit or an evil-maid tamper.
    """

    __tablename__ = "attestation_baselines"

    agent_id = Column(String(128), primary_key=True)
    ak_pubkey = Column(Text, nullable=False)  # Attestation Key public key (Ed25519, PEM)
    pcrs = Column(JSON, nullable=False)  # golden baseline {index: hex}
    selection = Column(JSON, nullable=False)  # quoted PCR indices
    created_at = Column(DateTime, default=now_utc)


class AttestationChallenge(Base):
    """A single-use attestation nonce issued to an agent (anti-replay for Quotes).

    One active challenge per agent (upserted on each `/api/attest/challenge`); consumed — deleted —
    when the matching Quote is submitted, so a captured Quote cannot be replayed.
    """

    __tablename__ = "attestation_challenges"

    agent_id = Column(String(128), primary_key=True)
    nonce = Column(String(64), nullable=False)
    created_at = Column(DateTime, default=now_utc)


class BlockedIP(Base):
    """An IP blocked by the auto-response engine (or manually). BlocklistMiddleware rejects it.

    Persisted so blocks survive restarts; the responder also keeps an in-memory mirror so the
    middleware does not hit the DB on every request.
    """

    __tablename__ = "blocked_ips"

    ip = Column(String(64), primary_key=True)
    reason = Column(String(128), nullable=True)
    rule_id = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=now_utc, index=True)
