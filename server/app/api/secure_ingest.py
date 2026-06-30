"""Secure telemetry ingestion: AES-GCM decryption + Ed25519 signature verification + replay protection.

Flow:
  1. Look up the registered AES + public key by agent ID.
  2. Decrypt the envelope with AES-GCM (confidentiality + integrity).
  3. Check timestamp freshness + nonce replay.
  4. Verify each event's Ed25519 signature (identity + integrity).
  5. Write the verified events to the hash chain and run the rules.
"""
import binascii
import datetime as dt
import json

from aegis_crypto import aesgcm, canonical, pfs, signing
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import ingest_service, keystore, models, schemas
from ..database import get_db
from ..utils import now_utc

router = APIRouter(prefix="/api", tags=["secure"])

_FIELDS = ("agent_id", "event_type", "timestamp", "data")
FRESHNESS_SEC = 300  # ±5 min freshness window


@router.post("/ingest/secure", response_model=schemas.IngestResult)
def ingest_secure(env: schemas.SecureEnvelope, db: Session = Depends(get_db)):
    # Identity is always proven by the agent's registered Ed25519 key.
    pub_key = keystore.load_agent_pubkey(env.agent_id)
    if pub_key is None:
        raise HTTPException(status_code=401, detail=f"Agent not registered: {env.agent_id}")

    # AES key derivation depends on the envelope version:
    #   v2 -> ephemeral-static ECDH (PFS): server static private + the agent's per-message epk.
    #   v1 -> static-static ECDH: the long-lived agent+server X25519 keys.
    if env.version >= 2 and env.epk:
        try:
            aes_key = pfs.recipient_session_key(keystore.server_x25519_private(), env.epk)
        except (ValueError, binascii.Error):
            raise HTTPException(status_code=400, detail="Invalid ephemeral public key (epk)")
    else:
        aes_key = keystore.derive_agent_aes(env.agent_id)
    if aes_key is None:
        raise HTTPException(status_code=401, detail=f"Agent not registered: {env.agent_id}")

    try:
        plaintext = aesgcm.decrypt(aes_key, env.nonce, env.ciphertext)
    except (InvalidTag, binascii.Error, ValueError):  # wrong key / tag / corrupt b64
        raise HTTPException(status_code=400, detail="Decryption failed (key/tag mismatch)")

    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON content")

    # --- Replay protection: timestamp freshness + nonce replay ---
    now = now_utc()
    ts_str = payload.get("ts")
    if not ts_str:
        raise HTTPException(status_code=400, detail="Missing timestamp (ts)")
    try:
        ts = dt.datetime.fromisoformat(str(ts_str))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid timestamp (ts)")
    if abs((now - ts).total_seconds()) > FRESHNESS_SEC:
        raise HTTPException(status_code=401, detail="Stale timestamp (possible replay)")

    db.add(models.SeenNonce(agent_id=env.agent_id, nonce=env.nonce, created_at=now))
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Replay detected")

    # Clean up old nonces (TTL).
    db.query(models.SeenNonce).filter(
        models.SeenNonce.created_at < now - dt.timedelta(seconds=FRESHNESS_SEC)
    ).delete()

    raw_events = payload.get("events", [])

    clean_events = []
    signatures = []
    for ev in raw_events:
        sig = ev.get("signature")
        cbytes = canonical.event_canonical(
            ev.get("agent_id"), ev.get("event_type"), ev.get("timestamp"), ev.get("data")
        )
        if not sig or not signing.verify(pub_key, cbytes, sig):
            raise HTTPException(
                status_code=401,
                detail=f"Signature could not be verified (event_type={ev.get('event_type')})",
            )
        clean_events.append({k: ev.get(k) for k in _FIELDS})
        signatures.append(sig)

    ingested, alerts = ingest_service.persist_events(db, clean_events, signatures)
    return schemas.IngestResult(ingested=ingested, alerts_created=alerts)
