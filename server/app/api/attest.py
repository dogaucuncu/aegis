"""TPM 2.0 remote attestation (Milestone 7) — a hardware root-of-trust for endpoints.

The blue-team question this answers: *has this endpoint's boot chain been tampered with?*
Measured boot records each stage (firmware -> bootloader -> Secure-Boot policy -> kernel) into
TPM PCRs; a signed Quote proves the current PCR state to the SOC.

Flow:
  1. POST /api/attest/enroll     (trusted, API-key) — record the endpoint's Attestation Key (AK)
     public key and its golden measured-boot PCR baseline.
  2. POST /api/attest/challenge  — the server issues a fresh single-use nonce.
  3. POST /api/attest/quote      — the agent returns a Quote (PCRs + an AK signature over the
     nonce). The server verifies the signature + nonce, compares the PCRs to the baseline, and
     reports the outcome to the SOC as a `tpm_attestation` event — which drives the drift / fail
     alerts (see detection_rules/default.yml).

`quote` is cryptographically verified, so it is reachable without an API key (like the canary
tripwire). `enroll` defines the trust baseline, so it always requires the API key.
"""
import datetime as dt
import secrets
from typing import List, Optional

from aegis_crypto import tpm
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import ingest_service, models
from ..auth import require_api_key, require_read_auth
from ..database import get_db
from ..utils import now_utc

router = APIRouter(prefix="/api/attest", tags=["attestation"])

CHALLENGE_TTL_SEC = 300  # a Quote must answer a challenge no older than 5 minutes


class EnrollIn(BaseModel):
    agent_id: str
    ak_pubkey: str  # Ed25519 public key (PEM)
    pcrs: dict  # golden baseline {index: hex}
    selection: Optional[List[int]] = None


class ChallengeIn(BaseModel):
    agent_id: str


class QuoteIn(BaseModel):
    agent_id: str
    quote: dict


@router.post("/enroll", dependencies=[Depends(require_api_key)])
def enroll(body: EnrollIn, db: Session = Depends(get_db)):
    """Record (or refresh) an endpoint's AK public key + golden PCR baseline."""
    try:
        load_pem_public_key(body.ak_pubkey.encode())
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid AK public key (PEM)")
    if not body.pcrs:
        raise HTTPException(status_code=400, detail="Empty PCR baseline")

    pcrs = {str(k): str(v).lower() for k, v in body.pcrs.items()}
    selection = sorted(body.selection) if body.selection else sorted(int(i) for i in pcrs)

    row = db.get(models.AttestationBaseline, body.agent_id)
    if row is None:
        row = models.AttestationBaseline(agent_id=body.agent_id)
        db.add(row)
    row.ak_pubkey = body.ak_pubkey
    row.pcrs = pcrs
    row.selection = selection
    row.created_at = now_utc()
    db.commit()
    return {"status": "enrolled", "agent_id": body.agent_id, "pcrs": len(pcrs)}


@router.get("/status", dependencies=[Depends(require_read_auth)])
def status(db: Session = Depends(get_db)):
    """Per-endpoint integrity view: each enrolled endpoint + its latest attestation verdict.

    Powers the dashboard's Endpoint Integrity panel. Worst-first ordering (fail/drift before pass)
    so problems surface at the top.
    """
    order = {"attestation_fail": 0, "pcr_drift": 1, None: 2, "pass": 3}
    out = []
    for b in db.query(models.AttestationBaseline).all():
        ev = (
            db.query(models.Event)
            .filter(
                models.Event.agent_id == b.agent_id,
                models.Event.event_type == "tpm_attestation",
            )
            .order_by(models.Event.id.desc())
            .first()
        )
        data = (ev.data if ev else None) or {}
        out.append({
            "agent_id": b.agent_id,
            "enrolled_at": b.created_at,
            "pcr_count": len(b.pcrs or {}),
            "selection": b.selection,
            "last_result": data.get("result"),
            "last_reason": data.get("reason", ""),
            "drifted_pcrs": data.get("drifted_pcrs", []),
            "source_ip": data.get("source_ip"),
            "last_seen": ev.timestamp if ev else None,
        })
    out.sort(key=lambda r: (order.get(r["last_result"], 2), r["agent_id"]))
    return out


@router.post("/challenge")
def challenge(body: ChallengeIn, db: Session = Depends(get_db)):
    """Issue a fresh single-use nonce for the agent to sign into its next Quote."""
    if db.get(models.AttestationBaseline, body.agent_id) is None:
        raise HTTPException(status_code=404, detail=f"Agent not enrolled: {body.agent_id}")
    nonce = secrets.token_hex(16)
    row = db.get(models.AttestationChallenge, body.agent_id)
    if row is None:
        row = models.AttestationChallenge(agent_id=body.agent_id)
        db.add(row)
    row.nonce = nonce
    row.created_at = now_utc()
    db.commit()
    return {"agent_id": body.agent_id, "nonce": nonce, "ttl": CHALLENGE_TTL_SEC}


@router.post("/quote")
def quote(body: QuoteIn, request: Request, db: Session = Depends(get_db)):
    """Verify a Quote and report the attestation result to the SOC as an event."""
    baseline = db.get(models.AttestationBaseline, body.agent_id)
    if baseline is None:
        raise HTTPException(status_code=404, detail=f"Agent not enrolled: {body.agent_id}")
    source_ip = request.client.host if request.client else "unknown"

    # The challenge must exist and be fresh; consume it (single use) whatever the outcome, so a
    # captured Quote cannot be replayed against a later challenge.
    ch = db.get(models.AttestationChallenge, body.agent_id)
    expected_nonce = ch.nonce if ch else None
    fresh = ch is not None and (now_utc() - ch.created_at) <= dt.timedelta(
        seconds=CHALLENGE_TTL_SEC
    )
    if ch is not None:
        db.delete(ch)
        db.commit()

    result, reason, drifted = "pass", "", []
    if not fresh or expected_nonce is None:
        result, reason = "attestation_fail", "no_challenge_or_stale"
    else:
        ak_pub = load_pem_public_key(baseline.ak_pubkey.encode())
        ok, why = tpm.verify_quote(ak_pub, body.quote, expected_nonce)
        if not ok:
            result, reason = "attestation_fail", why
        else:
            drifted = tpm.diff_baseline(body.quote.get("pcrs", {}), baseline.pcrs)
            if drifted:
                result = "pcr_drift"

    data = {
        "result": result,
        "reason": reason,
        "drifted_pcrs": drifted,
        "source_ip": source_ip,
        "pcr_selection": baseline.selection,
    }
    if result == "pcr_drift":
        got = {str(k): str(v).lower() for k, v in body.quote.get("pcrs", {}).items()}
        data["expected"] = {str(i): baseline.pcrs.get(str(i), "")[:16] for i in drifted}
        data["got"] = {str(i): got.get(str(i), "")[:16] for i in drifted}

    ingest_service.persist_events(
        db,
        [{
            "agent_id": body.agent_id,
            "event_type": "tpm_attestation",
            "timestamp": None,
            "data": data,
        }],
    )
    return {
        "verified": result == "pass",
        "result": result,
        "reason": reason,
        "drifted_pcrs": drifted,
    }
