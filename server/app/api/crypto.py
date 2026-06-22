"""Crypto audit endpoints: re-verification of stored signatures."""
from aegis_crypto import canonical, signing
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import keystore, models, schemas
from ..database import get_db

router = APIRouter(prefix="/api/crypto", tags=["crypto"])


@router.get("/verify-signatures", response_model=schemas.SignatureAudit)
def verify_signatures(db: Session = Depends(get_db)):
    signed = (
        db.query(models.Event).filter(models.Event.signature.isnot(None)).all()
    )
    pubkey_cache = {}
    valid = 0
    invalid_ids = []

    for ev in signed:
        if ev.agent_id not in pubkey_cache:
            pubkey_cache[ev.agent_id] = keystore.load_agent_pubkey(ev.agent_id)
        pub = pubkey_cache[ev.agent_id]

        cbytes = canonical.event_canonical(
            ev.agent_id, ev.event_type, ev.timestamp.isoformat(), ev.data
        )
        if pub is not None and signing.verify(pub, cbytes, ev.signature):
            valid += 1
        else:
            invalid_ids.append(ev.id)

    total = len(signed)
    ok = len(invalid_ids) == 0
    return schemas.SignatureAudit(
        total_signed=total,
        valid=valid,
        invalid=len(invalid_ids),
        invalid_event_ids=invalid_ids,
        message=(
            "All signatures are valid." if ok else f"{len(invalid_ids)} event(s) have an invalid signature!"
        ),
    )
