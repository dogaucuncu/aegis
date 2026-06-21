"""Güvenli telemetri alımı: AES-GCM çözme + Ed25519 imza doğrulama + replay koruması.

Akış:
  1. Ajan ID'sine göre kayıtlı AES + açık anahtarı bul.
  2. Zarfı AES-GCM ile çöz (gizlilik + bütünlük).
  3. Zaman damgası tazeliği + nonce tekrar (replay) kontrolü.
  4. Her olayın Ed25519 imzasını doğrula (kimlik + bütünlük).
  5. Doğrulananları hash-zincirine yaz ve kuralları çalıştır.
"""
import binascii
import datetime as dt
import json

from aegis_crypto import aesgcm, canonical, signing
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import ingest_service, keystore, models, schemas
from ..database import get_db
from ..utils import now_utc

router = APIRouter(prefix="/api", tags=["secure"])

_FIELDS = ("agent_id", "event_type", "timestamp", "data")
FRESHNESS_SEC = 300  # ±5 dk tazelik penceresi


@router.post("/ingest/secure", response_model=schemas.IngestResult)
def ingest_secure(env: schemas.SecureEnvelope, db: Session = Depends(get_db)):
    aes_key = keystore.derive_agent_aes(env.agent_id)
    pub_key = keystore.load_agent_pubkey(env.agent_id)
    if aes_key is None or pub_key is None:
        raise HTTPException(status_code=401, detail=f"Ajan kayıtlı değil: {env.agent_id}")

    try:
        plaintext = aesgcm.decrypt(aes_key, env.nonce, env.ciphertext)
    except (InvalidTag, binascii.Error, ValueError):  # yanlış anahtar / etiket / bozuk b64
        raise HTTPException(status_code=400, detail="Çözme başarısız (anahtar/etiket uyuşmazlığı)")

    try:
        payload = json.loads(plaintext)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Geçersiz JSON içeriği")

    # --- Replay koruması: zaman damgası tazeliği + nonce tekrarı ---
    now = now_utc()
    ts_str = payload.get("ts")
    if not ts_str:
        raise HTTPException(status_code=400, detail="Eksik zaman damgası (ts)")
    try:
        ts = dt.datetime.fromisoformat(str(ts_str))
    except ValueError:
        raise HTTPException(status_code=400, detail="Geçersiz zaman damgası (ts)")
    if abs((now - ts).total_seconds()) > FRESHNESS_SEC:
        raise HTTPException(status_code=401, detail="Bayat zaman damgası (replay olabilir)")

    db.add(models.SeenNonce(agent_id=env.agent_id, nonce=env.nonce, created_at=now))
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Tekrar (replay) tespit edildi")

    # Eski nonce'ları temizle (TTL).
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
                detail=f"İmza doğrulanamadı (event_type={ev.get('event_type')})",
            )
        clean_events.append({k: ev.get(k) for k in _FIELDS})
        signatures.append(sig)

    ingested, alerts = ingest_service.persist_events(db, clean_events, signatures)
    return schemas.IngestResult(ingested=ingested, alerts_created=alerts)
