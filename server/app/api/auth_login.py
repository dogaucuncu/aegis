"""Hardened authentication endpoints (Milestone 1 — Cryptography).

POST /api/auth/register  — create a user (Argon2id hash, optional TOTP). State-changing, so it
                           requires an API key when auth is enabled.
POST /api/auth/login     — verify Argon2 password (+ optional TOTP), enforce account lockout,
                           and on success issue a JWT. Every attempt is fed into the SOC pipeline
                           as an `auth_attempt` event, so brute-force against the *real* login is
                           detected by the same rules as the lab login.
"""
import datetime as dt
from typing import Optional

from aegis_crypto import jwt_tokens, passwords
from aegis_crypto import totp as totp_mod
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import config, ingest_service, models
from ..auth import require_api_key
from ..database import get_db
from ..utils import now_utc

router = APIRouter(prefix="/api/auth", tags=["auth"])


class RegisterIn(BaseModel):
    username: str
    password: str
    enable_totp: bool = False


class LoginIn(BaseModel):
    username: str
    password: str
    totp: Optional[str] = None


def _emit_attempt(db: Session, username: str, success: bool, source_ip: str, locked: bool = False) -> None:
    """Record a login attempt as an event so the rule engine can detect brute-force."""
    ingest_service.persist_events(
        db,
        [{
            "agent_id": "auth-server",
            "event_type": "auth_attempt",
            "timestamp": None,
            "data": {
                "target": "/api/auth/login",
                "username": username,
                "success": success,
                "source_ip": source_ip,
                "locked": locked,
            },
        }],
    )


@router.post("/register", dependencies=[Depends(require_api_key)])
def register(body: RegisterIn, db: Session = Depends(get_db)):
    if db.get(models.User, body.username) is not None:
        raise HTTPException(status_code=409, detail="User already exists")
    secret = totp_mod.generate_secret() if body.enable_totp else None
    db.add(models.User(
        username=body.username,
        password_hash=passwords.hash_password(body.password),
        totp_secret=secret,
    ))
    db.commit()
    # The secret is returned once so it can be provisioned into an authenticator app.
    return {"username": body.username, "totp_secret": secret}


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    source_ip = request.client.host if request.client else "unknown"
    user = db.get(models.User, body.username)
    now = now_utc()

    # Locked account: reject without revealing whether the password was right.
    if user is not None and user.locked_until is not None and user.locked_until > now:
        _emit_attempt(db, body.username, False, source_ip, locked=True)
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account temporarily locked")

    ok = user is not None and passwords.verify_password(user.password_hash, body.password)
    # Second factor: if the user enrolled TOTP, a valid code is also required.
    if ok and user.totp_secret:
        ok = totp_mod.verify_totp(user.totp_secret, body.totp or "")

    if not ok:
        if user is not None:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= config.AUTH_MAX_FAILS:
                user.locked_until = now + dt.timedelta(seconds=config.AUTH_LOCK_SECONDS)
        _emit_attempt(db, body.username, False, source_ip)  # commits the failure counter too
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Success: reset lockout state and issue a token.
    user.failed_attempts = 0
    user.locked_until = None
    token = jwt_tokens.issue_hs256(user.username, config.JWT_SECRET)
    _emit_attempt(db, body.username, True, source_ip)
    return {"access_token": token, "token_type": "bearer"}
