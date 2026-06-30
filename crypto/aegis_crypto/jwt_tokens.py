"""JSON Web Tokens — issue/verify with HS256 (shared secret) or EdDSA (Ed25519).

The EdDSA path reuses the project's existing Ed25519 keys, so the same key material that
signs telemetry can mint asymmetric tokens. `decode_unsafe` exists ONLY to demonstrate the
classic alg-confusion / `alg=none` attacks in the lab — never use it to trust a token.
"""
import base64
import datetime as dt
import json
from typing import Any, Dict, Optional

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DEFAULT_TTL = 3600  # seconds


class JWTError(Exception):
    """Raised when a token fails verification (signature, expiry, or malformed)."""


def _payload(subject: str, ttl: int, extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    now = dt.datetime.now(dt.timezone.utc)
    payload = {
        "sub": subject,
        "iat": int(now.timestamp()),
        "exp": int((now + dt.timedelta(seconds=ttl)).timestamp()),
    }
    if extra:
        payload.update(extra)
    return payload


# ---------------- HS256 (symmetric) ----------------
def issue_hs256(subject: str, secret: str, ttl: int = DEFAULT_TTL, **extra: Any) -> str:
    return jwt.encode(_payload(subject, ttl, extra), secret, algorithm="HS256")


def verify_hs256(token: str, secret: str) -> Dict[str, Any]:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"])
    except jwt.PyJWTError as exc:
        raise JWTError(str(exc)) from exc


# ---------------- EdDSA (asymmetric, Ed25519) ----------------
def issue_eddsa(
    subject: str, private_key: Ed25519PrivateKey, ttl: int = DEFAULT_TTL, **extra: Any
) -> str:
    return jwt.encode(_payload(subject, ttl, extra), private_key, algorithm="EdDSA")


def verify_eddsa(token: str, public_key: Ed25519PublicKey) -> Dict[str, Any]:
    try:
        return jwt.decode(token, public_key, algorithms=["EdDSA"])
    except jwt.PyJWTError as exc:
        raise JWTError(str(exc)) from exc


def decode_unsafe(token: str) -> Dict[str, Any]:
    """Decode WITHOUT verifying the signature — for attack demos/inspection only."""
    return jwt.decode(token, options={"verify_signature": False})


def _b64url(obj: Dict[str, Any]) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def forge_alg_none(claims: Dict[str, Any]) -> str:
    """Craft an UNSIGNED `alg=none` token (ATTACK DEMO).

    A correct verifier must reject `alg=none`; a broken one that skips signature verification
    will trust these claims, enabling privilege escalation. Used by the lab/scanner to prove
    the vulnerability and to contrast it with the hardened verifier.
    """
    return _b64url({"alg": "none", "typ": "JWT"}) + "." + _b64url(claims) + "."
