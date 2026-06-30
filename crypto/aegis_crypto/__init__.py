"""Aegis shared cryptography layer.

- Event signing with Ed25519 (authentication + integrity)
- Transport encryption with AES-GCM (confidentiality)
- Canonical JSON serialization (deterministic bytes for signing/encryption)
- Password hashing (Argon2id), TOTP (MFA) and JWT (HS256/EdDSA) for the login flow
"""
from . import jwt_tokens, keys, passwords, pfs, tlspin, totp, weak_crypto
from .aesgcm import decrypt, encrypt
from .canonical import canonical_bytes, event_canonical
from .kex import derive_aes_key
from .signing import sign, verify

__all__ = [
    "sign",
    "verify",
    "encrypt",
    "decrypt",
    "canonical_bytes",
    "event_canonical",
    "derive_aes_key",
    "keys",
    "passwords",
    "totp",
    "jwt_tokens",
    "pfs",
    "weak_crypto",
    "tlspin",
]
