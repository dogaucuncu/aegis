"""Aegis shared cryptography layer.

- Event signing with Ed25519 (authentication + integrity)
- Transport encryption with AES-GCM (confidentiality)
- Canonical JSON serialization (deterministic bytes for signing/encryption)
"""
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
]
