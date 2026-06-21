"""Aegis paylaşılan kriptografi katmanı.

- Ed25519 ile olay imzalama (kimlik doğrulama + bütünlük)
- AES-GCM ile taşıma şifreleme (gizlilik)
- Kanonik JSON serileştirme (imza/şifre için deterministik bytes)
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
