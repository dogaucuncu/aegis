"""Authenticated encryption with AES-256-GCM (AEAD)."""
import base64
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[str, str]:
    """Returns (nonce_b64, ciphertext_b64). The ciphertext includes the GCM tag."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce).decode("ascii"), base64.b64encode(ct).decode("ascii")


def decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: Optional[bytes] = None) -> bytes:
    """Decrypts; raises cryptography's InvalidTag if the key/tag does not match."""
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    return AESGCM(key).decrypt(nonce, ct, aad)
