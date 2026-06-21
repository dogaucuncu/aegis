"""AES-256-GCM ile kimlik-doğrulamalı şifreleme (AEAD)."""
import base64
import os
from typing import Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> Tuple[str, str]:
    """(nonce_b64, ciphertext_b64) döndürür. ciphertext GCM etiketini içerir."""
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return base64.b64encode(nonce).decode("ascii"), base64.b64encode(ct).decode("ascii")


def decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, aad: Optional[bytes] = None) -> bytes:
    """Çözer; anahtar/etiket uyuşmazsa cryptography InvalidTag fırlatır."""
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ciphertext_b64)
    return AESGCM(key).decrypt(nonce, ct, aad)
