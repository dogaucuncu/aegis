"""X25519 ECDH + HKDF ile paylaşılan AES anahtarı türetme.

Ajan ve sunucu statik X25519 çiftleri tutar. Paylaşılan sır simetriktir:
  derive_aes_key(agent_priv, server_pub) == derive_aes_key(server_priv, agent_pub)
Böylece AES anahtarı diskte düz metin tutulmaz; iki tarafça türetilir.
"""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_INFO = b"aegis-aes-256-gcm-v1"


def derive_aes_key(my_priv: X25519PrivateKey, peer_pub: X25519PublicKey) -> bytes:
    shared = my_priv.exchange(peer_pub)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(shared)
