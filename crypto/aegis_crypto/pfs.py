"""Perfect Forward Secrecy via ephemeral-static X25519 (Milestone 4).

The sender generates a fresh ephemeral X25519 keypair for every message and derives the AES
key from ECDH(ephemeral_priv, recipient_static_pub). The recipient derives the same key from
ECDH(recipient_static_priv, ephemeral_pub). Because the ephemeral private key is discarded
right after sending, a later compromise of the long-term keys cannot decrypt captured traffic
(forward secrecy). The ephemeral public key travels in the envelope (`epk`, base64 raw bytes).
"""
import base64
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .kex import derive_aes_key


def _pub_to_b64(pub: X25519PublicKey) -> str:
    return base64.b64encode(pub.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode("ascii")


def _pub_from_b64(epk_b64: str) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(base64.b64decode(epk_b64))


def sender_session_key(recipient_static_pub: X25519PublicKey) -> Tuple[bytes, str]:
    """One message: returns (aes_key, ephemeral_pub_b64). The ephemeral private key is dropped."""
    ephemeral = X25519PrivateKey.generate()
    aes = derive_aes_key(ephemeral, recipient_static_pub)
    return aes, _pub_to_b64(ephemeral.public_key())


def recipient_session_key(recipient_static_priv: X25519PrivateKey, ephemeral_pub_b64: str) -> bytes:
    """Recipient side: derive the same AES key from its static private + the sender's ephemeral pub."""
    return derive_aes_key(recipient_static_priv, _pub_from_b64(ephemeral_pub_b64))
