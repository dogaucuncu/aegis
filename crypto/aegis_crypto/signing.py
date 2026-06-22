"""Ed25519 signing / verification."""
import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Signs the data and returns a base64 signature."""
    return base64.b64encode(private_key.sign(data)).decode("ascii")


def verify(public_key: Ed25519PublicKey, data: bytes, signature_b64: str) -> bool:
    """True if the signature is valid, otherwise (or if corrupt) False."""
    try:
        public_key.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, binascii.Error, ValueError):
        return False
