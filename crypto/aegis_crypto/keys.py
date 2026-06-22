"""Key generation, saving and loading.

- Ed25519 signing key pair (PEM)
- AES-256 symmetric key (base64)

Note (Phase 2, dev-grade): the AES key is assumed to be pre-shared between agent and
server. In production, deriving a per-session key via ECDH is recommended.
"""
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)


def generate_ed25519() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def save_private_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    Path(path).write_bytes(pem)


def save_public_key(key: Ed25519PrivateKey, path: str | Path) -> None:
    pub = key.public_key()
    pem = pub.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(path).write_bytes(pem)


def load_private_key(path: str | Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public_key(path: str | Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(Path(path).read_bytes())


# --- X25519 (ECDH key exchange) ---
def generate_x25519() -> X25519PrivateKey:
    return X25519PrivateKey.generate()


def save_x25519_private(key: X25519PrivateKey, path: str | Path) -> None:
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    Path(path).write_bytes(pem)


def save_x25519_public(key: X25519PrivateKey, path: str | Path) -> None:
    pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    Path(path).write_bytes(pem)


def load_x25519_private(path: str | Path) -> X25519PrivateKey:
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_x25519_public(path: str | Path) -> X25519PublicKey:
    return serialization.load_pem_public_key(Path(path).read_bytes())


def generate_aes_key() -> bytes:
    return os.urandom(32)  # AES-256 (now only for tests/tools)


def save_aes_key(key: bytes, path: str | Path) -> None:
    Path(path).write_text(base64.b64encode(key).decode(), encoding="utf-8")


def load_aes_key(path: str | Path) -> bytes:
    return base64.b64decode(Path(path).read_text(encoding="utf-8"))
