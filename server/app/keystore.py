"""Kayıtlı ajan anahtarları + sunucu X25519 çifti (ECDH).

Sunucuda:
  keys/server_x25519.key/.pub        -> sunucunun statik X25519 çifti (ilk çalışmada üretilir)
  keys/agents/<id>.pub               -> ajan Ed25519 açık anahtarı (imza doğrulama)
  keys/agents/<id>.x25519.pub        -> ajan X25519 açık anahtarı (ECDH)

AES anahtarı diskte tutulmaz; ECDH(sunucu_priv, ajan_pub) + HKDF ile türetilir.
Anahtarlar `scripts/provision_agent.py` ile üretilir.
"""
from typing import Optional

from aegis_crypto import derive_aes_key, keys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import BASE_DIR

SERVER_KEYS_DIR = BASE_DIR / "keys"
KEYS_DIR = SERVER_KEYS_DIR / "agents"


def server_x25519_private():
    """Sunucunun statik X25519 özel anahtarı; yoksa üretilir (priv+pub yazılır)."""
    priv_path = SERVER_KEYS_DIR / "server_x25519.key"
    if not priv_path.exists():
        SERVER_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        priv = keys.generate_x25519()
        keys.save_x25519_private(priv, priv_path)
        keys.save_x25519_public(priv, SERVER_KEYS_DIR / "server_x25519.pub")
        return priv
    return keys.load_x25519_private(priv_path)


def load_agent_pubkey(agent_id: str) -> Optional[Ed25519PublicKey]:
    path = KEYS_DIR / f"{agent_id}.pub"
    if not path.exists():
        return None
    return keys.load_public_key(path)


def derive_agent_aes(agent_id: str) -> Optional[bytes]:
    """Ajanın X25519 açık anahtarı + sunucu özel anahtarından AES anahtarı türetir."""
    pub_path = KEYS_DIR / f"{agent_id}.x25519.pub"
    if not pub_path.exists():
        return None
    agent_pub = keys.load_x25519_public(pub_path)
    return derive_aes_key(server_x25519_private(), agent_pub)
