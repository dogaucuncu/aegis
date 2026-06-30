"""Registered agent keys + server X25519 pair (ECDH).

On the server:
  keys/server_x25519.key/.pub        -> the server's static X25519 pair (generated on first run)
  keys/agents/<id>.pub               -> agent Ed25519 public key (signature verification)
  keys/agents/<id>.x25519.pub        -> agent X25519 public key (ECDH)

The AES key is not stored on disk; it is derived via ECDH(server_priv, agent_pub) + HKDF.
The keys are generated with `scripts/provision_agent.py`.
"""
import re
from typing import Optional

from aegis_crypto import derive_aes_key, keys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import BASE_DIR

SERVER_KEYS_DIR = BASE_DIR / "keys"
KEYS_DIR = SERVER_KEYS_DIR / "agents"

# agent_id arrives from the (attacker-controllable) request body and is used to build
# filesystem paths, so it must be a strict slug — otherwise "../../x" would escape KEYS_DIR.
_VALID_AGENT_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _safe_agent_id(agent_id: str) -> bool:
    return bool(_VALID_AGENT_ID.fullmatch(agent_id))


def server_x25519_private():
    """The server's static X25519 private key; generated if absent (priv+pub written)."""
    priv_path = SERVER_KEYS_DIR / "server_x25519.key"
    if not priv_path.exists():
        SERVER_KEYS_DIR.mkdir(parents=True, exist_ok=True)
        priv = keys.generate_x25519()
        keys.save_x25519_private(priv, priv_path)
        keys.save_x25519_public(priv, SERVER_KEYS_DIR / "server_x25519.pub")
        return priv
    return keys.load_x25519_private(priv_path)


def load_agent_pubkey(agent_id: str) -> Optional[Ed25519PublicKey]:
    if not _safe_agent_id(agent_id):
        return None
    path = KEYS_DIR / f"{agent_id}.pub"
    if not path.exists():
        return None
    return keys.load_public_key(path)


def derive_agent_aes(agent_id: str) -> Optional[bytes]:
    """Derives the AES key from the agent's X25519 public key + the server's private key."""
    if not _safe_agent_id(agent_id):
        return None
    pub_path = KEYS_DIR / f"{agent_id}.x25519.pub"
    if not pub_path.exists():
        return None
    agent_pub = keys.load_x25519_public(pub_path)
    return derive_aes_key(server_x25519_private(), agent_pub)
