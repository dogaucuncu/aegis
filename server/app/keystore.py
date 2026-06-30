"""Registered agent keys + server X25519 pair (ECDH).

On the server:
  keys/server_x25519.key/.pub        -> the server's static X25519 pair (generated on first run)
  keys/agents/<id>.pub               -> agent Ed25519 public key (signature verification)
  keys/agents/<id>.x25519.pub        -> agent X25519 public key (ECDH)

The AES key is not stored on disk; it is derived via ECDH(server_priv, agent_pub) + HKDF.
The keys are generated with `scripts/provision_agent.py`.
"""
import os
import re
from pathlib import Path
from typing import Optional

from aegis_crypto import derive_aes_key, keys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .config import BASE_DIR

SERVER_KEYS_DIR = BASE_DIR / "keys"
KEYS_DIR = SERVER_KEYS_DIR / "agents"

# agent_id arrives from the (attacker-controllable) request body and is used to build
# filesystem paths, so it must be a strict slug — otherwise "../../x" would escape KEYS_DIR.
_VALID_AGENT_ID = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _agent_key_path(agent_id: str, suffix: str) -> Optional[Path]:
    """Resolve KEYS_DIR/<agent_id><suffix>, refusing anything that escapes KEYS_DIR.

    Two barriers: an allowlist on the id, plus a normalized-path containment check (realpath +
    startswith) — the latter is the canonical form CodeQL recognizes as a path-traversal barrier.
    """
    if not _VALID_AGENT_ID.fullmatch(agent_id):
        return None
    base = os.path.realpath(KEYS_DIR)
    target = os.path.realpath(os.path.join(base, f"{agent_id}{suffix}"))
    if target != base and not target.startswith(base + os.sep):
        return None
    return Path(target)


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
    path = _agent_key_path(agent_id, ".pub")
    if path is None or not path.exists():
        return None
    return keys.load_public_key(path)


def derive_agent_aes(agent_id: str) -> Optional[bytes]:
    """Derives the AES key from the agent's X25519 public key + the server's private key."""
    pub_path = _agent_key_path(agent_id, ".x25519.pub")
    if pub_path is None or not pub_path.exists():
        return None
    agent_pub = keys.load_x25519_public(pub_path)
    return derive_aes_key(server_x25519_private(), agent_pub)
