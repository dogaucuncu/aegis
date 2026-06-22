"""Generates keys for an agent and 'registers' them with the server (Phase 2 / WP6 ECDH).

Generates:
  agent/secrets/<id>.key              Ed25519 private (signing, stays on the agent)
  agent/secrets/<id>.x25519.key       X25519 private (ECDH, stays on the agent)
  agent/secrets/server_x25519.pub     the server's X25519 public key (agent copy)
  server/keys/agents/<id>.pub         Ed25519 public (the server verifies)
  server/keys/agents/<id>.x25519.pub  X25519 public (for the server's ECDH)
  server/keys/server_x25519.key/.pub  server X25519 pair (generated if absent)

The AES key is not stored on disk; it is derived by both sides via ECDH+HKDF.

Usage:
    python scripts/provision_agent.py --agent-id agent-local
"""
import argparse
from pathlib import Path

from aegis_crypto import keys

ROOT = Path(__file__).resolve().parent.parent
AGENT_SECRETS = ROOT / "agent" / "secrets"
SERVER_KEYS = ROOT / "server" / "keys"
SERVER_AGENTS = SERVER_KEYS / "agents"


def ensure_server_x25519() -> Path:
    priv = SERVER_KEYS / "server_x25519.key"
    pub = SERVER_KEYS / "server_x25519.pub"
    if not priv.exists():
        SERVER_KEYS.mkdir(parents=True, exist_ok=True)
        k = keys.generate_x25519()
        keys.save_x25519_private(k, priv)
        keys.save_x25519_public(k, pub)
    return pub


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-id", default="agent-local")
    args = parser.parse_args()
    aid = args.agent_id

    AGENT_SECRETS.mkdir(parents=True, exist_ok=True)
    SERVER_AGENTS.mkdir(parents=True, exist_ok=True)

    # Ed25519 signing pair
    sign_key = keys.generate_ed25519()
    keys.save_private_key(sign_key, AGENT_SECRETS / f"{aid}.key")
    keys.save_public_key(sign_key, SERVER_AGENTS / f"{aid}.pub")

    # X25519 ECDH pair
    x_key = keys.generate_x25519()
    keys.save_x25519_private(x_key, AGENT_SECRETS / f"{aid}.x25519.key")
    keys.save_x25519_public(x_key, SERVER_AGENTS / f"{aid}.x25519.pub")

    # Copy the server's X25519 public key to the agent
    server_pub = ensure_server_x25519()
    (AGENT_SECRETS / "server_x25519.pub").write_bytes(server_pub.read_bytes())

    print(f"[provision] ECDH keys generated for '{aid}' (AES is not stored on disk):")
    print(f"  agent signing:  {AGENT_SECRETS / (aid + '.key')}")
    print(f"  agent x25519:   {AGENT_SECRETS / (aid + '.x25519.key')}")
    print(f"  server x25519 pub (agent): {AGENT_SECRETS / 'server_x25519.pub'}")
    print(f"  server pub (Ed25519):      {SERVER_AGENTS / (aid + '.pub')}")
    print(f"  server x25519 pub (agent): {SERVER_AGENTS / (aid + '.x25519.pub')}")


if __name__ == "__main__":
    main()
