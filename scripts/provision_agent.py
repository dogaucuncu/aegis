"""Bir ajan için anahtarlar üretir ve sunucuya 'kaydeder' (Faz 2 / WP6 ECDH).

Üretilenler:
  agent/secrets/<id>.key              Ed25519 özel (imza, ajanda kalır)
  agent/secrets/<id>.x25519.key       X25519 özel (ECDH, ajanda kalır)
  agent/secrets/server_x25519.pub     sunucunun X25519 açık anahtarı (ajan kopyası)
  server/keys/agents/<id>.pub         Ed25519 açık (sunucu doğrular)
  server/keys/agents/<id>.x25519.pub  X25519 açık (sunucu ECDH için)
  server/keys/server_x25519.key/.pub  sunucu X25519 çifti (yoksa üretilir)

AES anahtarı diskte tutulmaz; iki tarafça ECDH+HKDF ile türetilir.

Kullanım:
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

    # Ed25519 imza çifti
    sign_key = keys.generate_ed25519()
    keys.save_private_key(sign_key, AGENT_SECRETS / f"{aid}.key")
    keys.save_public_key(sign_key, SERVER_AGENTS / f"{aid}.pub")

    # X25519 ECDH çifti
    x_key = keys.generate_x25519()
    keys.save_x25519_private(x_key, AGENT_SECRETS / f"{aid}.x25519.key")
    keys.save_x25519_public(x_key, SERVER_AGENTS / f"{aid}.x25519.pub")

    # Sunucu X25519 açık anahtarını ajana kopyala
    server_pub = ensure_server_x25519()
    (AGENT_SECRETS / "server_x25519.pub").write_bytes(server_pub.read_bytes())

    print(f"[provision] '{aid}' icin ECDH anahtarlari uretildi (AES diskte tutulmaz):")
    print(f"  ajan imza:    {AGENT_SECRETS / (aid + '.key')}")
    print(f"  ajan x25519:  {AGENT_SECRETS / (aid + '.x25519.key')}")
    print(f"  sunucu x25519 pub (ajan): {AGENT_SECRETS / 'server_x25519.pub'}")
    print(f"  sunucu pub (Ed25519):     {SERVER_AGENTS / (aid + '.pub')}")
    print(f"  sunucu x25519 pub (ajan): {SERVER_AGENTS / (aid + '.x25519.pub')}")


if __name__ == "__main__":
    main()
