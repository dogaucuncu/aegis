"""Rotate the server's static X25519 key pair (Milestone 4 key hygiene).

Archives the old keypair (timestamped .bak) and writes a fresh one. After rotation, agents
that use the v1 (static-static) secure channel must re-fetch the new `server_x25519.pub`;
PFS (v2) agents only need the refreshed public key at startup.

Usage:
    python scripts/rotate_keys.py                       # rotate server/keys/server_x25519.*
    python scripts/rotate_keys.py --priv path --pub path
"""
import argparse
from pathlib import Path

from aegis_crypto import keys

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PRIV = ROOT / "server" / "keys" / "server_x25519.key"
DEFAULT_PUB = ROOT / "server" / "keys" / "server_x25519.pub"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--priv", default=str(DEFAULT_PRIV))
    parser.add_argument("--pub", default=str(DEFAULT_PUB))
    args = parser.parse_args()

    Path(args.priv).parent.mkdir(parents=True, exist_ok=True)
    keys.rotate_x25519(args.priv, args.pub)
    print(f"[rotate] new X25519 keypair written:\n  {args.priv}\n  {args.pub}")
    print("[rotate] previous keys archived as *.bak — re-distribute the new public key to agents.")


if __name__ == "__main__":
    main()
