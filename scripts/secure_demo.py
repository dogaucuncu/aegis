"""Faz 2 güvenli akış demosu.

Kanıtlar:
  1. Geçerli imzalı + şifreli batch -> kabul (200).
  2. Sahte (bozulmuş) imza -> 401 reddedilir.
  3. Yanlış AES anahtarı -> 400 (çözme başarısız).

Önce: python scripts/provision_agent.py --agent-id agent-local
Kullanım: python scripts/secure_demo.py --server http://127.0.0.1:8000
"""
import argparse
import base64
import os
from pathlib import Path

import requests
from aegis_crypto import aesgcm, canonical, derive_aes_key, keys, signing

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / "agent" / "secrets"
AGENT = "agent-local"


def _now_iso():
    import datetime as dt
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat()


def build_envelope(aes_key, priv, events):
    signed = []
    for e in events:
        cbytes = canonical.event_canonical(AGENT, e["event_type"], e["timestamp"], e["data"])
        signed.append({**e, "agent_id": AGENT, "signature": signing.sign(priv, cbytes)})
    plaintext = canonical.canonical_bytes({"ts": _now_iso(), "events": signed})
    nonce, ct = aesgcm.encrypt(aes_key, plaintext)
    return {"agent_id": AGENT, "nonce": nonce, "ciphertext": ct}, signed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="http://127.0.0.1:8000")
    args = parser.parse_args()
    url = args.server.rstrip("/") + "/api/ingest/secure"

    priv = keys.load_private_key(SECRETS / f"{AGENT}.key")
    # AES anahtarını ECDH ile türet (ajan x25519 priv + sunucu x25519 pub).
    x_priv = keys.load_x25519_private(SECRETS / f"{AGENT}.x25519.key")
    server_pub = keys.load_x25519_public(SECRETS / "server_x25519.pub")
    aes_key = derive_aes_key(x_priv, server_pub)

    events = [
        {"event_type": "process", "timestamp": "2026-06-17T12:00:00",
         "data": {"name": "powershell.exe", "cmdline": "powershell -enc QQQ="}},
        {"event_type": "process", "timestamp": "2026-06-17T12:00:01",
         "data": {"name": "mimikatz.exe", "cmdline": "mimikatz.exe"}},
    ]

    # 1) Geçerli
    env, signed = build_envelope(aes_key, priv, events)
    r = requests.post(url, json=env, timeout=10)
    print(f"[1] Gecerli batch  -> HTTP {r.status_code} {r.json() if r.ok else r.text}")

    # 2) Sahte imza (ilk olayın imzasının son baytını boz)
    env2, signed2 = build_envelope(aes_key, priv, events)
    bad = bytearray(base64.b64decode(signed2[0]["signature"]))
    bad[-1] ^= 0x01
    signed2[0]["signature"] = base64.b64encode(bytes(bad)).decode()
    pt = canonical.canonical_bytes({"ts": _now_iso(), "events": signed2})
    n, ct = aesgcm.encrypt(aes_key, pt)
    r2 = requests.post(url, json={"agent_id": AGENT, "nonce": n, "ciphertext": ct}, timeout=10)
    print(f"[2] Sahte imza     -> HTTP {r2.status_code} {r2.text.strip()[:80]}")

    # 3) Yanlış AES anahtarı
    wrong = os.urandom(32)
    env3, _ = build_envelope(wrong, priv, events)
    r3 = requests.post(url, json=env3, timeout=10)
    print(f"[3] Yanlis AES key -> HTTP {r3.status_code} {r3.text.strip()[:80]}")

    print("\nBeklenen: [1]=200, [2]=401, [3]=400")


if __name__ == "__main__":
    main()
