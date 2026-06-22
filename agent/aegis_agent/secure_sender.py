"""Secure sender: signs events (Ed25519) + encrypts (AES-GCM) + sends them.

Optional mTLS: if ca_cert/client_cert/client_key are provided, uses HTTPS + a client certificate.
"""
import datetime as dt
from typing import Dict, List, Optional

import requests
from aegis_crypto import aesgcm, canonical, derive_aes_key, keys, signing


class SecureSender:
    def __init__(
        self,
        server_url: str,
        agent_id: str,
        private_key_path: str,
        x25519_key_path: str,
        server_x25519_pub_path: str,
        timeout: float = 10.0,
        ca_cert: Optional[str] = None,
        client_cert: Optional[str] = None,
        client_key: Optional[str] = None,
    ):
        self.url = server_url.rstrip("/") + "/api/ingest/secure"
        self.agent_id = agent_id
        self.priv = keys.load_private_key(private_key_path)
        # The AES key is derived via ECDH(agent_x25519_priv, server_x25519_pub) + HKDF.
        x_priv = keys.load_x25519_private(x25519_key_path)
        server_pub = keys.load_x25519_public(server_x25519_pub_path)
        self.aes = derive_aes_key(x_priv, server_pub)
        self.timeout = timeout
        # requests TLS parameters
        self.verify = ca_cert if ca_cert else True
        self.cert = (client_cert, client_key) if client_cert and client_key else None

    def _sign_event(self, e: Dict) -> Dict:
        ts = e.get("timestamp")
        cbytes = canonical.event_canonical(self.agent_id, e["event_type"], ts, e.get("data", {}))
        return {
            "agent_id": self.agent_id,
            "event_type": e["event_type"],
            "timestamp": ts,
            "data": e.get("data", {}),
            "signature": signing.sign(self.priv, cbytes),
        }

    def send(self, events: List[Dict]) -> int:
        if not events:
            return 0
        signed = [self._sign_event(e) for e in events]
        # ts: freshness stamp for replay protection (naive UTC isoformat).
        ts = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat()
        plaintext = canonical.canonical_bytes({"ts": ts, "events": signed})
        nonce, ciphertext = aesgcm.encrypt(self.aes, plaintext)
        envelope = {"agent_id": self.agent_id, "nonce": nonce, "ciphertext": ciphertext}
        resp = requests.post(
            self.url,
            json=envelope,
            timeout=self.timeout,
            verify=self.verify,
            cert=self.cert,
        )
        resp.raise_for_status()
        return resp.json().get("ingested", 0)
