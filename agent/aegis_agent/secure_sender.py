"""Secure sender: signs events (Ed25519) + encrypts (AES-GCM) + sends them.

Optional mTLS: if ca_cert/client_cert/client_key are provided, uses HTTPS + a client certificate.
"""
import datetime as dt
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from aegis_crypto import aesgcm, canonical, derive_aes_key, keys, pfs, signing, tlspin


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
        use_pfs: bool = False,
        pin_sha256: Optional[str] = None,
    ):
        self.url = server_url.rstrip("/") + "/api/ingest/secure"
        self.agent_id = agent_id
        self.pin_sha256 = pin_sha256
        self.priv = keys.load_private_key(private_key_path)
        # The server's static X25519 public key (recipient for ECDH).
        self.server_pub = keys.load_x25519_public(server_x25519_pub_path)
        self.use_pfs = use_pfs
        # v1 (static-static): derive the long-lived AES key once via ECDH(agent_priv, server_pub).
        # v2 (PFS): a fresh key is derived per message in send(); no static AES key is kept.
        x_priv = keys.load_x25519_private(x25519_key_path)
        self.aes = derive_aes_key(x_priv, self.server_pub)
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

    def _check_pin(self) -> None:
        """If a pin is configured, refuse to send unless the server cert fingerprint matches."""
        if not self.pin_sha256:
            return
        parts = urlparse(self.url)
        if parts.scheme != "https":
            return  # nothing to pin over plain HTTP
        host, port = parts.hostname, parts.port or 443
        if not tlspin.verify_pin(host, port, self.pin_sha256, cafile=self.verify if isinstance(self.verify, str) else None):
            raise RuntimeError(f"Certificate pin mismatch for {host}:{port} — refusing to send")

    def send(self, events: List[Dict]) -> int:
        if not events:
            return 0
        self._check_pin()
        signed = [self._sign_event(e) for e in events]
        # ts: freshness stamp for replay protection (naive UTC isoformat).
        ts = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat()
        plaintext = canonical.canonical_bytes({"ts": ts, "events": signed})
        if self.use_pfs:
            aes, epk = pfs.sender_session_key(self.server_pub)  # fresh ephemeral key per message
            nonce, ciphertext = aesgcm.encrypt(aes, plaintext)
            envelope = {"agent_id": self.agent_id, "nonce": nonce, "ciphertext": ciphertext,
                        "version": 2, "epk": epk}
        else:
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
