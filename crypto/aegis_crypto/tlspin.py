"""Certificate pinning helpers (Milestone 4).

Pinning protects the agent->server channel even if a rogue CA (or a local TLS-intercepting
product) issues a 'valid' certificate: the agent additionally checks that the server's
certificate SHA-256 matches a value it was provisioned with, and refuses to talk otherwise.
"""
import hashlib
import socket
import ssl
from typing import Optional


def cert_sha256(der_bytes: bytes) -> str:
    """SHA-256 fingerprint (hex) of a DER-encoded certificate."""
    return hashlib.sha256(der_bytes).hexdigest()


def get_server_cert_sha256(
    host: str, port: int, cafile: Optional[str] = None, timeout: float = 5.0
) -> str:
    """Open a TLS connection and return the server certificate's SHA-256 fingerprint.

    When `cafile` is None the chain is not validated (we only want the leaf fingerprint) — this
    is exactly the case where pinning adds value over CA trust.
    """
    ctx = ssl.create_default_context(cafile=cafile)
    if cafile is None:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    return cert_sha256(der)


def verify_pin(host: str, port: int, expected_sha256: str, cafile: Optional[str] = None) -> bool:
    """True if the live server certificate fingerprint matches the pinned value."""
    return get_server_cert_sha256(host, port, cafile).lower() == expected_sha256.strip().lower()
