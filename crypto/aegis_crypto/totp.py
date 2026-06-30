"""RFC 6238 TOTP (and RFC 4226 HOTP) — time-based one-time passwords for MFA.

Pure-stdlib implementation (hmac + hashlib), no extra dependency. Compatible with Google
Authenticator / Authy when the base32 secret is provisioned via an otpauth:// URI.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time


def generate_secret(length: int = 20) -> str:
    """Returns a random base32 secret (default 160-bit, the RFC-recommended size)."""
    return base64.b32encode(secrets.token_bytes(length)).decode("ascii")


def _b32decode(secret_b32: str) -> bytes:
    # Accept secrets with stripped padding and any case (authenticator apps print them that way).
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    return base64.b32decode(padded, casefold=True)


def hotp(secret_b32: str, counter: int, digits: int = 6) -> str:
    """RFC 4226 HOTP for a given counter."""
    digest = hmac.new(_b32decode(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp_now(secret_b32: str, t: float | None = None, step: int = 30, digits: int = 6) -> str:
    """Current TOTP code for the secret."""
    if t is None:
        t = time.time()
    return hotp(secret_b32, int(t // step), digits)


def verify_totp(
    secret_b32: str,
    code: str,
    t: float | None = None,
    step: int = 30,
    digits: int = 6,
    window: int = 1,
) -> bool:
    """Constant-time check of a submitted code, allowing +/- `window` steps for clock skew."""
    if not code:
        return False
    if t is None:
        t = time.time()
    counter = int(t // step)
    target = str(code).strip().zfill(digits)
    return any(
        hmac.compare_digest(hotp(secret_b32, counter + offset, digits), target)
        for offset in range(-window, window + 1)
    )
