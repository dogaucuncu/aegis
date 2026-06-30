"""Password hashing with Argon2id.

Used by the server login flow to store/verify user passwords. Argon2id is the modern,
memory-hard KDF recommended for password storage (resistant to GPU/ASIC brute-force).
"""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

# Default parameters are sane for an interactive login; tune for your hardware in production.
_hasher = PasswordHasher()


def hash_password(password: str) -> str:
    """Returns an Argon2id PHC-format hash string (salt + parameters embedded)."""
    return _hasher.hash(password)


def verify_password(hashed: str, password: str) -> bool:
    """True if the password matches the hash; False on mismatch or a malformed hash (never raises)."""
    try:
        return _hasher.verify(hashed, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(hashed: str) -> bool:
    """True if the hash was produced with outdated parameters and should be re-hashed on next login."""
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True
