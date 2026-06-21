import pytest
from aegis_crypto import (
    canonical_bytes,
    decrypt,
    encrypt,
    event_canonical,
    keys,
    sign,
    verify,
)
from cryptography.exceptions import InvalidTag


def test_sign_verify_roundtrip():
    priv = keys.generate_ed25519()
    pub = priv.public_key()
    data = canonical_bytes({"b": 2, "a": 1})
    sig = sign(priv, data)
    assert verify(pub, data, sig)
    assert not verify(pub, data + b"x", sig)  # kurcalanmış reddedilir


def test_aes_roundtrip_and_wrong_key():
    key = keys.generate_aes_key()
    nonce, ct = encrypt(key, b"gizli")
    assert decrypt(key, nonce, ct) == b"gizli"
    with pytest.raises(InvalidTag):
        decrypt(keys.generate_aes_key(), nonce, ct)


def test_event_canonical_is_order_independent():
    a = event_canonical("a1", "process", "2026-01-01T00:00:00", {"x": 1, "y": 2})
    b = event_canonical("a1", "process", "2026-01-01T00:00:00", {"y": 2, "x": 1})
    assert a == b
