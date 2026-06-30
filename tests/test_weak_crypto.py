"""Weak-crypto demonstrations (Milestone 4): ECB leakage, weak-hash flagging, padding oracle."""
import os

from aegis_crypto import weak_crypto


def test_ecb_leaks_repeated_blocks():
    key = os.urandom(16)
    # Three identical 16-byte plaintext blocks -> identical ciphertext blocks under ECB.
    ct = weak_crypto.aes_ecb_encrypt(key, b"YELLOW SUBMARINE" * 3)
    assert weak_crypto.ecb_has_repeated_blocks(ct) is True


def test_ecb_no_false_positive_on_distinct_blocks():
    key = os.urandom(16)
    ct = weak_crypto.aes_ecb_encrypt(key, os.urandom(48))
    assert weak_crypto.ecb_has_repeated_blocks(ct) is False


def test_is_weak_hash():
    assert weak_crypto.is_weak_hash("md5")
    assert weak_crypto.is_weak_hash("SHA-1")
    assert not weak_crypto.is_weak_hash("sha256")


def test_padding_oracle_recovers_plaintext_without_key():
    secret = b"Attack at dawn! transfer=1000 to=attacker"
    oracle = weak_crypto.PaddingOracle()
    iv, ct = oracle.encrypt(secret)
    # The attacker only uses the padding-validity oracle, never the key.
    recovered = weak_crypto.recover_plaintext(oracle, iv, ct)
    assert recovered == secret


def test_padding_oracle_single_block():
    oracle = weak_crypto.PaddingOracle()
    iv, ct = oracle.encrypt(b"one block exactly")  # spans two blocks after padding
    assert weak_crypto.recover_plaintext(oracle, iv, ct) == b"one block exactly"
