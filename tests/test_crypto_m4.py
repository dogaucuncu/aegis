"""Milestone 4 crypto tests: cert-pin helpers and X25519 key rotation."""
import hashlib

from aegis_crypto import keys, tlspin


def test_cert_sha256_matches_hashlib():
    der = b"\x30\x82demo-der-bytes"
    assert tlspin.cert_sha256(der) == hashlib.sha256(der).hexdigest()


def test_verify_pin_match_and_mismatch(monkeypatch):
    fixed = "ab" * 32
    monkeypatch.setattr(tlspin, "get_server_cert_sha256", lambda *a, **k: fixed)
    assert tlspin.verify_pin("h", 443, fixed.upper()) is True       # case-insensitive
    assert tlspin.verify_pin("h", 443, "cd" * 32) is False


def test_rotate_x25519_archives_old_and_writes_new(tmp_path):
    priv, pub = tmp_path / "s.key", tmp_path / "s.pub"
    original = keys.generate_x25519()
    keys.save_x25519_private(original, priv)
    keys.save_x25519_public(original, pub)
    old_pub_bytes = pub.read_bytes()

    keys.rotate_x25519(priv, pub)

    assert pub.read_bytes() != old_pub_bytes               # a fresh key was written
    backups = list(tmp_path.glob("s.pub.*.bak"))
    assert len(backups) == 1 and backups[0].read_bytes() == old_pub_bytes  # old key archived
    keys.load_x25519_private(priv)  # the new private key loads cleanly
