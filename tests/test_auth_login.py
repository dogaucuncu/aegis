"""Login hardening tests: Argon2, JWT (HS256/EdDSA), TOTP, and the /api/auth endpoints."""
import time

import pytest
from aegis_crypto import jwt_tokens, keys, passwords, totp


# ---------------- crypto primitives ----------------
def test_argon2_roundtrip():
    h = passwords.hash_password("hunter2")
    assert h != "hunter2"  # never stored in plaintext
    assert passwords.verify_password(h, "hunter2") is True
    assert passwords.verify_password(h, "wrong") is False
    assert passwords.verify_password("not-a-hash", "x") is False  # malformed → False, no raise


def test_jwt_hs256():
    token = jwt_tokens.issue_hs256("alice", "secret", ttl=60, role="admin")
    claims = jwt_tokens.verify_hs256(token, "secret")
    assert claims["sub"] == "alice" and claims["role"] == "admin"
    with pytest.raises(jwt_tokens.JWTError):
        jwt_tokens.verify_hs256(token, "wrong-secret")


def test_jwt_eddsa_reuses_ed25519():
    priv = keys.generate_ed25519()
    token = jwt_tokens.issue_eddsa("bob", priv)
    assert jwt_tokens.verify_eddsa(token, priv.public_key())["sub"] == "bob"


def test_totp_roundtrip():
    secret = totp.generate_secret()
    assert totp.verify_totp(secret, totp.totp_now(secret)) is True
    wrong = totp.hotp(secret, int(time.time() // 30) + 1000)  # far outside the window
    assert totp.verify_totp(secret, wrong) is False


# ---------------- endpoint flow ----------------
def test_register_and_login(client):
    assert client.post("/api/auth/register", json={"username": "neo", "password": "matrix"}).status_code == 200
    r = client.post("/api/auth/login", json={"username": "neo", "password": "matrix"})
    assert r.status_code == 200 and "access_token" in r.json()


def test_login_wrong_password(client):
    client.post("/api/auth/register", json={"username": "trinity", "password": "zion"})
    assert client.post("/api/auth/login", json={"username": "trinity", "password": "nope"}).status_code == 401


def test_account_lockout(client):
    client.post("/api/auth/register", json={"username": "morpheus", "password": "redpill"})
    for _ in range(5):
        client.post("/api/auth/login", json={"username": "morpheus", "password": "bad"})
    # Correct password is now rejected because the account is locked.
    r = client.post("/api/auth/login", json={"username": "morpheus", "password": "redpill"})
    assert r.status_code == 423


def test_totp_second_factor(client):
    reg = client.post(
        "/api/auth/register",
        json={"username": "oracle", "password": "cookies", "enable_totp": True},
    ).json()
    secret = reg["totp_secret"]
    assert secret
    # Password alone is not enough once TOTP is enrolled.
    assert client.post("/api/auth/login", json={"username": "oracle", "password": "cookies"}).status_code == 401
    r = client.post(
        "/api/auth/login",
        json={"username": "oracle", "password": "cookies", "totp": totp.totp_now(secret)},
    )
    assert r.status_code == 200
