"""Güvenli ingestion testleri: geçerli=200, sahte imza=401, yanlış anahtar=400, replay=409."""
import base64
import datetime as dt

import pytest
from aegis_crypto import aesgcm, canonical, derive_aes_key, keys, signing


def _now_iso():
    return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat()


@pytest.fixture()
def provisioned(tmp_path, monkeypatch):
    """keystore'u geçici dizine yönlendirir; ECDH anahtarlarını üretir.

    Döndürür: (agent_id, ed25519_priv, türetilmiş_aes_key)
    """
    from app import keystore

    agents_dir = tmp_path / "agents"
    agents_dir.mkdir()
    monkeypatch.setattr(keystore, "SERVER_KEYS_DIR", tmp_path)
    monkeypatch.setattr(keystore, "KEYS_DIR", agents_dir)

    # Sunucu X25519 çifti
    server_x = keys.generate_x25519()
    keys.save_x25519_private(server_x, tmp_path / "server_x25519.key")
    keys.save_x25519_public(server_x, tmp_path / "server_x25519.pub")

    # Ajan Ed25519 (imza) + X25519 (ECDH)
    ed = keys.generate_ed25519()
    keys.save_public_key(ed, agents_dir / "ag.pub")
    agent_x = keys.generate_x25519()
    keys.save_x25519_public(agent_x, agents_dir / "ag.x25519.pub")

    # Ajan tarafı türetilmiş AES (server_priv + agent_pub ile eşit olmalı)
    aes = derive_aes_key(agent_x, server_x.public_key())
    return "ag", ed, aes


def _envelope(agent, priv, aes, events, ts=None):
    signed = []
    for e in events:
        cb = canonical.event_canonical(agent, e["event_type"], e["timestamp"], e["data"])
        signed.append({**e, "agent_id": agent, "signature": signing.sign(priv, cb)})
    pt = canonical.canonical_bytes({"ts": ts or _now_iso(), "events": signed})
    nonce, ct = aesgcm.encrypt(aes, pt)
    return {"agent_id": agent, "nonce": nonce, "ciphertext": ct}, signed


_EV = [{"event_type": "process", "timestamp": "2026-01-01T00:00:00", "data": {"name": "x"}}]


def test_secure_valid(client, provisioned):
    agent, priv, aes = provisioned
    env, _ = _envelope(agent, priv, aes, _EV)
    assert client.post("/api/ingest/secure", json=env).status_code == 200
    # Güvenli kanaldan gelen olay imzalı işaretlenir.
    assert client.get("/api/events").json()[0]["signed"] is True


def test_secure_forged_signature(client, provisioned):
    agent, priv, aes = provisioned
    _, signed = _envelope(agent, priv, aes, _EV)
    bad = bytearray(base64.b64decode(signed[0]["signature"]))
    bad[-1] ^= 0x01
    signed[0]["signature"] = base64.b64encode(bytes(bad)).decode()
    pt = canonical.canonical_bytes({"ts": _now_iso(), "events": signed})
    nonce, ct = aesgcm.encrypt(aes, pt)
    r = client.post("/api/ingest/secure", json={"agent_id": agent, "nonce": nonce, "ciphertext": ct})
    assert r.status_code == 401


def test_secure_wrong_key(client, provisioned):
    agent, priv, _aes = provisioned
    env, _ = _envelope(agent, priv, keys.generate_aes_key(), _EV)  # yanlış AES
    assert client.post("/api/ingest/secure", json=env).status_code == 400


def test_secure_unknown_agent(client, provisioned):
    _, priv, aes = provisioned
    env, _ = _envelope("ag", priv, aes, _EV)
    env["agent_id"] = "bilinmeyen"
    assert client.post("/api/ingest/secure", json=env).status_code == 401


def test_secure_replay_rejected(client, provisioned):
    agent, priv, aes = provisioned
    env, _ = _envelope(agent, priv, aes, _EV)
    assert client.post("/api/ingest/secure", json=env).status_code == 200
    # Aynı zarfı tekrar gönder -> replay
    assert client.post("/api/ingest/secure", json=env).status_code == 409


def test_secure_stale_timestamp_rejected(client, provisioned):
    agent, priv, aes = provisioned
    old = (dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) - dt.timedelta(hours=1)).isoformat()
    env, _ = _envelope(agent, priv, aes, _EV, ts=old)
    assert client.post("/api/ingest/secure", json=env).status_code == 401
