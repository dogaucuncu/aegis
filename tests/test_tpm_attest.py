"""TPM 2.0 attestation tests (Milestone 7).

Unit: soft-TPM extend / quote / verify / drift.
Integration: enroll -> challenge -> quote, with pass / drift / replay / forgery outcomes and the
matching SOC alerts.
"""
from aegis_crypto import keys, tpm
from cryptography.hazmat.primitives import serialization

GOLDEN = {
    0: b"UEFI firmware v1.0",
    4: b"Boot manager: bootmgfw.efi",
    7: b"Secure Boot: ENABLED",
    8: b"OS loader: kernel sig=ok",
}


def _measure(components):
    soft = tpm.SoftTPM()
    soft.measure_boot(components)
    return soft.read(sorted(components))


def _pem(priv):
    return (
        priv.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )


# --------------------------- unit: soft-TPM ---------------------------
def test_extend_is_deterministic_and_order_sensitive():
    a, b = tpm.SoftTPM(), tpm.SoftTPM()
    a.measure_boot(GOLDEN)
    b.measure_boot(GOLDEN)
    assert a.read(sorted(GOLDEN)) == b.read(sorted(GOLDEN))
    # A different measurement in one PCR changes only that PCR.
    c = tpm.SoftTPM()
    c.measure_boot({**GOLDEN, 7: b"Secure Boot: DISABLED"})
    got = c.read(sorted(GOLDEN))
    assert got[7] != a.read([7])[7]
    assert got[0] == a.read([0])[0]


def test_quote_roundtrip_verifies():
    ak = keys.generate_ed25519()
    quote = tpm.make_quote(ak, "nonce123", _measure(GOLDEN))
    ok, reason = tpm.verify_quote(ak.public_key(), quote, "nonce123")
    assert ok and reason == ""


def test_quote_tampered_pcr_breaks_digest():
    ak = keys.generate_ed25519()
    quote = tpm.make_quote(ak, "n", _measure(GOLDEN))
    # Flip a reported PCR without re-signing -> digest no longer matches.
    quote["pcrs"]["7"] = "00" * 32
    ok, reason = tpm.verify_quote(ak.public_key(), quote, "n")
    assert not ok and reason == "pcr_digest_mismatch"


def test_quote_forged_signature_rejected():
    ak, rogue = keys.generate_ed25519(), keys.generate_ed25519()
    quote = tpm.make_quote(ak, "n", _measure(GOLDEN))
    ok, reason = tpm.verify_quote(rogue.public_key(), quote, "n")
    assert not ok and reason == "bad_signature"


def test_quote_nonce_mismatch_rejected():
    ak = keys.generate_ed25519()
    quote = tpm.make_quote(ak, "old", _measure(GOLDEN))
    ok, reason = tpm.verify_quote(ak.public_key(), quote, "fresh")
    assert not ok and reason == "nonce_mismatch"


def test_diff_baseline_reports_changed_pcrs():
    base = _measure(GOLDEN)
    tampered = _measure({**GOLDEN, 7: b"Secure Boot: DISABLED"})
    assert tpm.diff_baseline(tampered, base) == [7]
    assert tpm.diff_baseline(base, base) == []


# --------------------------- integration: SOC ---------------------------
def _enroll(client, ak, pcrs=None):
    pcrs = pcrs or _measure(GOLDEN)
    r = client.post(
        "/api/attest/enroll",
        json={
            "agent_id": "ep1",
            "ak_pubkey": _pem(ak),
            "pcrs": pcrs,
            "selection": sorted(pcrs),
        },
    )
    assert r.status_code == 200
    return pcrs


def _nonce(client):
    r = client.post("/api/attest/challenge", json={"agent_id": "ep1"})
    assert r.status_code == 200
    return r.json()["nonce"]


def _alert_rule_ids(client):
    return {a["rule_id"] for a in client.get("/api/alerts").json()}


def test_challenge_unenrolled_agent_404(client):
    assert client.post("/api/attest/challenge", json={"agent_id": "nope"}).status_code == 404


def test_attest_pass_no_alert(client):
    ak = keys.generate_ed25519()
    _enroll(client, ak)
    quote = tpm.make_quote(ak, _nonce(client), _measure(GOLDEN))
    res = client.post("/api/attest/quote", json={"agent_id": "ep1", "quote": quote}).json()
    assert res == {"verified": True, "result": "pass", "reason": "", "drifted_pcrs": []}
    assert "tpm-pcr-drift" not in _alert_rule_ids(client)
    assert "tpm-attestation-fail" not in _alert_rule_ids(client)


def test_attest_drift_raises_alert(client):
    ak = keys.generate_ed25519()
    _enroll(client, ak)
    tampered = _measure({**GOLDEN, 7: b"Secure Boot: DISABLED"})
    quote = tpm.make_quote(ak, _nonce(client), tampered)
    res = client.post("/api/attest/quote", json={"agent_id": "ep1", "quote": quote}).json()
    assert res["result"] == "pcr_drift" and res["drifted_pcrs"] == [7]
    assert "tpm-pcr-drift" in _alert_rule_ids(client)


def test_attest_replay_rejected(client):
    ak = keys.generate_ed25519()
    _enroll(client, ak)
    captured = tpm.make_quote(ak, _nonce(client), _measure(GOLDEN))
    _nonce(client)  # server rotates the nonce -> the captured quote is stale
    res = client.post("/api/attest/quote", json={"agent_id": "ep1", "quote": captured}).json()
    assert res["result"] == "attestation_fail" and res["reason"] == "nonce_mismatch"
    assert "tpm-attestation-fail" in _alert_rule_ids(client)


def test_attest_forged_key_rejected(client):
    ak, rogue = keys.generate_ed25519(), keys.generate_ed25519()
    _enroll(client, ak)
    forged = tpm.make_quote(rogue, _nonce(client), _measure(GOLDEN))
    res = client.post("/api/attest/quote", json={"agent_id": "ep1", "quote": forged}).json()
    assert res["result"] == "attestation_fail" and res["reason"] == "bad_signature"
    assert "tpm-attestation-fail" in _alert_rule_ids(client)


def test_quote_without_challenge_rejected(client):
    ak = keys.generate_ed25519()
    _enroll(client, ak)
    # No /challenge issued -> nothing to answer.
    quote = tpm.make_quote(ak, "made-up-nonce", _measure(GOLDEN))
    res = client.post("/api/attest/quote", json={"agent_id": "ep1", "quote": quote}).json()
    assert res["result"] == "attestation_fail" and res["reason"] == "no_challenge_or_stale"


def test_status_reports_worst_first(client):
    ak = keys.generate_ed25519()
    _enroll(client, ak)
    # Drive one drift verdict, then read the per-endpoint status surface.
    tampered = _measure({**GOLDEN, 7: b"Secure Boot: DISABLED"})
    client.post(
        "/api/attest/quote",
        json={"agent_id": "ep1", "quote": tpm.make_quote(ak, _nonce(client), tampered)},
    )
    rows = client.get("/api/attest/status").json()
    assert len(rows) == 1
    row = rows[0]
    assert row["agent_id"] == "ep1"
    assert row["last_result"] == "pcr_drift"
    assert row["drifted_pcrs"] == [7]
    assert row["pcr_count"] == len(GOLDEN)


def test_enroll_invalid_pubkey_rejected(client):
    r = client.post(
        "/api/attest/enroll",
        json={"agent_id": "ep1", "ak_pubkey": "not-a-pem", "pcrs": _measure(GOLDEN)},
    )
    assert r.status_code == 400
