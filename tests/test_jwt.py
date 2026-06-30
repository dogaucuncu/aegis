"""JWT attack/defense tests (Milestone 4): alg=none forgery, lab vuln vs hardened, scanner + rule."""
import importlib.util
from pathlib import Path
from urllib.parse import urlparse

import pytest
from aegis_crypto import jwt_tokens

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture()
def lab():
    # Load the lab app by path under a unique name (its module is "app", which would otherwise
    # collide with the server's `app` package already on sys.path).
    spec = importlib.util.spec_from_file_location(
        "aegis_lab_app", ROOT / "lab" / "vulnerable_app" / "app.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def lab_client(lab):
    return lab.app.test_client()


def test_forge_alg_none_unsigned_but_rejected_by_strict_verify():
    token = jwt_tokens.forge_alg_none({"sub": "attacker", "role": "admin"})
    assert jwt_tokens.decode_unsafe(token)["role"] == "admin"  # unsafe decode trusts it
    with pytest.raises(jwt_tokens.JWTError):
        jwt_tokens.verify_hs256(token, "any-secret")  # strict verification rejects it


def test_lab_jwt_vulnerable_endpoint_grants_admin(lab_client):
    token = jwt_tokens.forge_alg_none({"sub": "attacker", "role": "admin"})
    r = lab_client.get("/jwt/admin", headers={"Authorization": "Bearer " + token})
    assert r.status_code == 200 and "secret" in r.get_data(as_text=True).lower()


def test_lab_jwt_secure_endpoint_rejects_forgery(lab_client):
    token = jwt_tokens.forge_alg_none({"sub": "attacker", "role": "admin"})
    r = lab_client.get("/jwt/admin-secure", headers={"Authorization": "Bearer " + token})
    assert r.status_code == 401  # strict HS256 verification rejects alg=none


def test_jwt_scanner_detects_alg_none(monkeypatch, lab_client):
    import aegis_scanner.jwt_attacks as ja

    class _R:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

    def fake_get(url, headers=None, timeout=None):
        rv = lab_client.get(urlparse(url).path, headers=headers or {})
        return _R(rv.status_code, rv.get_data(as_text=True))

    monkeypatch.setattr(ja.requests, "get", fake_get)
    findings = ja.run("http://lab")
    assert any(f["type"] == "jwt_alg_none" for f in findings)
    assert findings[0]["technique"] == "T1550.001"


def test_jwt_vuln_finding_alerts(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "s", "event_type": "vuln_finding",
         "data": {"type": "jwt_alg_none", "url": "http://x/jwt/admin", "param": "Authorization",
                  "severity": "critical", "tactic": "Credential Access", "technique": "T1550.001"}}
    ]})
    a = next(x for x in client.get("/api/alerts").json() if x["rule_id"] == "vuln-jwt_alg_none")
    assert a["technique"] == "T1550.001" and a["severity"] == "critical"
