"""Rule engine tests — end-to-end via the API (ingest -> alert)."""


def _rule_ids(client):
    return {a["rule_id"] for a in client.get("/api/alerts").json()}


def test_suspicious_cmdline(client):
    r = client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process",
         "data": {"name": "powershell.exe", "cmdline": "powershell -enc QQQ="}}
    ]})
    assert r.status_code == 200
    assert "suspicious-cmdline" in _rule_ids(client)


def test_suspicious_process_name(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "mimikatz.exe"}}
    ]})
    assert "suspicious-process-name" in _rule_ids(client)


def test_brute_force_threshold(client):
    ev = {"agent_id": "bf", "event_type": "auth_failure",
          "data": {"username": "root", "source_ip": "1.2.3.4"}}
    r = client.post("/api/ingest", json={"events": [ev] * 6})
    assert r.json()["alerts_created"] >= 1
    assert "brute-force" in _rule_ids(client)


def test_vuln_and_ml_findings(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "s", "event_type": "vuln_finding",
         "data": {"type": "sqli", "url": "http://x/?id=1", "param": "id", "severity": "high"}},
        {"agent_id": "ml", "event_type": "phishing",
         "data": {"url": "http://evil.tk", "score": 0.95}},
    ]})
    ids = _rule_ids(client)
    assert "vuln-sqli" in ids and "ml-phishing" in ids


def test_benign_process_no_alert(client):
    r = client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process",
         "data": {"name": "chrome.exe", "cmdline": "chrome.exe --type=renderer"}}
    ]})
    assert r.json()["alerts_created"] == 0


def _vuln(url):
    return {"agent_id": "s", "event_type": "vuln_finding",
            "data": {"type": "sqli", "url": url, "param": "id", "severity": "high"}}


def test_alert_dedup_same_finding(client):
    client.post("/api/ingest", json={"events": [_vuln("http://x/?id=1")]})
    client.post("/api/ingest", json={"events": [_vuln("http://x/?id=1")]})
    sqli = [a for a in client.get("/api/alerts").json() if a["rule_id"] == "vuln-sqli"]
    assert len(sqli) == 1 and sqli[0]["count"] == 2


def test_alert_no_dedup_different_finding(client):
    client.post("/api/ingest", json={"events": [_vuln("http://x/?id=1")]})
    client.post("/api/ingest", json={"events": [_vuln("http://y/?id=2")]})
    sqli = [a for a in client.get("/api/alerts").json() if a["rule_id"] == "vuln-sqli"]
    assert len(sqli) == 2


def test_event_signed_flag_plain(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "t", "event_type": "process", "data": {"name": "x"}}
    ]})
    assert client.get("/api/events").json()[0]["signed"] is False


def test_file_integrity_alert(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "a", "event_type": "file_change",
         "data": {"path": "/etc/passwd", "action": "modified", "hash": "abc123"}}
    ]})
    assert "file-integrity" in _rule_ids(client)


def test_gte_operator_fires_above_threshold(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "ml", "event_type": "ueba_anomaly", "data": {"username": "bob", "score": 0.92}}
    ]})
    assert "ml-ueba-anomaly" in _rule_ids(client)


def test_gte_operator_silent_below_threshold(client):
    r = client.post("/api/ingest", json={"events": [
        {"agent_id": "ml", "event_type": "ueba_anomaly", "data": {"username": "bob", "score": 0.30}}
    ]})
    assert r.json()["alerts_created"] == 0


def test_numeric_and_regex_operators_unit():
    """Directly exercise the new _check operators without the DB."""
    from app import models, rules

    ev = models.Event(agent_id="t", event_type="x",
                      data={"cmd": "SELECT * FROM users", "n": 7})
    assert rules._check({"field": "data.cmd", "op": "regex_match", "value": "select", "lower": True}, ev) is True
    assert rules._check({"field": "data.cmd", "op": "regex_match", "value": "drop"}, ev) is False
    assert rules._check({"field": "data.n", "op": "gte", "value": 5}, ev) is True
    assert rules._check({"field": "data.n", "op": "lt", "value": 5}, ev) is False


def test_vuln_alert_carries_per_finding_mitre(client):
    """The generic vuln rule pulls tactic/technique from the scanner's finding data (M2)."""
    client.post("/api/ingest", json={"events": [
        {"agent_id": "s", "event_type": "vuln_finding",
         "data": {"type": "ssti", "url": "http://x/greet", "param": "name",
                  "severity": "high", "tactic": "Execution", "technique": "T1059"}}
    ]})
    alert = next(a for a in client.get("/api/alerts").json() if a["rule_id"] == "vuln-ssti")
    assert alert["tactic"] == "Execution" and alert["technique"] == "T1059"


def test_new_web_vuln_types_alert(client):
    """Each new finding type maps to a vuln-<type> alert via the generic rule."""
    events = [
        {"agent_id": "s", "event_type": "vuln_finding",
         "data": {"type": t, "url": f"http://x/{t}", "param": "p", "severity": "high"}}
        for t in ("command_injection", "path_traversal", "ssrf", "idor", "prompt_injection")
    ]
    client.post("/api/ingest", json={"events": events})
    ids = _rule_ids(client)
    for t in ("command_injection", "path_traversal", "ssrf", "idor", "prompt_injection"):
        assert f"vuln-{t}" in ids


def test_waf_inspection_middleware_raises_alert(client):
    """The opt-in request-inspection middleware flags an attack signature in the URL."""
    from app.middleware import RequestInspectionMiddleware
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    waf_app = FastAPI()
    waf_app.add_middleware(RequestInspectionMiddleware, enabled=True)

    @waf_app.get("/x")
    def _x():
        return {"ok": True}

    # Malicious query string (SQLi signature) — detection-only, request still succeeds.
    assert TestClient(waf_app).get("/x", params={"id": "1' OR '1'='1"}).status_code == 200
    # The alert is written to the shared DB the main app reads from.
    assert "waf-signature" in _rule_ids(client)
