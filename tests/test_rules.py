"""Kural motoru testleri — API üzerinden uçtan uca (ingest -> alarm)."""


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
