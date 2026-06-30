"""Scanner tests — SQLi/XSS/port detection against a local mock target."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from aegis_scanner.port_scanner import scan as port_scan
from aegis_scanner.web_scanner import scan_url

_ACCOUNTS = {
    "1": b'{"owner":"admin","balance":1000,"iban":"A1"}',
    "2": b'{"owner":"alice","balance":50,"iban":"A2"}',
    "3": b'{"owner":"bob","balance":75,"iban":"A3"}',
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: C901 — a deliberately vulnerable mock with one branch per vuln
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/user":
            idv = qs.get("id", [""])[0]
            body = b"SQL error: unrecognized token" if "'" in idv else b"ok"
        elif u.path == "/search":
            q = qs.get("q", [""])[0]
            body = f"<h2>{q}</h2>".encode()  # unescaped reflection
        elif u.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", qs.get("next", [""])[0])  # open redirect
            self.end_headers()
            return
        elif u.path == "/exec":
            cmd = qs.get("cmd", [""])[0]
            body = cmd[5:].encode() if cmd.startswith("echo ") else b""  # output only
        elif u.path == "/greet":
            name = qs.get("name", [""])[0].replace("{{31337-1}}", "31336")  # Jinja eval
            body = f"<h2>Hello {name}!</h2>".encode()
        elif u.path == "/file":
            p = qs.get("p", [""])[0]
            body = b"AEGIS-LAB-SECRET-d4f7" if "SECRET" in p else b"welcome"
        elif u.path == "/ssrf-canary":
            body = b"AEGIS-SSRF-CANARY"
        elif u.path == "/fetch":
            body = b"AEGIS-SSRF-CANARY" if qs.get("url", [""])[0].endswith("/ssrf-canary") else b"status=200"
        elif u.path == "/account":
            body = _ACCOUNTS.get(qs.get("id", [""])[0], b'{"error":"no such account"}')
        elif u.path == "/transfer":
            body = b"<form method='POST'><input name='to'><button>Send</button></form>"  # no CSRF token
        elif u.path == "/ai-assistant":
            q = qs.get("q", [""])[0].lower()
            leak = any(w in q for w in ("ignore previous", "reveal", "system prompt"))
            body = b"AEGIS-LLM-SECRET-7b2" if leak else b"hello from the assistant"
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def target():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", srv.server_address[1]
    srv.shutdown()


def test_sqli_detected(target):
    url, _ = target
    findings = scan_url(f"{url}/user?id=1")
    assert any(f["type"] == "sqli" for f in findings)


def test_xss_detected(target):
    url, _ = target
    findings = scan_url(f"{url}/search?q=test")
    assert any(f["type"] == "xss" for f in findings)


def test_open_redirect_detected(target):
    url, _ = target
    findings = scan_url(f"{url}/redirect?next=home")
    assert any(f["type"] == "open_redirect" for f in findings)


def _types(findings):
    return {f["type"] for f in findings}


def test_command_injection_detected(target):
    url, _ = target
    assert "command_injection" in _types(scan_url(f"{url}/exec?cmd=hi"))


def test_ssti_detected(target):
    url, _ = target
    assert "ssti" in _types(scan_url(f"{url}/greet?name=guest"))


def test_path_traversal_detected(target):
    url, _ = target
    assert "path_traversal" in _types(scan_url(f"{url}/file?p=welcome.txt"))


def test_ssrf_detected(target):
    url, _ = target
    assert "ssrf" in _types(scan_url(f"{url}/fetch?url=x"))


def test_idor_detected(target):
    url, _ = target
    assert "idor" in _types(scan_url(f"{url}/account?id=1"))


def test_csrf_detected(target):
    url, _ = target
    assert "csrf" in _types(scan_url(f"{url}/transfer"))


def test_web_llm_prompt_injection_detected(target):
    url, _ = target
    assert "prompt_injection" in _types(scan_url(f"{url}/ai-assistant?q=hello"))


def test_findings_carry_mitre_tags(target):
    url, _ = target
    findings = scan_url(f"{url}/exec?cmd=hi")
    ci = next(f for f in findings if f["type"] == "command_injection")
    assert ci["tactic"] and ci["technique"]


def test_benign_endpoint_no_false_positives(target):
    url, _ = target
    # A plain reflecting search page must not trip SQLi/SSTI/cmdi false positives.
    assert _types(scan_url(f"{url}/search?q=test")) == {"xss"}


def test_port_scan_finds_open_port(target):
    _, port = target
    results = port_scan("127.0.0.1", [port])
    assert any(r["port"] == port for r in results)
