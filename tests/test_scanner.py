"""Scanner tests — SQLi/XSS/port detection against a local mock target."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import pytest
from aegis_scanner.port_scanner import scan as port_scan
from aegis_scanner.web_scanner import scan_url


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
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


def test_port_scan_finds_open_port(target):
    _, port = target
    results = port_scan("127.0.0.1", [port])
    assert any(r["port"] == port for r in results)
