"""Simple web vulnerability scanner: SQL injection + reflected XSS.

Fuzzes every query parameter in a URL. For educational purposes; it does not replace a
real scanner (ZAP/Burp) but demonstrates the detection logic.
"""
from typing import Dict, List
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests

SQLI_PAYLOADS = ["'", '"', "' OR '1'='1", "1' OR '1'='1' -- "]
SQL_ERROR_SIGNATURES = [
    "sql error", "sqlite", "syntax error", "unrecognized token",
    "no such column", "operationalerror", "you have an error in your sql",
]
XSS_PAYLOAD = "<svg/onload=alert('aegisXSS')>"
OPENREDIR_PAYLOAD = "https://aegis-redirect.example/evil"
OPENREDIR_MARKER = "aegis-redirect.example"


def _with_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    qs = parse_qs(parts.query)
    qs[param] = [value]
    return urlunparse(parts._replace(query=urlencode(qs, doseq=True)))


def scan_url(url: str, timeout: float = 5.0) -> List[Dict]:
    findings: List[Dict] = []
    params = list(parse_qs(urlparse(url).query).keys())
    if not params:
        return findings

    for param in params:
        # --- SQL injection (error-based) ---
        for payload in SQLI_PAYLOADS:
            try:
                r = requests.get(_with_param(url, param, payload), timeout=timeout)
            except requests.RequestException:
                continue
            if any(sig in r.text.lower() for sig in SQL_ERROR_SIGNATURES):
                findings.append({
                    "type": "sqli", "url": url, "param": param, "payload": payload,
                    "evidence": "SQL error message reflected in the response", "severity": "high",
                })
                break

        # --- Reflected XSS ---
        try:
            r = requests.get(_with_param(url, param, XSS_PAYLOAD), timeout=timeout)
            if XSS_PAYLOAD in r.text:
                findings.append({
                    "type": "xss", "url": url, "param": param, "payload": XSS_PAYLOAD,
                    "evidence": "Payload reflected into HTML without escaping", "severity": "medium",
                })
        except requests.RequestException:
            pass

        # --- Open redirect (inspect Location without following the redirect) ---
        try:
            r = requests.get(
                _with_param(url, param, OPENREDIR_PAYLOAD),
                timeout=timeout,
                allow_redirects=False,
            )
            location = r.headers.get("Location", "")
            if r.is_redirect and OPENREDIR_MARKER in location:
                findings.append({
                    "type": "open_redirect", "url": url, "param": param,
                    "payload": OPENREDIR_PAYLOAD,
                    "evidence": f"Location redirects to an external address: {location}",
                    "severity": "medium",
                })
        except requests.RequestException:
            pass

    return findings
