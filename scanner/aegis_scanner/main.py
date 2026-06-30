"""Aegis scanner CLI — port + web vulnerability scanning, reports findings to the SOC.

⚠️ ETHICS: Use only against targets you OWN / are authorized to test.
Default target is 127.0.0.1 (local lab).

Usage:
    python -m aegis_scanner.main --target 127.0.0.1 \
        --web-url "http://127.0.0.1:5001/user?id=1" \
        --web-url "http://127.0.0.1:5001/search?q=test"
"""
import argparse
from pathlib import Path
from typing import List, Optional

from . import bruteforce, jwt_attacks
from .port_scanner import scan as port_scan
from .reporter import Reporter
from .web_scanner import scan_url

DEFAULT_PORTS = [21, 22, 80, 443, 445, 3306, 3389, 5001, 5173, 5432, 6379, 8000, 8080, 8443]
DEFAULT_WEB = [
    "http://127.0.0.1:5001/user?id=1",
    "http://127.0.0.1:5001/search?q=test",
    "http://127.0.0.1:5001/redirect?next=home",
    "http://127.0.0.1:5001/exec?cmd=hi",
    "http://127.0.0.1:5001/greet?name=guest",
    "http://127.0.0.1:5001/file?p=welcome.txt",
    "http://127.0.0.1:5001/fetch?url=http://127.0.0.1:5001/ssrf-canary",
    "http://127.0.0.1:5001/account?id=1",
    "http://127.0.0.1:5001/transfer",
    "http://127.0.0.1:5001/ai-assistant?q=hello",
]


def parse_ports(spec: str) -> List[int]:
    if not spec:
        return DEFAULT_PORTS
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return list(range(int(lo), int(hi) + 1))
    return [int(p) for p in spec.split(",") if p.strip()]


def _load_wordlist(spec: Optional[str]) -> Optional[List[str]]:
    """Wordlist from a file (one password per line) or a comma-separated list; None = default."""
    if not spec:
        return None
    path = Path(spec)
    if path.exists():
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [w.strip() for w in spec.split(",") if w.strip()]


def main():
    parser = argparse.ArgumentParser(description="Aegis vulnerability scanner")
    parser.add_argument("--target", default="127.0.0.1", help="host to port-scan")
    parser.add_argument("--ports", default="", help="'1-1024' or '22,80,443' (empty=default list)")
    parser.add_argument("--web-url", action="append", default=[], help="URL for web scanning (repeatable)")
    parser.add_argument("--jwt-url", default="http://127.0.0.1:5001",
                        help="base URL for JWT alg=none tests (empty string to skip)")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Aegis SOC server")
    parser.add_argument("--no-report", action="store_true", help="do not send findings to the SOC")
    # Brute-force / password-spray (authorized lab targets only)
    parser.add_argument("--brute-login", help="login URL to brute-force, e.g. http://127.0.0.1:5001/login")
    parser.add_argument("--brute-user", help="username to brute-force (dictionary attack)")
    parser.add_argument("--brute-wordlist", help="password list: comma-separated or a file path")
    parser.add_argument("--spray-users", help="comma-separated usernames for password spray")
    parser.add_argument("--spray-password", help="single password to spray across --spray-users")
    parser.add_argument("--i-am-authorized", action="store_true",
                        help="confirm you own / are authorized to test a non-loopback target")
    args = parser.parse_args()

    print("[!] Only scan authorized/lab targets.\n")
    events = []

    # --- Port scan ---
    print(f"[port] scanning {args.target}...")
    scanned_ports = parse_ports(args.ports)
    open_ports = port_scan(args.target, scanned_ports)
    for op in open_ports:
        print(f"  OPEN  {op['port']:>5}/tcp  {op['service']}")
        events.append({"event_type": "open_port", "data": {"host": args.target, **op}})
    # Summary event so the SOC's port-scan rule (len(data.ports) >= 10) can detect the sweep.
    events.append({
        "event_type": "port_scan",
        "data": {
            "target": args.target, "source_ip": "scanner",
            "ports": scanned_ports, "open": [op["port"] for op in open_ports],
        },
    })

    # --- Web scan ---
    web_urls = args.web_url or DEFAULT_WEB
    print(f"\n[web] scanning {len(web_urls)} URL(s)...")
    for url in web_urls:
        for f in scan_url(url):
            print(f"  VULN [{f['severity']}] {f['type'].upper()} -> {f['url']} (param={f['param']})")
            events.append({"event_type": "vuln_finding", "data": f})

    # --- JWT alg=none attack ---
    if args.jwt_url:
        print(f"\n[jwt] testing {args.jwt_url} for alg=none forgery...")
        for f in jwt_attacks.run(args.jwt_url):
            print(f"  VULN [{f['severity']}] {f['type'].upper()} -> {f['url']}")
            events.append({"event_type": "vuln_finding", "data": f})

    # --- Brute-force / password spray (only when requested) ---
    if args.brute_login and (args.brute_user or args.spray_users):
        print(f"\n[brute] {args.brute_login}")
        try:
            if args.brute_user:
                wl = _load_wordlist(args.brute_wordlist)
                attempts = bruteforce.scan(
                    args.brute_login, args.brute_user, wl, authorized=args.i_am_authorized)
            else:
                users = [u.strip() for u in args.spray_users.split(",") if u.strip()]
                attempts = bruteforce.spray(
                    args.brute_login, users, args.spray_password or "",
                    authorized=args.i_am_authorized)
            for a in attempts:
                d = a["data"]
                flag = "HIT " if d["success"] else "miss"
                print(f"  {flag} {d['username']}:{d['attempt']}/{d['total']}")
                events.append(a)
        except PermissionError as exc:
            print(f"  refused: {exc}")

    # --- Report ---
    if not args.no_report:
        sent = Reporter(args.server).send(events)
        print(f"\n[report] {sent} findings sent to the Aegis SOC -> {args.server}/api/alerts")
    else:
        print(f"\n[report] skipped (--no-report). {len(events)} findings found.")


if __name__ == "__main__":
    main()
