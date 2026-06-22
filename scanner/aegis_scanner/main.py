"""Aegis scanner CLI — port + web vulnerability scanning, reports findings to the SOC.

⚠️ ETHICS: Use only against targets you OWN / are authorized to test.
Default target is 127.0.0.1 (local lab).

Usage:
    python -m aegis_scanner.main --target 127.0.0.1 \
        --web-url "http://127.0.0.1:5001/user?id=1" \
        --web-url "http://127.0.0.1:5001/search?q=test"
"""
import argparse
from typing import List

from .port_scanner import scan as port_scan
from .reporter import Reporter
from .web_scanner import scan_url

DEFAULT_PORTS = [21, 22, 80, 443, 445, 3306, 3389, 5001, 5173, 5432, 6379, 8000, 8080, 8443]
DEFAULT_WEB = [
    "http://127.0.0.1:5001/user?id=1",
    "http://127.0.0.1:5001/search?q=test",
    "http://127.0.0.1:5001/redirect?next=home",
]


def parse_ports(spec: str) -> List[int]:
    if not spec:
        return DEFAULT_PORTS
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return list(range(int(lo), int(hi) + 1))
    return [int(p) for p in spec.split(",") if p.strip()]


def main():
    parser = argparse.ArgumentParser(description="Aegis vulnerability scanner")
    parser.add_argument("--target", default="127.0.0.1", help="host to port-scan")
    parser.add_argument("--ports", default="", help="'1-1024' or '22,80,443' (empty=default list)")
    parser.add_argument("--web-url", action="append", default=[], help="URL for web scanning (repeatable)")
    parser.add_argument("--server", default="http://127.0.0.1:8000", help="Aegis SOC server")
    parser.add_argument("--no-report", action="store_true", help="do not send findings to the SOC")
    args = parser.parse_args()

    print("[!] Only scan authorized/lab targets.\n")
    events = []

    # --- Port scan ---
    print(f"[port] scanning {args.target}...")
    open_ports = port_scan(args.target, parse_ports(args.ports))
    for op in open_ports:
        print(f"  OPEN  {op['port']:>5}/tcp  {op['service']}")
        events.append({"event_type": "open_port", "data": {"host": args.target, **op}})

    # --- Web scan ---
    web_urls = args.web_url or DEFAULT_WEB
    print(f"\n[web] scanning {len(web_urls)} URL(s)...")
    for url in web_urls:
        for f in scan_url(url):
            print(f"  VULN [{f['severity']}] {f['type'].upper()} -> {f['url']} (param={f['param']})")
            events.append({"event_type": "vuln_finding", "data": f})

    # --- Report ---
    if not args.no_report:
        sent = Reporter(args.server).send(events)
        print(f"\n[report] {sent} findings sent to the Aegis SOC -> {args.server}/api/alerts")
    else:
        print(f"\n[report] skipped (--no-report). {len(events)} findings found.")


if __name__ == "__main__":
    main()
