"""Capped, loopback-ONLY HTTP flood to trip the SOC's volumetric (flood) detection.

Strictly for testing your OWN local SOC: it refuses any non-loopback target and hard-caps the
request count. Start the SOC with a rate limit so the limiter fires, e.g.:
    AEGIS_RATE_LIMIT_PER_MIN=30 uvicorn app.main:app --port 8000

Usage:
    python scripts/flood_lab.py --url http://127.0.0.1:8000/health --count 80
"""
import argparse
import ipaddress
import sys
from urllib.parse import urlparse

import requests

MAX_COUNT = 1000  # hard safety cap


def _is_loopback(url: str) -> bool:
    host = urlparse(url).hostname or ""
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000/health")
    parser.add_argument("--count", type=int, default=80)
    args = parser.parse_args()

    if not _is_loopback(args.url):
        sys.exit("Refusing: flood_lab only targets loopback (127.0.0.1 / localhost).")

    count = min(args.count, MAX_COUNT)
    print(f"[flood] sending {count} requests to {args.url} (hard cap {MAX_COUNT})")
    codes: dict = {}
    session = requests.Session()
    for _ in range(count):
        try:
            r = session.get(args.url, timeout=3)
            codes[r.status_code] = codes.get(r.status_code, 0) + 1
        except requests.RequestException:
            codes["err"] = codes.get("err", 0) + 1
    print("[flood] response codes:", codes)
    if codes.get(429):
        print("[flood] rate limiter tripped -> SOC should raise a 'network-flood' alert")
    else:
        print("[flood] no 429s — start the SOC with AEGIS_RATE_LIMIT_PER_MIN set below --count")


if __name__ == "__main__":
    main()
