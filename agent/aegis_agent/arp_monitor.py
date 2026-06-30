"""ARP table monitor — detects ARP-spoofing / man-in-the-middle indicators (defensive).

This is a *detector*, not an attacker. It reads the host ARP cache (cross-platform `arp -a`)
and flags two classic adversary-in-the-middle (MITRE T1557) signatures:

  1. an IP whose MAC address changed since the baseline (cache poisoning), and
  2. one MAC claiming multiple IPs (a spoofer impersonating several hosts / the gateway).

For lab demos an explicit `table_file` (a JSON ``{ip: mac}`` fixture) can be supplied instead
of the live cache, so a simulation can "poison" the table on disk without touching the network.
"""
import datetime as dt
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

# Matches an IPv4 + MAC pair on a line of `arp -a` output on Windows ("aa-bb-..") or Linux ("aa:bb:..").
_ARP_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3}).*?([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})"
)


def _parse_arp(text: str) -> Dict[str, str]:
    table: Dict[str, str] = {}
    for line in text.splitlines():
        m = _ARP_RE.search(line)
        if m:
            table[m.group(1)] = m.group(2).lower().replace("-", ":")
    return table


class ARPMonitor:
    def __init__(self, table_file: Optional[str] = None):
        # table_file: optional JSON {ip: mac} fixture (lab simulation). None = live `arp -a`.
        self._table_file = Path(table_file) if table_file else None
        self._baseline = self._read_table()

    def _read_table(self) -> Dict[str, str]:
        if self._table_file is not None:
            try:
                return {str(k): str(v).lower() for k, v in
                        json.loads(self._table_file.read_text(encoding="utf-8")).items()}
            except (OSError, ValueError):
                return {}
        return self._read_system_arp()

    @staticmethod
    def _read_system_arp() -> Dict[str, str]:
        try:
            out = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return {}
        return _parse_arp(out)

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat()

    def collect(self) -> List[Dict]:
        """Compare the current ARP table to the baseline and emit arp_change events."""
        current = self._read_table()
        events: List[Dict] = []

        # 1) An existing IP now maps to a different MAC -> cache poisoning.
        for ip, mac in current.items():
            old = self._baseline.get(ip)
            if old and old != mac:
                events.append({
                    "event_type": "arp_change", "timestamp": self._now(),
                    "data": {"ip": ip, "old_mac": old, "new_mac": mac, "risk": "mac_changed"},
                })

        # 2) One MAC claiming several IPs -> a spoofer impersonating multiple hosts.
        by_mac: Dict[str, List[str]] = defaultdict(list)
        for ip, mac in current.items():
            by_mac[mac].append(ip)
        for mac, ips in by_mac.items():
            if len(ips) >= 2:
                events.append({
                    "event_type": "arp_change", "timestamp": self._now(),
                    "data": {"mac": mac, "ips": sorted(ips), "risk": "duplicate_mac"},
                })

        self._baseline = current
        return events
