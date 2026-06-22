"""Endpoint telemetry collector (cross-platform).

Collects:
  - process     : newly started processes (psutil)
  - network     : established outbound connections (psutil)
  - file_change : file integrity changes on watched paths (FIM, hash-based)
  - auth_failure: failed logins in the watched auth log file (tail + regex)
"""
import datetime as dt
import hashlib
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Set

import psutil

# sshd / common "Failed password for [invalid user ]<user> from <ip>" pattern
_AUTH_FAIL_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)", re.IGNORECASE
)


class TelemetryCollector:
    def __init__(
        self,
        watch_paths: Optional[List[str]] = None,
        auth_log: Optional[str] = None,
    ):
        self._seen_pids: Set[int] = set(psutil.pids())
        self._watch_paths = [Path(p) for p in (watch_paths or [])]
        self._auth_log = Path(auth_log) if auth_log else None
        self._file_hashes: Dict[str, str] = self._snapshot_files()
        # offset to read only new lines from the auth log
        self._auth_offset = self._auth_log.stat().st_size if (
            self._auth_log and self._auth_log.exists()
        ) else 0

    def _now(self) -> str:
        # Naive UTC isoformat (compatible with the server's canonical format).
        return dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat()

    # ---------- process / network ----------
    def collect_new_processes(self) -> List[Dict]:
        """Returns processes started since the last scan as 'process' events."""
        events: List[Dict] = []
        current = set(psutil.pids())
        for pid in current - self._seen_pids:
            try:
                p = psutil.Process(pid)
                with p.oneshot():
                    events.append({
                        "event_type": "process",
                        "timestamp": self._now(),
                        "data": {
                            "pid": pid, "name": p.name(), "cmdline": " ".join(p.cmdline()),
                            "username": p.username(), "ppid": p.ppid(),
                        },
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self._seen_pids = current
        return events

    def collect_network(self) -> List[Dict]:
        """Returns established (ESTABLISHED) outbound connections as 'network' events."""
        events: List[Dict] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return events
        for c in conns:
            if c.status == psutil.CONN_ESTABLISHED and c.raddr:
                events.append({
                    "event_type": "network",
                    "timestamp": self._now(),
                    "data": {
                        "pid": c.pid,
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}",
                        "status": c.status,
                    },
                })
        return events

    # ---------- file integrity (FIM) ----------
    def _iter_watched_files(self):
        for base in self._watch_paths:
            if base.is_file():
                yield base
            elif base.is_dir():
                for root, _dirs, files in os.walk(base):
                    for name in files:
                        yield Path(root) / name

    @staticmethod
    def _hash_file(path: Path) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except OSError:
            return None

    def _snapshot_files(self) -> Dict[str, str]:
        snap: Dict[str, str] = {}
        for path in self._iter_watched_files():
            digest = self._hash_file(path)
            if digest is not None:
                snap[str(path)] = digest
        return snap

    def collect_file_changes(self) -> List[Dict]:
        """Returns created/modified/deleted file changes on the watched paths."""
        if not self._watch_paths:
            return []
        events: List[Dict] = []
        current = self._snapshot_files()
        for path, digest in current.items():
            old = self._file_hashes.get(path)
            if old is None:
                action = "created"
            elif old != digest:
                action = "modified"
            else:
                continue
            events.append({
                "event_type": "file_change",
                "timestamp": self._now(),
                "data": {"path": path, "action": action, "hash": digest[:16]},
            })
        for path in self._file_hashes.keys() - current.keys():
            events.append({
                "event_type": "file_change",
                "timestamp": self._now(),
                "data": {"path": path, "action": "deleted", "hash": ""},
            })
        self._file_hashes = current
        return events

    # ---------- failed logins ----------
    def collect_auth_failures(self) -> List[Dict]:
        """Returns new failed-login lines from the watched auth log file."""
        if not self._auth_log or not self._auth_log.exists():
            return []
        events: List[Dict] = []
        size = self._auth_log.stat().st_size
        if size < self._auth_offset:  # rotated/truncated -> from the start
            self._auth_offset = 0
        try:
            with open(self._auth_log, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(self._auth_offset)
                for line in f:
                    m = _AUTH_FAIL_RE.search(line)
                    if m:
                        events.append({
                            "event_type": "auth_failure",
                            "timestamp": self._now(),
                            "data": {"username": m.group("user"), "source_ip": m.group("ip")},
                        })
                self._auth_offset = f.tell()
        except OSError:
            return events
        return events

    def collect(self) -> List[Dict]:
        return (
            self.collect_new_processes()
            + self.collect_network()
            + self.collect_file_changes()
            + self.collect_auth_failures()
        )
