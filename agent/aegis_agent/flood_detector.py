"""Outbound flood / scan detection from network telemetry (defensive).

Watches the rate of outbound connections per remote IP across a sliding window. When the host
opens an abnormal number of connections to one peer (a volumetric flood or a port sweep) it
emits a `flood_detected` event. It re-alerts at most once per window per peer to avoid spam.
"""
import datetime as dt
from collections import defaultdict
from typing import Dict, List, Tuple


class FloodDetector:
    def __init__(self, window_sec: int = 60, threshold: int = 50):
        self.window_sec = window_sec
        self.threshold = threshold
        self._events: List[Tuple[str, dt.datetime]] = []  # (remote_ip, ts)
        self._alerted: Dict[str, dt.datetime] = {}

    def analyze(self, network_events: List[Dict]) -> List[Dict]:
        now = dt.datetime.now(dt.timezone.utc)
        cutoff = now - dt.timedelta(seconds=self.window_sec)
        # Slide the window, then add this round's connections.
        self._events = [(ip, ts) for ip, ts in self._events if ts > cutoff]
        for ev in network_events:
            raddr = (ev.get("data") or {}).get("raddr") or ""
            ip = raddr.rsplit(":", 1)[0]
            if ip:
                self._events.append((ip, now))

        counts: Dict[str, int] = defaultdict(int)
        for ip, _ts in self._events:
            counts[ip] += 1

        out: List[Dict] = []
        for ip, count in counts.items():
            if count < self.threshold:
                continue
            last = self._alerted.get(ip)
            if last is not None and last > cutoff:
                continue  # already alerted for this peer within the window
            self._alerted[ip] = now
            out.append({
                "event_type": "flood_detected",
                "timestamp": now.replace(tzinfo=None).isoformat(),
                "data": {
                    "target_ip": ip,
                    "connection_count": count,
                    "window_sec": self.window_sec,
                    "source": "agent-outbound",
                    "severity": "high" if count > 2 * self.threshold else "medium",
                },
            })
        return out
