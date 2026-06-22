"""Sends collected events to the Aegis server.

Phase 0: plain HTTP. mTLS + AES-GCM + signing will be added in Phase 2 (aegis-crypto).
"""
from typing import Dict, List

import requests


class Sender:
    def __init__(self, server_url: str, agent_id: str, timeout: float = 10.0):
        self.ingest_url = server_url.rstrip("/") + "/api/ingest"
        self.agent_id = agent_id
        self.timeout = timeout

    def send(self, events: List[Dict]) -> int:
        if not events:
            return 0
        payload = {
            "events": [
                {
                    "agent_id": self.agent_id,
                    "event_type": e["event_type"],
                    "timestamp": e.get("timestamp"),
                    "data": e.get("data", {}),
                }
                for e in events
            ]
        }
        resp = requests.post(self.ingest_url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json().get("ingested", 0)
