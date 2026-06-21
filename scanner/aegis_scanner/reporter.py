"""Tarama bulgularını Aegis sunucusuna olay olarak gönderir."""
from typing import Dict, List

import requests


class Reporter:
    def __init__(self, server_url: str, agent_id: str = "scanner-01", timeout: float = 10.0):
        self.url = server_url.rstrip("/") + "/api/ingest"
        self.agent_id = agent_id
        self.timeout = timeout

    def send(self, events: List[Dict]) -> int:
        """events: [{event_type, data}, ...]"""
        if not events:
            return 0
        payload = {
            "events": [
                {"agent_id": self.agent_id, "event_type": e["event_type"], "data": e["data"]}
                for e in events
            ]
        }
        resp = requests.post(self.url, json=payload, timeout=self.timeout)
        resp.raise_for_status()
        return resp.json().get("ingested", 0)
