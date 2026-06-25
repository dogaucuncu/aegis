"""Outbound alert notifications via a Slack-compatible webhook.

No-op unless `AEGIS_WEBHOOK_URL` is set. Delivery is fire-and-forget on a daemon thread so a
slow/unreachable webhook never blocks or breaks ingestion.
"""
import json
import logging
import threading
import urllib.request

from . import config

log = logging.getLogger("aegis.notify")


def _post(url: str, payload: dict) -> None:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        log.exception("webhook delivery failed")


def _deliver(url: str, payload: dict) -> None:
    threading.Thread(target=_post, args=(url, payload), daemon=True).start()


def notify_alert(rule_id: str, severity: str, title: str, description: str) -> None:
    """Send a webhook for a newly created alert (no-op when no webhook is configured)."""
    url = config.WEBHOOK_URL
    if not url:
        return
    payload = {
        "text": f":rotating_light: [{severity.upper()}] {title}\n{description}\n`{rule_id}`"
    }
    _deliver(url, payload)
