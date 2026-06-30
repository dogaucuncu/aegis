"""Automated response (Milestone 6): auto-block the source IP of selected high-severity alerts.

A small policy engine called right after an alert is created. When `AEGIS_AUTO_BLOCK=1` and the
alert's rule is in the policy set, the event's source IP is added to the blocklist (persisted +
mirrored in memory). `BlocklistMiddleware` then rejects further requests from that IP with 403.
Every block is written to the audit log.
"""
import logging

from sqlalchemy.orm import Session

from . import config, models
from .utils import now_utc

audit = logging.getLogger("aegis.audit")

# In-memory mirror of the blocklist so the middleware avoids a DB hit per request.
_blocked: set[str] = set()
# IPs we never auto-block (our own tools / placeholders).
_SAFE_IPS = {"scanner", "unknown", "127.0.0.1", "::1", "testclient"}


def load_blocked(db: Session) -> int:
    _blocked.clear()
    _blocked.update(ip for (ip,) in db.query(models.BlockedIP.ip).all())
    return len(_blocked)


def is_blocked(ip: str) -> bool:
    return ip in _blocked


def list_blocked() -> list:
    return sorted(_blocked)


def block_ip(db: Session, ip: str, reason: str, rule_id: str | None = None) -> bool:
    if not ip or ip in _blocked:
        return False
    db.merge(models.BlockedIP(ip=ip, reason=reason, rule_id=rule_id, created_at=now_utc()))
    _blocked.add(ip)
    audit.info("auto_block ip=%s reason=%s rule=%s", ip, reason, rule_id or "-")
    return True


def unblock_ip(db: Session, ip: str) -> bool:
    obj = db.get(models.BlockedIP, ip)
    if obj is not None:
        db.delete(obj)
    removed = ip in _blocked
    _blocked.discard(ip)
    if removed:
        audit.info("unblock ip=%s", ip)
    return removed


def consider(db: Session, alert: models.Alert, event: models.Event) -> None:
    """Apply the auto-block policy for a freshly created alert (no-op unless enabled)."""
    if not config.AUTO_BLOCK or alert.rule_id not in config.AUTO_BLOCK_RULES:
        return
    data = event.data or {}
    ip = data.get("source_ip") or data.get("target_ip")
    if ip and ip not in _SAFE_IPS:
        block_ip(db, ip, reason=alert.rule_id, rule_id=alert.rule_id)
