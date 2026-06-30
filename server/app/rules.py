"""Rule engine — loads and evaluates YAML (Sigma-like) detection rules.

The rules live in `detection_rules/*.yml`. Each rule takes an Event and returns 0+ Alerts.
Supported ops: in, contains_any, equals, len_gte ; optional window (window-threshold).
"""
import datetime as dt
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from sqlalchemy.orm import Session

from . import models
from .utils import now_utc

RULES_DIR = Path(__file__).resolve().parent / "detection_rules"
_PLACEHOLDER = re.compile(r"\{([^}]+)\}")


def _load_rules() -> List[dict]:
    rules: List[dict] = []
    for path in sorted(RULES_DIR.glob("*.yml")):
        with open(path, encoding="utf-8") as fh:
            rules.extend(yaml.safe_load(fh) or [])
    return rules


_RULES = _load_rules()


def reload_rules() -> int:
    """Hot-reload the YAML rules without restarting the server (threat-hunting / tuning)."""
    global _RULES
    _RULES = _load_rules()
    return len(_RULES)


def _get(event: models.Event, path: str, extra: Optional[Dict] = None) -> Any:
    if extra and path in extra:
        return extra[path]
    parts = path.split(".")
    if parts[0] == "data":
        val: Any = event.data or {}
        for key in parts[1:]:
            if isinstance(val, dict):
                val = val.get(key)
            else:
                return None
        return val
    return getattr(event, parts[0], None)


def _check(cond: dict, event: models.Event) -> bool:
    field = _get(event, cond["field"])
    if field is None:
        return False
    op = cond["op"]
    value = cond.get("value")
    lower = cond.get("lower", False)
    if op == "equals":
        return field == value
    if op == "in":
        f = str(field).lower() if lower else field
        vals = [str(v).lower() for v in value] if lower else value
        return f in vals
    if op == "contains_any":
        f = str(field).lower() if lower else str(field)
        toks = [str(v).lower() for v in value] if lower else value
        return any(t in f for t in toks)
    if op == "len_gte":
        return isinstance(field, list) and len(field) >= value
    if op in ("gte", "lt"):
        try:
            f, v = float(field), float(value)
        except (TypeError, ValueError):
            return False
        return f >= v if op == "gte" else f < v
    if op == "regex_match":
        flags = re.IGNORECASE if lower else 0
        return re.search(str(value), str(field), flags) is not None
    return False


def _interpolate(template: str, event: models.Event, extra: Dict) -> str:
    def repl(match: "re.Match") -> str:
        val = _get(event, match.group(1), extra)
        return str(val) if val is not None else ""

    return _PLACEHOLDER.sub(repl, template)


def _window_count(rule: dict, event: models.Event, db: Session) -> Optional[int]:
    win = rule["window"]
    start = now_utc() - dt.timedelta(seconds=win["seconds"])
    q = db.query(models.Event).filter(
        models.Event.event_type == event.event_type,
        models.Event.timestamp >= start,
    )
    if win.get("group_by", "agent_id") == "agent_id":
        q = q.filter(models.Event.agent_id == event.agent_id)
    count = q.count()
    return count if count >= win["threshold"] else None


def _correlation_count(rule: dict, event: models.Event, db: Session) -> Optional[int]:
    """Count prior events that, together with this triggering event, form an attack sequence.

    A `correlation` rule fires when >= `threshold` prior events of `prior_event_type` (matching
    `prior_conditions` and sharing the `group_by` value) occurred within `window_seconds` before
    the triggering event. Classic use: a successful login preceded by many failed attempts.
    """
    corr = rule["correlation"]
    window = corr.get("window_seconds", 120)
    threshold = corr.get("threshold", 5)
    prior_type = corr.get("prior_event_type", event.event_type)
    group_by = corr.get("group_by")
    prior_conditions = corr.get("prior_conditions", [])

    start = now_utc() - dt.timedelta(seconds=window)
    target_group = _get(event, group_by) if group_by else None

    # Volumes are low (educational SOC), so filter by type/time in SQL and the rest in Python —
    # this keeps JSON `group_by` portable across SQLite and PostgreSQL.
    candidates = (
        db.query(models.Event)
        .filter(models.Event.event_type == prior_type, models.Event.timestamp >= start)
        .all()
    )
    count = 0
    for ev in candidates:
        if ev.id == event.id:
            continue
        if group_by and _get(ev, group_by) != target_group:
            continue
        if all(_check(c, ev) for c in prior_conditions):
            count += 1
    return count if count >= threshold else None


def evaluate(event: models.Event, db: Session) -> List[models.Alert]:
    alerts: List[models.Alert] = []
    for rule in _RULES:
        if rule.get("event_type") and rule["event_type"] != event.event_type:
            continue
        if not all(_check(c, event) for c in rule.get("conditions", [])):
            continue

        extra: Dict[str, Any] = {}
        if rule.get("type") == "correlation":
            count = _correlation_count(rule, event, db)
            if count is None:
                continue
            extra["prior_count"] = count
        if "window" in rule:
            count = _window_count(rule, event, db)
            if count is None:
                continue
            extra["window_count"] = count

        severity = rule.get("severity") or _get(event, rule.get("severity_field", "")) or "medium"
        if rule.get("id_prefix"):
            rule_id = rule["id_prefix"] + str(_get(event, rule["id_field"]))
        else:
            rule_id = rule["id"]

        title = _interpolate(rule.get("title", ""), event, extra)
        if "dedup" in rule:
            dedup_key = _interpolate(rule["dedup"], event, extra)
        else:
            dedup_key = f"{rule_id}|{event.agent_id}|{title}"

        # MITRE tags may be static on the rule, or pulled per-event (e.g. the generic vuln rule
        # reads the tactic/technique the scanner attached to each finding).
        tactic = rule.get("tactic") or _get(event, rule.get("tactic_field", ""))
        technique = rule.get("technique") or _get(event, rule.get("technique_field", ""))

        alerts.append(
            models.Alert(
                rule_id=rule_id,
                severity=str(severity),
                title=title,
                description=_interpolate(rule.get("description", ""), event, extra),
                dedup_key=dedup_key,
                tactic=tactic,
                technique=technique,
            )
        )
    return alerts
