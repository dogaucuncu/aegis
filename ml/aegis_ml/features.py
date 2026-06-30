"""Feature extraction.

- URL features (phishing): entirely from the string, offline.
- NIDS flow features: a name list (compatible with synthetic generation and the NSL-KDD numeric subset).
"""
import math
import re
from collections import Counter
from typing import Dict, List
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "bank", "confirm",
    "signin", "password", "webscr", "ebayisapi", "gift", "free",
]
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_VOWELS = set("aeiou")

URL_FEATURES: List[str] = [
    "url_length", "num_dots", "num_hyphens", "num_at", "num_digits",
    "has_ip", "is_http", "num_subdomains", "has_suspicious_word",
    "path_length", "num_params",
]

# Flow features compatible with synthetic generation and the NSL-KDD numeric subset
NIDS_FEATURES: List[str] = [
    "duration", "src_bytes", "dst_bytes", "count", "srv_count",
    "serror_rate", "same_srv_rate", "dst_host_count",
]

# UEBA login-behavior features (aggregated per login context window)
LOGIN_FEATURES: List[str] = [
    "failed_count", "hour", "is_night", "num_ips", "attempt_rate", "distinct_users",
]

# DGA (algorithmically generated C2 domains) — string statistics of the registrable label.
DGA_FEATURES: List[str] = [
    "length", "entropy", "digit_ratio", "vowel_ratio", "consonant_ratio",
    "max_consonant_run", "unique_char_ratio", "num_subdomains",
]


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def domain_features(domain: str) -> Dict[str, float]:
    """String-statistics of a domain's second-level label (random DGA names score high entropy)."""
    host = domain.lower().strip().split("/")[0]
    parts = host.split(".")
    label = parts[-2] if len(parts) >= 2 else parts[0]
    n = max(len(label), 1)
    digits = sum(c.isdigit() for c in label)
    vowels = sum(1 for c in label if c in _VOWELS)
    consonants = sum(1 for c in label if c.isalpha() and c not in _VOWELS)
    run = best = 0
    for c in label:
        if c.isalpha() and c not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return {
        "length": float(len(label)),
        "entropy": _shannon_entropy(label),
        "digit_ratio": digits / n,
        "vowel_ratio": vowels / n,
        "consonant_ratio": consonants / n,
        "max_consonant_run": float(best),
        "unique_char_ratio": len(set(label)) / n,
        "num_subdomains": float(max(0, len(parts) - 2)),
    }


def login_features(rec: Dict[str, float]) -> Dict[str, float]:
    """Features describing a login context (counts/timing/spread) for UEBA anomaly scoring."""
    hour = float(rec.get("hour", 12))
    return {
        "failed_count": float(rec.get("failed_count", 0)),
        "hour": hour,
        "is_night": float(1 if hour < 6 or hour >= 22 else 0),
        "num_ips": float(rec.get("num_ips", 1)),
        "attempt_rate": float(rec.get("attempt_rate", 1.0)),
        "distinct_users": float(rec.get("distinct_users", 1)),
    }


def url_features(url: str) -> Dict[str, float]:
    parsed = urlparse(url if "://" in url else "http://" + url)
    host = parsed.hostname or ""
    return {
        "url_length": len(url),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_at": url.count("@"),
        "num_digits": sum(c.isdigit() for c in url),
        "has_ip": int(bool(_IP_RE.match(host))),
        "is_http": int(parsed.scheme != "https"),
        "num_subdomains": max(0, host.count(".") - 1),
        "has_suspicious_word": int(any(w in url.lower() for w in SUSPICIOUS_WORDS)),
        "path_length": len(parsed.path),
        "num_params": len(parsed.query.split("&")) if parsed.query else 0,
    }


def to_vector(feat: Dict[str, float], names: List[str]) -> List[float]:
    """Converts a named feature dict into a vector following a fixed order."""
    return [float(feat.get(n, 0)) for n in names]
