"""Feature extraction.

- URL features (phishing): entirely from the string, offline.
- NIDS flow features: a name list (compatible with synthetic generation and the NSL-KDD numeric subset).
"""
import re
from typing import Dict, List
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "bank", "confirm",
    "signin", "password", "webscr", "ebayisapi", "gift", "free",
]
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

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
