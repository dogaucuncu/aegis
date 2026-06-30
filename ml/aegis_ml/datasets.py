"""Hybrid dataset loader: uses real data if available, otherwise synthetic.

Real data (optional):
  ml/data/phishing.csv         columns: url,label (1=phishing, 0=benign)
  ml/data/nsl_kdd_train.txt    NSL-KDD format (a numeric subset is used)
"""
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd

from . import features

DATA = Path(__file__).resolve().parent.parent / "data"
_RNG = np.random.default_rng(42)

# NSL-KDD 41 column names (to select the numeric subset)
_NSL_COLS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate",
    "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty",
]


# ---------------- NIDS ----------------
def load_nids() -> Tuple[pd.DataFrame, np.ndarray, List[str], str]:
    path = DATA / "nsl_kdd_train.txt"
    if path.exists():
        df = pd.read_csv(path, names=_NSL_COLS)
        X = df[features.NIDS_FEATURES].astype(float)
        y = (df["label"] != "normal").astype(int).to_numpy()
        return X, y, features.NIDS_FEATURES, "real(NSL-KDD)"
    return _synthetic_nids()


def _synthetic_nids(n: int = 2000) -> Tuple[pd.DataFrame, np.ndarray, List[str], str]:
    half = n // 2
    # Normal traffic: low bytes/count, low error rate, high same_srv_rate
    normal = {
        "duration": _RNG.exponential(2, half),
        "src_bytes": _RNG.normal(500, 150, half).clip(0),
        "dst_bytes": _RNG.normal(1500, 400, half).clip(0),
        "count": _RNG.poisson(5, half),
        "srv_count": _RNG.poisson(5, half),
        "serror_rate": _RNG.beta(1, 12, half),
        "same_srv_rate": _RNG.beta(9, 1, half),
        "dst_host_count": _RNG.normal(40, 15, half).clip(0),
    }
    # Attack traffic: high count/error (scan/DoS signature), low same_srv_rate
    attack = {
        "duration": _RNG.exponential(0.5, half),
        "src_bytes": _RNG.normal(120, 80, half).clip(0),
        "dst_bytes": _RNG.normal(80, 60, half).clip(0),
        "count": _RNG.poisson(120, half),
        "srv_count": _RNG.poisson(110, half),
        "serror_rate": _RNG.beta(7, 2, half),
        "same_srv_rate": _RNG.beta(1, 6, half),
        "dst_host_count": _RNG.normal(220, 30, half).clip(0),
    }
    df = pd.concat(
        [pd.DataFrame(normal), pd.DataFrame(attack)], ignore_index=True
    )[features.NIDS_FEATURES]
    y = np.concatenate([np.zeros(half, int), np.ones(half, int)])
    # Realism: ~7% label noise (prevents perfect separation)
    flip = _RNG.random(len(y)) < 0.07
    y = np.where(flip, 1 - y, y)
    return df, y, features.NIDS_FEATURES, "synthetic"


# ---------------- Phishing ----------------
def load_phishing() -> Tuple[pd.DataFrame, np.ndarray, List[str], str]:
    csv = DATA / "phishing.csv"
    if csv.exists():
        df = pd.read_csv(csv)
        source = "real(csv)"
    else:
        df = _synthetic_phishing()
        source = "synthetic"
    X = pd.DataFrame([features.url_features(u) for u in df["url"]])[features.URL_FEATURES]
    y = df["label"].astype(int).to_numpy()
    return X, y, features.URL_FEATURES, source


_GOOD_DOMAINS = [
    "google.com", "github.com", "wikipedia.org", "python.org", "microsoft.com",
    "amazon.com", "cloudflare.com", "stackoverflow.com", "mozilla.org", "apple.com",
]
_GOOD_PATHS = ["/", "/about", "/docs/index", "/search?q=test", "/user/profile", "/help"]
_BAD_WORDS = ["login", "verify", "secure-update", "account-confirm", "bank-signin", "free-gift"]
_BAD_TLDS = ["tk", "ml", "ga", "cf", "gq", "xyz", "top", "ru", "cn"]


# ---------------- UEBA login behavior ----------------
def load_login() -> Tuple[pd.DataFrame, np.ndarray, List[str], str]:
    """Hybrid loader for the UEBA login-anomaly model (real CSV if present, else synthetic).

    Real data (optional): ml/data/logins.csv with the LOGIN_FEATURES columns + a `label` column.
    """
    csv = DATA / "logins.csv"
    if csv.exists():
        df = pd.read_csv(csv)
        X = df[features.LOGIN_FEATURES].astype(float)
        y = df["label"].astype(int).to_numpy()
        return X, y, features.LOGIN_FEATURES, "real(csv)"
    return _synthetic_login()


def _synthetic_login(n: int = 2000) -> Tuple[pd.DataFrame, np.ndarray, List[str], str]:
    half = n // 2
    # Normal: few/zero failures, daytime, single IP, low rate, single user.
    normal = {
        "failed_count": _RNG.poisson(0.5, half),
        "hour": _RNG.integers(7, 21, half),
        "num_ips": np.ones(half, dtype=int),
        "attempt_rate": _RNG.normal(1.0, 0.3, half).clip(0.1),
        "distinct_users": np.ones(half, dtype=int),
    }
    # Anomalous: many failures (brute-force), night-time, several IPs, high rate, spray over users.
    anomalous = {
        "failed_count": _RNG.poisson(12, half).clip(1),
        "hour": _RNG.choice([0, 1, 2, 3, 4, 23], half),
        "num_ips": _RNG.integers(2, 8, half),
        "attempt_rate": _RNG.normal(8.0, 2.0, half).clip(1.0),
        "distinct_users": _RNG.integers(1, 10, half),
    }
    rows = pd.concat([pd.DataFrame(normal), pd.DataFrame(anomalous)], ignore_index=True)
    rows["is_night"] = ((rows["hour"] < 6) | (rows["hour"] >= 22)).astype(int)
    df = rows[features.LOGIN_FEATURES]
    y = np.concatenate([np.zeros(half, int), np.ones(half, int)])
    # Realism: ~6% label noise.
    flip = _RNG.random(len(y)) < 0.06
    y = np.where(flip, 1 - y, y)
    return df, y, features.LOGIN_FEATURES, "synthetic"


# ---------------- DGA (C2 domains) ----------------
_DGA_TLDS = ["com", "net", "org", "info", "biz", "top", "xyz", "ru"]
_BENIGN_WORDS = [
    "cloud", "secure", "mail", "shop", "news", "data", "tech", "home", "world", "center",
    "group", "online", "media", "service", "global", "system", "market", "health", "money",
    "studio", "design", "photo", "music", "video", "game", "travel", "food", "sport", "book",
]
_DGA_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


def load_dga() -> Tuple[pd.DataFrame, np.ndarray, List[str], str]:
    csv = DATA / "dga.csv"  # columns: domain,label (1=DGA, 0=benign)
    if csv.exists():
        df = pd.read_csv(csv)
        source = "real(csv)"
    else:
        df = _synthetic_dga()
        source = "synthetic"
    X = pd.DataFrame([features.domain_features(d) for d in df["domain"]])[features.DGA_FEATURES]
    y = df["label"].astype(int).to_numpy()
    return X, y, features.DGA_FEATURES, source


def _synthetic_dga(n: int = 2000) -> pd.DataFrame:
    half = n // 2
    rows = []
    # Benign: pronounceable dictionary compounds (+ optional digits).
    for _ in range(half):
        word = str(_RNG.choice(_BENIGN_WORDS))
        if _RNG.random() < 0.5:
            word += str(_RNG.choice(_BENIGN_WORDS))
        if _RNG.random() < 0.2:
            word += str(int(_RNG.integers(1, 99)))
        rows.append((f"{word}.{_RNG.choice(_DGA_TLDS[:5])}", 0))
    # DGA: high-entropy random alphanumeric labels.
    for _ in range(half):
        length = int(_RNG.integers(10, 22))
        label = "".join(_RNG.choice(list(_DGA_ALPHABET), length))
        rows.append((f"{label}.{_RNG.choice(_DGA_TLDS)}", 1))
    df = pd.DataFrame(rows, columns=["domain", "label"])
    flip = _RNG.random(len(df)) < 0.04  # ~4% label noise
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]
    return df


def _synthetic_phishing(n: int = 1000) -> pd.DataFrame:
    half = n // 2
    rows = []
    for _ in range(half):
        d = _RNG.choice(_GOOD_DOMAINS)
        p = _RNG.choice(_GOOD_PATHS)
        # 20% overlapping case: legitimate but "login/signin"-containing benign (e.g. accounts.google.com/login)
        if _RNG.random() < 0.2:
            sub = _RNG.choice(["accounts", "signin", "secure", "login"])
            rows.append((f"https://{sub}.{d}/login", 0))
        else:
            rows.append((f"https://www.{d}{p}", 0))
    for _ in range(half):
        word = _RNG.choice(_BAD_WORDS)
        tld = _RNG.choice(_BAD_TLDS)
        r = _RNG.random()
        if r < 0.35:
            host = f"{_RNG.integers(1,255)}.{_RNG.integers(0,255)}.{_RNG.integers(0,255)}.{_RNG.integers(1,255)}"
            url = f"http://{host}/{word}.php?cmd=login"
        elif r < 0.85:
            brand = _RNG.choice(["paypal", "apple", "bankofamerica", "ebay", "amazon"])
            url = f"http://{brand}.{word}.{_RNG.choice(_BAD_WORDS)}.{tld}/index"
        else:
            # 15% overlapping case: phishing that looks "cleaner" (https + .com)
            brand = _RNG.choice(["paypal", "apple", "secure-bank"])
            url = f"https://{brand}-{word}.com/{word}"
        rows.append((url, 1))
    df = pd.DataFrame(rows, columns=["url", "label"])
    # Realism: ~4% label noise
    flip = _RNG.random(len(df)) < 0.04
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]
    return df
