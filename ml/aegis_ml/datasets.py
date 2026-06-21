"""Hibrit veri seti yükleyici: gerçek veri varsa onu, yoksa sentetiği kullanır.

Gerçek veri (opsiyonel):
  ml/data/phishing.csv         sütunlar: url,label (1=phishing, 0=benign)
  ml/data/nsl_kdd_train.txt    NSL-KDD formatı (numeric alt küme kullanılır)
"""
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd

from . import features

DATA = Path(__file__).resolve().parent.parent / "data"
_RNG = np.random.default_rng(42)

# NSL-KDD 41 sütun adı (numeric alt kümeyi seçmek için)
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
    # Normal trafik: düşük bayt/sayım, düşük hata oranı, yüksek same_srv_rate
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
    # Saldırı trafiği: yüksek sayım/hata (tarama/DoS imzası), düşük same_srv_rate
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
    # Gerçekçilik: ~%7 etiket gürültüsü (mükemmel ayrışmayı önler)
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


def _synthetic_phishing(n: int = 1000) -> pd.DataFrame:
    half = n // 2
    rows = []
    for _ in range(half):
        d = _RNG.choice(_GOOD_DOMAINS)
        p = _RNG.choice(_GOOD_PATHS)
        # %20 örtüşen vaka: meşru ama "login/signin" içeren benign (örn. accounts.google.com/login)
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
            # %15 örtüşen vaka: daha "temiz" görünen phishing (https + .com)
            brand = _RNG.choice(["paypal", "apple", "secure-bank"])
            url = f"https://{brand}-{word}.com/{word}"
        rows.append((url, 1))
    df = pd.DataFrame(rows, columns=["url", "label"])
    # Gerçekçilik: ~%4 etiket gürültüsü
    flip = _RNG.random(len(df)) < 0.04
    df.loc[flip, "label"] = 1 - df.loc[flip, "label"]
    return df
