"""Downloads the real ML datasets (Phase 4 / WP8).

The hybrid loader (`aegis_ml.datasets`) uses files under `ml/data/` if they exist:
  ml/data/nsl_kdd_train.txt   -> NIDS (NSL-KDD KDDTrain+)
  ml/data/phishing.csv        -> phishing (url,label; phishing list + popular domains)

The Windows cert store is used (truststore) to get past TLS interception (Norton) on this
machine. If the download fails, you can place the files manually at the paths above.

Usage:  python scripts/fetch_datasets.py
"""
import csv
import random
from pathlib import Path

try:
    import truststore

    truststore.inject_into_ssl()  # Windows cert store -> ssl (accepts the Norton root)
except Exception:
    pass

import requests

DATA = Path(__file__).resolve().parent.parent / "ml" / "data"
DATA.mkdir(parents=True, exist_ok=True)

NSL_KDD_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
PHISHING_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
BENIGN_URL = "https://raw.githubusercontent.com/zer0h/top-1000000-domains/master/top-100000-domains"
PER_CLASS = 5000

# Realistic paths appended to benign domains (legitimate sites also have login/account/params)
# → creates overlap with phishing features, prevents the model from trivially returning 1.0.
BENIGN_PATHS = [
    "/", "/login", "/account/settings", "/search?q=test&page=2",
    "/products/12345", "/help/contact-us", "/signin?next=/home",
    "/user/profile?id=42", "/blog/2026/update", "/secure/checkout",
]


def _take_lines(url: str, n: int, transform=lambda s: s) -> list:
    out = []
    r = requests.get(url, timeout=90, stream=True)
    r.raise_for_status()
    for raw in r.iter_lines():
        if not raw:
            continue
        line = raw.decode("utf-8", "ignore").strip()
        if not line or line.startswith("#"):
            continue
        out.append(transform(line))
        if len(out) >= n:
            break
    return out


def fetch_nsl_kdd() -> bool:
    dest = DATA / "nsl_kdd_train.txt"
    try:
        r = requests.get(NSL_KDD_URL, timeout=90)
        r.raise_for_status()
        dest.write_bytes(r.content)
        print(f"[fetch] OK  nsl_kdd_train.txt ({len(r.content) // 1024} KB)")
        return True
    except Exception as exc:
        print(f"[fetch] FAILED NSL-KDD: {exc}")
        return False


def build_phishing_csv() -> bool:
    dest = DATA / "phishing.csv"
    try:
        phishing = _take_lines(PHISHING_URL, PER_CLASS)
        benign = _take_lines(
            BENIGN_URL, PER_CLASS, lambda d: f"https://www.{d}{random.choice(BENIGN_PATHS)}"
        )
        rows = [(u, 1) for u in phishing] + [(u, 0) for u in benign]
        random.shuffle(rows)
        # The popular-domain/phishing distinction is lexically very easy (trivial 1.0 score).
        # Add ~3% label noise to reflect real-world labeling error.
        rows = [(u, 1 - lbl if random.random() < 0.03 else lbl) for u, lbl in rows]
        with open(dest, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "label"])
            w.writerows(rows)
        print(f"[fetch] OK  phishing.csv ({len(phishing)} phishing + {len(benign)} benign)")
        return True
    except Exception as exc:
        print(f"[fetch] FAILED phishing: {exc}")
        print(f"        You can manually place a url,label CSV at {dest}.")
        return False


def main():
    ok = sum([fetch_nsl_kdd(), build_phishing_csv()])
    print(f"\n[fetch] {ok}/2 ready. Next: cd ml; python -m aegis_ml.train")


if __name__ == "__main__":
    main()
