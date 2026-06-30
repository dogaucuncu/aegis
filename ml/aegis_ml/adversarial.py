"""Adversarial robustness probes (test your OWN models).

Generates evasion variants of phishing URLs — small, label-preserving edits an attacker would
try (upgrade to https, prepend a legitimate-looking host, append benign query params) — and
measures how often the classifier flips from 'phishing' to 'benign'. A high evasion rate is a
robustness gap; `scripts/adversarial_test.py` reports it and raises an `ml_evasion` alert.
"""
from typing import Dict, List

from . import serve


def evasion_variants(url: str) -> List[str]:
    host = url.split("://", 1)[-1]
    return [
        "https://" + host,                               # http -> https
        "https://accounts.google.com." + host,           # legitimate-looking prefix
        url + ("&" if "?" in url else "?") + "utm=login&ref=secure",  # benign params
        url.replace(".", "-", 1),                         # split a dotted label
    ]


def evasion_rate(bundle, phishing_urls: List[str]) -> Dict:
    """Of the URLs the model originally flags as phishing, how many evade after a tweak?"""
    tested = evaded = 0
    for url in phishing_urls:
        if serve.score_url(bundle, url)["label"] != "phishing":
            continue  # only probe samples the model gets right to begin with
        for variant in evasion_variants(url):
            tested += 1
            if serve.score_url(bundle, variant)["label"] != "phishing":
                evaded += 1
    rate = round(evaded / tested, 4) if tested else 0.0
    return {"tested": tested, "evaded": evaded, "evasion_rate": rate, "robustness": round(1 - rate, 4)}
