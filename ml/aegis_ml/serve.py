"""Eğitilmiş modelleri yükleme ve skorlama."""
from pathlib import Path
from typing import Dict

import joblib
import pandas as pd

from . import features

MODELS = Path(__file__).resolve().parent.parent / "models"


def load(name: str):
    """name: 'nids' veya 'phishing'. Bulunamazsa FileNotFoundError."""
    path = MODELS / f"{name}.joblib"
    if not path.exists():
        raise FileNotFoundError(f"Model yok: {path} — once egitin (train_*.py)")
    return joblib.load(path)


def _proba(bundle, feat: Dict[str, float]) -> float:
    names = bundle["feature_names"]
    # Model DataFrame (kolon adlı) üzerinde eğitildi; aynı şekilde besle.
    row = pd.DataFrame([{n: float(feat.get(n, 0)) for n in names}])[names]
    return float(bundle["model"].predict_proba(row)[0][1])


def score_url(bundle, url: str) -> Dict:
    proba = _proba(bundle, features.url_features(url))
    return {"label": "phishing" if proba >= 0.5 else "benign", "score": round(proba, 4)}


def score_flow(bundle, flow: Dict[str, float]) -> Dict:
    proba = _proba(bundle, flow)
    return {"label": "attack" if proba >= 0.5 else "normal", "score": round(proba, 4)}
