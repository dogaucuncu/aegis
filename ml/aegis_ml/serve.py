"""Loading and scoring trained models (+ per-prediction explanations)."""
import hashlib
from pathlib import Path
from typing import Dict, List

import joblib
import pandas as pd

from . import features

MODELS = Path(__file__).resolve().parent.parent / "models"


def load(name: str):
    """name: 'nids' | 'phishing' | 'ueba' | 'dga'. Raises FileNotFoundError if not found."""
    path = MODELS / f"{name}.joblib"
    if not path.exists():
        raise FileNotFoundError(f"Model not found: {path} — train it first (python -m aegis_ml.train)")
    bundle = joblib.load(path)
    if isinstance(bundle, dict):
        bundle.setdefault("name", name)
        bundle["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
    return bundle


def _vector(bundle, feat: Dict[str, float]) -> List[float]:
    return [float(feat.get(n, 0)) for n in bundle["feature_names"]]


def _proba(bundle, feat: Dict[str, float]) -> float:
    names = bundle["feature_names"]
    row = pd.DataFrame([{n: float(feat.get(n, 0)) for n in names}])[names]
    return float(bundle["model"].predict_proba(row)[0][1])


def explain(bundle, feat: Dict[str, float], top: int = 3) -> List[Dict]:
    """Per-prediction top features: model importance x this instance's scaled magnitude.

    Dependency-free (no SHAP): for a StandardScaler+estimator pipeline it weights each global
    feature importance (tree) or |coef| (linear) by how far this instance sits from the mean.
    """
    names = bundle["feature_names"]
    vec = _vector(bundle, feat)
    model = bundle["model"]
    scaled, clf = vec, model
    try:
        scaler = model.named_steps["scaler"]
        clf = model.named_steps["clf"]
        # Pass a named DataFrame so sklearn doesn't warn about missing feature names.
        scaled = list(scaler.transform(pd.DataFrame([dict(zip(names, vec))])[names])[0])
    except (AttributeError, KeyError):
        pass
    if hasattr(clf, "feature_importances_"):
        importance = list(clf.feature_importances_)
    elif hasattr(clf, "coef_"):
        importance = [abs(c) for c in clf.coef_[0]]
    else:
        importance = [0.0] * len(names)
    ranked = sorted(
        ({"feature": names[i], "value": round(vec[i], 3),
          "weight": round(float(importance[i]) * abs(float(scaled[i])), 4)}
         for i in range(len(names))),
        key=lambda d: d["weight"], reverse=True,
    )
    return ranked[:top]


def score_url(bundle, url: str) -> Dict:
    feat = features.url_features(url)
    proba = _proba(bundle, feat)
    return {"label": "phishing" if proba >= 0.5 else "benign", "score": round(proba, 4),
            "top_features": explain(bundle, feat)}


def score_flow(bundle, flow: Dict[str, float]) -> Dict:
    proba = _proba(bundle, flow)
    return {"label": "attack" if proba >= 0.5 else "normal", "score": round(proba, 4),
            "top_features": explain(bundle, flow)}


def score_login(bundle, rec: Dict[str, float]) -> Dict:
    feat = features.login_features(rec)
    proba = _proba(bundle, feat)
    return {"label": "anomalous" if proba >= 0.5 else "normal", "score": round(proba, 4),
            "top_features": explain(bundle, feat)}


def score_domain(bundle, domain: str) -> Dict:
    feat = features.domain_features(domain)
    proba = _proba(bundle, feat)
    return {"label": "dga" if proba >= 0.5 else "benign", "score": round(proba, 4),
            "top_features": explain(bundle, feat)}
