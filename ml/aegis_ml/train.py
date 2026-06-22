"""Train, evaluate and save both models.

Usage:
    python -m aegis_ml.train            # both
    python -m aegis_ml.train --only nids
"""
import argparse
import json
from pathlib import Path

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    classification_report,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from . import datasets

MODELS = Path(__file__).resolve().parent.parent / "models"
MODELS.mkdir(parents=True, exist_ok=True)


def _evaluate(model, X_test, y_test) -> dict:
    pred = model.predict(X_test)
    proba = model.predict_proba(X_test)[:, 1]
    return {
        "precision": round(precision_score(y_test, pred), 4),
        "recall": round(recall_score(y_test, pred), 4),
        "f1": round(f1_score(y_test, pred), 4),
        "roc_auc": round(roc_auc_score(y_test, proba), 4),
    }


def _train_one(name, X, y, feature_names, source, estimator):
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )
    model = Pipeline([("scaler", StandardScaler()), ("clf", estimator)])
    model.fit(X_train, y_train)
    metrics = _evaluate(model, X_test, y_test)

    bundle = {"model": model, "feature_names": list(feature_names), "source": source}
    joblib.dump(bundle, MODELS / f"{name}.joblib")
    (MODELS / f"{name}_metrics.json").write_text(
        json.dumps({"source": source, **metrics}, indent=2)
    )

    print(f"\n=== {name.upper()} model (data: {source}, n={len(y)}) ===")
    print(json.dumps(metrics, indent=2))
    print(classification_report(y_test, model.predict(X_test), digits=3))
    return metrics


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--only", choices=["nids", "phishing"])
    args = parser.parse_args()

    if args.only in (None, "nids"):
        X, y, names, src = datasets.load_nids()
        _train_one("nids", X, y, names, src, RandomForestClassifier(
            n_estimators=120, random_state=42, n_jobs=-1))

    if args.only in (None, "phishing"):
        X, y, names, src = datasets.load_phishing()
        _train_one("phishing", X, y, names, src, LogisticRegression(max_iter=1000))

    print(f"\nModels saved -> {MODELS}")


if __name__ == "__main__":
    main()
