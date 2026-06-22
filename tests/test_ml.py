"""ML tests: feature extraction, model quality, scoring."""
from aegis_ml import datasets, features, serve
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


def test_url_features():
    f = features.url_features("http://192.0.2.1/login")
    assert f["has_ip"] == 1 and f["is_http"] == 1 and f["has_suspicious_word"] == 1
    g = features.url_features("https://www.google.com/")
    assert g["has_ip"] == 0 and g["is_http"] == 0


def _train_phishing():
    X, y, names, _src = datasets.load_phishing()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=0, stratify=y)
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000)),
    ]).fit(Xtr, ytr)
    return model, names, f1_score(yte, model.predict(Xte))


def test_phishing_model_quality():
    _model, _names, f1 = _train_phishing()
    assert f1 > 0.85


def test_phishing_scoring():
    model, names, _f1 = _train_phishing()
    bundle = {"model": model, "feature_names": names}
    assert serve.score_url(bundle, "http://paypal.secure-login.verify.tk/login")["label"] == "phishing"
    assert serve.score_url(bundle, "https://www.github.com/user/repo")["label"] == "benign"


def test_nids_dataset_loads():
    X, y, names, src = datasets.load_nids()
    assert src in ("synthetic", "real(NSL-KDD)")
    assert 0 < y.mean() < 1  # both classes are present
    assert list(X.columns) == names
