"""ML tests: feature extraction, model quality, scoring."""
from aegis_ml import adversarial, datasets, features, serve
from sklearn.ensemble import RandomForestClassifier
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


def test_login_features():
    f = features.login_features(
        {"failed_count": 20, "hour": 3, "num_ips": 5, "attempt_rate": 9, "distinct_users": 6})
    assert f["is_night"] == 1 and f["failed_count"] == 20
    assert features.login_features({"hour": 14})["is_night"] == 0


def _train_ueba():
    X, y, names, _src = datasets.load_login()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=0, stratify=y)
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=80, random_state=0)),
    ]).fit(Xtr, ytr)
    return {"model": model, "feature_names": names}, f1_score(yte, model.predict(Xte))


def test_ueba_model_quality_and_scoring():
    bundle, f1 = _train_ueba()
    assert f1 > 0.85
    anomalous = {"failed_count": 25, "hour": 3, "num_ips": 6, "attempt_rate": 10, "distinct_users": 7}
    normal = {"failed_count": 0, "hour": 14, "num_ips": 1, "attempt_rate": 1, "distinct_users": 1}
    assert serve.score_login(bundle, anomalous)["label"] == "anomalous"
    assert serve.score_login(bundle, normal)["label"] == "normal"


def test_login_dataset_loads():
    X, y, names, src = datasets.load_login()
    assert src in ("synthetic", "real(csv)")
    assert 0 < y.mean() < 1
    assert list(X.columns) == names


# --- Milestone 5: DGA detector, explainability, adversarial ---
def test_domain_features_distinguish_dga():
    rand = features.domain_features("kq3x9zr7vw2htb8s.top")   # high entropy, long, few vowels
    dictw = features.domain_features("securecloud.com")        # pronounceable
    assert rand["entropy"] > dictw["entropy"]
    assert rand["vowel_ratio"] < dictw["vowel_ratio"]


def _train_dga():
    X, y, names, _src = datasets.load_dga()
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.25, random_state=0, stratify=y)
    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=80, random_state=0)),
    ]).fit(Xtr, ytr)
    return {"model": model, "feature_names": names}, f1_score(yte, model.predict(Xte))


def test_dga_model_quality_and_scoring():
    bundle, f1 = _train_dga()
    assert f1 > 0.9
    assert serve.score_domain(bundle, "kq3x9zr7vw2htb8s.top")["label"] == "dga"
    assert serve.score_domain(bundle, "securecloud.com")["label"] == "benign"


def test_dga_dataset_loads():
    X, y, names, src = datasets.load_dga()
    assert src in ("synthetic", "real(csv)")
    assert 0 < y.mean() < 1
    assert list(X.columns) == names


def test_score_includes_explanation():
    model, names, _f1 = _train_phishing()
    bundle = {"model": model, "feature_names": names}
    out = serve.score_url(bundle, "http://paypal.secure-login.verify.tk/login")
    assert "top_features" in out and len(out["top_features"]) == 3
    assert all({"feature", "value", "weight"} <= set(tf) for tf in out["top_features"])


def test_adversarial_evasion_report_structure():
    model, names, _f1 = _train_phishing()
    bundle = {"model": model, "feature_names": names}
    report = adversarial.evasion_rate(bundle, [
        "http://paypal.secure-login.verify.tk/index",
        "http://192.0.2.55/account-confirm.php?cmd=login",
    ])
    assert set(report) == {"tested", "evaded", "evasion_rate", "robustness"}
    assert 0.0 <= report["evasion_rate"] <= 1.0
    assert round(report["evasion_rate"] + report["robustness"], 4) == 1.0


def test_ml_dga_and_evasion_rules(client):
    client.post("/api/ingest", json={"events": [
        {"agent_id": "ml-engine", "event_type": "dga_detection",
         "data": {"domain": "kq3x9zr7vw2htb8s.top", "score": 0.95}},
        {"agent_id": "ml-engine", "event_type": "ml_evasion",
         "data": {"model": "phishing", "evasion_rate": 0.5, "tested": 8, "evaded": 4}},
    ]})
    ids = {a["rule_id"] for a in client.get("/api/alerts").json()}
    assert "ml-dga" in ids and "ml-evasion" in ids
