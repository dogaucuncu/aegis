"""Aegis ML microservice — NIDS + phishing scoring API.

Run:  uvicorn service:app --port 8001   (from the ml/ directory)
Train the models first:  python -m aegis_ml.train
"""
from contextlib import asynccontextmanager
from typing import Dict, Optional

from aegis_ml import serve
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

_models: Dict[str, Optional[dict]] = {"nids": None, "phishing": None, "ueba": None, "dga": None}


@asynccontextmanager
async def lifespan(app: FastAPI):
    for name in _models:
        try:
            _models[name] = serve.load(name)
        except FileNotFoundError:
            _models[name] = None
    yield


app = FastAPI(title="Aegis ML Engine", version="0.1.0", lifespan=lifespan)


class UrlIn(BaseModel):
    url: str


class FlowIn(BaseModel):
    features: Dict[str, float]


class LoginIn(BaseModel):
    context: Dict[str, float]


class DomainIn(BaseModel):
    domain: str


@app.get("/health")
def health():
    return {
        "status": "ok",
        "models": {
            n: (None if b is None else b.get("source")) for n, b in _models.items()
        },
    }


@app.get("/model-info")
def model_info():
    """Version + provenance of each loaded model (hash, train date, sample count, metrics)."""
    out: Dict[str, Optional[dict]] = {}
    for name, b in _models.items():
        out[name] = None if b is None else {
            "source": b.get("source"),
            "trained_at": b.get("trained_at"),
            "n_samples": b.get("n_samples"),
            "n_features": len(b.get("feature_names", [])),
            "sha256": b.get("sha256"),
            "metrics": b.get("metrics"),
        }
    return out


@app.post("/score/url")
def score_url(body: UrlIn):
    if _models["phishing"] is None:
        raise HTTPException(503, "phishing model not loaded — train it first")
    return serve.score_url(_models["phishing"], body.url)


@app.post("/score/flow")
def score_flow(body: FlowIn):
    if _models["nids"] is None:
        raise HTTPException(503, "nids model not loaded — train it first")
    return serve.score_flow(_models["nids"], body.features)


@app.post("/score/login")
def score_login(body: LoginIn):
    if _models["ueba"] is None:
        raise HTTPException(503, "ueba model not loaded — train it first")
    return serve.score_login(_models["ueba"], body.context)


@app.post("/score/domain")
def score_domain(body: DomainIn):
    if _models["dga"] is None:
        raise HTTPException(503, "dga model not loaded — train it first")
    return serve.score_domain(_models["dga"], body.domain)
