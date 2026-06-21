"""Aegis ML mikroservisi — NIDS + phishing skorlama API'si.

Çalıştır:  uvicorn service:app --port 8001   (ml/ dizininden)
Önce modelleri eğit:  python -m aegis_ml.train
"""
from contextlib import asynccontextmanager
from typing import Dict, Optional

from aegis_ml import serve
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

_models: Dict[str, Optional[dict]] = {"nids": None, "phishing": None}


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


@app.get("/health")
def health():
    return {
        "status": "ok",
        "models": {
            n: (None if b is None else b.get("source")) for n, b in _models.items()
        },
    }


@app.post("/score/url")
def score_url(body: UrlIn):
    if _models["phishing"] is None:
        raise HTTPException(503, "phishing modeli yuklu degil — once egitin")
    return serve.score_url(_models["phishing"], body.url)


@app.post("/score/flow")
def score_flow(body: FlowIn):
    if _models["nids"] is None:
        raise HTTPException(503, "nids modeli yuklu degil — once egitin")
    return serve.score_flow(_models["nids"], body.features)
