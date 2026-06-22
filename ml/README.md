# aegis-ml — ML engine (NIDS + phishing)

NIDS network-anomaly and phishing URL classification; scored as a separate FastAPI microservice.

## Running
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m aegis_ml.train             # train the models -> models/*.joblib
uvicorn service:app --port 8001      # /health /score/url /score/flow
```

## Hybrid data
If real data exists under `ml/data/` it is used, otherwise the synthetic data is used:
- `nsl_kdd_train.txt` (NSL-KDD) — NIDS
- `phishing.csv` (columns: url,label) — phishing

Download the real data: `python scripts/fetch_datasets.py` (using the Windows cert store / truststore;
builds `phishing.csv` by combining the [mitchellkrogza] phishing feed with popular domains).
With real data: NIDS ~0.99 F1, phishing ~0.97 F1. (Since the popular-domain/phishing distinction is
lexically very easy, ~3% label noise is added for a realistic score.)

## Structure
- `aegis_ml/features.py` — URL + flow feature extraction
- `aegis_ml/datasets.py` — hybrid loader (+ synthetic generator, with label noise)
- `aegis_ml/train.py` — training + evaluation (`models/*_metrics.json`)
- `aegis_ml/serve.py`, `service.py` — model loading + scoring API
