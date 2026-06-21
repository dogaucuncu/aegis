# aegis-ml — ML motoru (NIDS + phishing)

NIDS ağ-anomali ve phishing URL sınıflandırma; ayrı bir FastAPI mikroservisi olarak skorlar.

## Çalıştırma
```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m aegis_ml.train             # modelleri eğit -> models/*.joblib
uvicorn service:app --port 8001      # /health /score/url /score/flow
```

## Hibrit veri
`ml/data/` altında gerçek veri varsa onu, yoksa sentetiği kullanır:
- `nsl_kdd_train.txt` (NSL-KDD) — NIDS
- `phishing.csv` (sütunlar: url,label) — phishing

Gerçek veriyi indir: `python scripts/fetch_datasets.py` (Windows cert store / truststore ile;
NSL-KDD + phishing feed'i [mitchellkrogza] ile popüler domainleri birleştirip `phishing.csv` kurar).
Gerçek veriyle NIDS ~0.99 F1, phishing ~0.97 F1. (Popüler-domain/phishing ayrımı leksik olarak
çok kolay olduğundan, gerçekçi skor için ~%3 etiket gürültüsü eklenir.)

## Yapı
- `aegis_ml/features.py` — URL + akış özellik çıkarımı
- `aegis_ml/datasets.py` — hibrit yükleyici (+ sentetik üreteç, etiket gürültülü)
- `aegis_ml/train.py` — eğitim + değerlendirme (`models/*_metrics.json`)
- `aegis_ml/serve.py`, `service.py` — model yükleme + skorlama API'si
