# Aegis ML engine. The build context is the repo root:
#   docker build -f ml/Dockerfile -t aegis-ml .
FROM python:3.13-slim
WORKDIR /app

COPY ml/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY ml /app
EXPOSE 8001
# Train the models on startup, then run the service.
CMD ["sh", "-c", "python -m aegis_ml.train && uvicorn service:app --host 0.0.0.0 --port 8001"]
