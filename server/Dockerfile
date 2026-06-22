# Aegis SOC server. The build context must be the repo root:
#   docker build -f server/Dockerfile -t aegis-soc .
FROM python:3.13-slim
WORKDIR /app

COPY server/requirements.txt ./requirements.txt
COPY crypto /crypto
RUN pip install --no-cache-dir -r requirements.txt && pip install --no-cache-dir -e /crypto

COPY server /app
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
