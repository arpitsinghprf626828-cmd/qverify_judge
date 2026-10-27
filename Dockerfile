FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-hin libgl1 libglib2.0-0 curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements-lock.txt .
RUN pip install --no-cache-dir -r requirements-lock.txt
COPY . .
RUN chmod +x docker-entrypoint.sh
ENV PYTHONUNBUFFERED=1 QV_DEMO=0
EXPOSE 8501
VOLUME /data
HEALTHCHECK CMD curl -fs http://localhost:${PORT:-8501}/_stcore/health || exit 1
ENTRYPOINT ["./docker-entrypoint.sh"]
