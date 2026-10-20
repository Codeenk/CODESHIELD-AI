# CodeShield AI — production image (API + built dashboard).
# Build from the repository root:
#   docker build -f docker/Dockerfile -t codeshield:latest .
FROM node:22-alpine AS frontend

WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CODESHIELD_HOST=0.0.0.0 \
    CODESHIELD_PORT=8000 \
    CODESHIELD_DATA_DIR=/data \
    CODESHIELD_MODEL_MODE=off

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 codeshield

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend ./backend
COPY --from=frontend /app/frontend/dist ./frontend/dist
COPY samples ./samples
COPY ATTRIBUTION_STRIX_APACHE2_LICENSE.txt ./

RUN mkdir -p /data && chown -R codeshield:codeshield /data /app
USER codeshield

WORKDIR /app/backend
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3)"
CMD ["python", "-m", "codeshield"]
