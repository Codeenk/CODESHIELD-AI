# CodeShield AI — API + built dashboard.
# Build from the repository root:  docker build -f docker/Dockerfile -t codeshield .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CODESHIELD_MODEL_MODE=${CODESHIELD_MODEL_MODE:-auto} \
    CODESHIELD_HOST=0.0.0.0 \
    CODESHIELD_PORT=8000

# git is needed to clone repositories.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Optional ML deps: uncomment to bake the CodeBERT model in.
# RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
# RUN pip install --no-cache-dir transformers

COPY backend ./backend
COPY frontend/dist ./frontend/dist
COPY samples ./samples

WORKDIR /app/backend
EXPOSE 8000
CMD ["python", "-m", "codeshield"]
