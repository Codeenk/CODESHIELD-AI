# CodeShield AI application image (API + dashboard).
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CODESHIELD_HOST=0.0.0.0

WORKDIR /app

# git is needed for read-only repository cloning (FR-2).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY codeshield ./codeshield
COPY PRD.md README.md ./

# Run as a non-root user.
RUN useradd --create-home --uid 10001 codeshield && chown -R codeshield /app
USER codeshield

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/health || exit 1

CMD ["python", "-m", "codeshield", "serve"]
