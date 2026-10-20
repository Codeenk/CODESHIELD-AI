PYTHON ?= $(CURDIR)/.venv/bin/python
UV ?= uv
NPM ?= npm
HOST ?= 127.0.0.1
PORT ?= 8000
TORCH_INDEX ?= https://download.pytorch.org/whl/cpu
LLAMA ?= .tools/llama-b11753/llama-server
REPAIR_MODEL ?= models/repair/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf

.PHONY: help venv install install-ml models llama model-server dev build serve test seed scan verify docker docker-up clean

help:
	@echo "CodeShield AI"
	@echo "  make venv         create a Python 3.12 virtualenv in .venv (uv)"
	@echo "  make install      install core backend and frontend dependencies"
	@echo "  make install-ml   install PyTorch/Transformers (CPU wheel by default)"
	@echo "  make models       download CodeBERT + Qwen2.5-Coder GGUF weights"
	@echo "  make llama        install the llama.cpp CPU server into .tools/"
	@echo "  make model-server serve the local repair model on :8080"
	@echo "  make dev          run backend (:8000) and Vite (:5173)"
	@echo "  make build        build the production frontend bundle"
	@echo "  make serve        run the API and serve the built dashboard"
	@echo "  make test         run the backend pytest suite"
	@echo "  make scan         scan the repository's own backend"
	@echo "  make seed         seed demo scans for the dashboard"
	@echo "  make verify       tests, self-scan, and frontend build"
	@echo "  make docker       build the production image"
	@echo "  make docker-up    run the service with docker compose"

venv:
	$(UV) venv --python 3.12 .venv

install: venv
	$(UV) pip install --python $(PYTHON) -r backend/requirements.txt
	cd frontend && $(NPM) ci --no-audit --no-fund

install-ml: venv
	$(UV) pip install --python $(PYTHON) torch --index-url $(TORCH_INDEX)
	$(UV) pip install --python $(PYTHON) -r backend/requirements-ml.txt

models: venv
	$(PYTHON) backend/scripts/download_models.py --all

llama:
	backend/scripts/download_llama.sh

model-server:
	$(LLAMA) -m $(REPAIR_MODEL) -c 4096 -t 6 -ngl 0 \
		--host 127.0.0.1 --port 8080 --jinja --no-webui

dev:
	@echo "backend: http://$(HOST):$(PORT)   frontend: http://127.0.0.1:5173"
	@trap 'kill 0' INT TERM; \
	(cd backend && $(PYTHON) -m codeshield) & \
	(cd frontend && $(NPM) run dev) & \
	wait

build:
	cd frontend && $(NPM) run build

serve: build
	cd backend && CODESHIELD_HOST=$(HOST) CODESHIELD_PORT=$(PORT) $(PYTHON) -m codeshield

test:
	cd backend && $(PYTHON) -m pytest -q

scan:
	$(PYTHON) backend/scripts/run_scan.py backend/codeshield --fail-on high

seed:
	$(PYTHON) backend/scripts/seed_demo.py

verify: test scan build

docker:
	docker build -f docker/Dockerfile -t codeshield:latest .

docker-up:
	docker compose -f docker/docker-compose.yml up --build

clean:
	find backend -name __pycache__ -type d -prune -exec rm -rf {} +
	rm -rf backend/data frontend/dist .pytest_cache backend/.pytest_cache
