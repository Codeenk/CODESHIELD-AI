PYTHON ?= python3
NPM ?= npm
HOST ?= 127.0.0.1
PORT ?= 8000

.PHONY: help install install-ml dev build serve test seed scan verify docker docker-up clean

help:
	@echo "CodeShield AI"
	@echo "  make install     install backend and frontend dependencies"
	@echo "  make install-ml  install optional CodeBERT/Qwen dependencies"
	@echo "  make dev         run backend (:8000) and Vite (:5173)"
	@echo "  make build       build the production frontend bundle"
	@echo "  make serve       run the API and serve the built dashboard"
	@echo "  make test        run the backend pytest suite"
	@echo "  make scan        scan the repository's own backend"
	@echo "  make seed        seed demo scans for the dashboard"
	@echo "  make verify      tests, self-scan, and frontend build"
	@echo "  make docker      build the production image"
	@echo "  make docker-up   run the service with docker compose"

install:
	$(PYTHON) -m pip install -r backend/requirements.txt
	cd frontend && $(NPM) ci --no-audit --no-fund

install-ml:
	$(PYTHON) -m pip install -r backend/requirements-ml.txt

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
