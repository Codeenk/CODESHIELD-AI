.PHONY: help install dev test lint scan serve pdf docker clean

help:
	@echo "install  - create a venv and install runtime deps"
	@echo "dev      - install dev + (optional) ML deps"
	@echo "test     - run the pytest suite"
	@echo "lint     - run ruff"
	@echo "scan     - scan the bundled vulnerable examples (rules only)"
	@echo "serve    - run the dashboard + API"
	@echo "pdf      - write a PDF report of the examples"
	@echo "docker   - build the app and sandbox images"

install:
	python -m venv .venv
	.venv/bin/pip install -r requirements.txt || .venv/Scripts/pip install -r requirements.txt

dev:
	.venv/bin/pip install -r requirements-dev.txt || .venv/Scripts/pip install -r requirements-dev.txt

test:
	.venv/bin/pytest -q || .venv/Scripts/pytest -q

lint:
	.venv/bin/ruff check codeshield tests || .venv/Scripts/ruff check codeshield tests

scan:
	.venv/bin/python -m codeshield scan examples/vulnerable --no-model || \
	.venv/Scripts/python -m codeshield scan examples/vulnerable --no-model

serve:
	.venv/bin/python -m codeshield serve || .venv/Scripts/python -m codeshield serve

pdf:
	.venv/bin/python -m codeshield scan examples/vulnerable --no-model --format pdf -o report.pdf || \
	.venv/Scripts/python -m codeshield scan examples/vulnerable --no-model --format pdf -o report.pdf

docker:
	docker build -f docker/Dockerfile -t codeshield-ai:latest .
	docker build -f docker/sandbox.Dockerfile -t codeshield-sandbox:latest .

clean:
	rm -rf .pytest_cache .ruff_cache **/__pycache__ build dist *.egg-info
