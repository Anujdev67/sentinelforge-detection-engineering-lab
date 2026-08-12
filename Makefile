.PHONY: setup demo up down test lint validate api dashboard

PYTHON ?= python
PNPM ?= pnpm

setup:
	$(PYTHON) -m scripts.create_env
	$(PYTHON) -m pip install -e ".[dev]"
	cd apps/dashboard && $(PNPM) install --frozen-lockfile

demo:
	docker compose exec api python -m scripts.demo

up:
	docker compose up --build

down:
	docker compose down

test:
	$(PYTHON) -m pytest
	cd apps/dashboard && $(PNPM) test

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy apps detections evaluators telemetry soar scripts tests
	cd apps/dashboard && $(PNPM) lint
	cd apps/dashboard && $(PNPM) exec tsc -b --pretty false

validate: test lint
	$(PYTHON) -m scripts.validate_content
	$(PYTHON) -m scripts.check_links
	cd apps/dashboard && $(PNPM) build
	cd infrastructure/terraform && terraform fmt -check -recursive && terraform validate
	docker compose config --quiet

api:
	$(PYTHON) -m uvicorn apps.api.sentinelforge_api.main:app --reload

dashboard:
	cd apps/dashboard && $(PNPM) dev
