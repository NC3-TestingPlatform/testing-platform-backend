.PHONY: dev export-openapi lint typecheck test up down logs scan

# The host-run API reads .env when present, matching what Compose gives the containers.
dev:
	uv run $(if $(wildcard .env),--env-file .env) fastapi dev src/nc3_testing_platform/main.py

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

# make scan DOMAIN=example.com
DOMAIN ?= example.com
scan:
	docker compose exec -T worker-platform \
		celery -A nc3_testing_platform.worker.app call scan.dispatch --args='["$(DOMAIN)"]'

export-openapi:
	uv run export-openapi

lint:
	uv run ruff check .

typecheck:
	uv run --locked pyright

test:
	uv run pytest
