.PHONY: dev export-openapi lint typecheck test up down logs scan db-upgrade db-downgrade db-revision db-check db-current db-history

# The host-run API reads .env when present, matching what Compose gives the containers.
dev:
	uv run $(if $(wildcard .env),--env-file .env) fastapi dev src/nc3_testing_platform/main.py

# Build changed images and wait for every healthcheck, so `make scan` right
# after `make up` finds a stack that is actually serving.
up:
	docker compose up -d --build --wait

down:
	docker compose down

logs:
	docker compose logs -f

# make scan DOMAIN=example.com
# The domain travels as an environment value and Python passes it on as data,
# so no shell ever interpolates it into a command line.
DOMAIN ?= example.com
scan:
	docker compose exec -T -e SCAN_DOMAIN="$(DOMAIN)" worker-platform \
		python -c 'import os; from nc3_testing_platform.worker.tasks import dispatch; print(dispatch.delay(os.environ["SCAN_DOMAIN"]).id)'

# Database migrations (docs/database-migrations.md).
# migrations/env.py refuses to run without DATABASE_URL (a downgrade against a
# silently-defaulted database drops every table); the local development value
# lives here instead, and an exported DATABASE_URL always wins.
db-%: export DATABASE_URL ?= postgresql+psycopg://postgres:postgres@localhost:5432/nc3_testing_platform
db-upgrade:
	uv run alembic upgrade head

db-downgrade:
	uv run alembic downgrade -1

# make db-revision m="add asset tags"
db-revision:
	uv run alembic revision --autogenerate -m "$(m)"

db-check:
	uv run alembic check

db-current:
	uv run alembic current

db-history:
	uv run alembic history

export-openapi:
	uv run export-openapi

lint:
	uv run ruff check .

typecheck:
	uv run --locked pyright

test:
	uv run pytest
