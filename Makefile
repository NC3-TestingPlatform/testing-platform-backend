.PHONY: dev export-openapi lint typecheck test up down logs migrate scan db-upgrade db-downgrade db-revision db-check db-current db-history

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

# Apply migrations inside the running stack; the scan tables must exist
# before `make scan` seeds a job (the api image carries alembic + migrations/).
migrate:
	docker compose exec -T api alembic upgrade head

# make scan DOMAIN=example.com  (requires `make migrate` once per fresh stack)
# The domain travels as an environment value expanded by the recipe shell
# ($$DOMAIN), never by make: a make-time $(DOMAIN) expansion would splice the
# value into the command line before any quoting applies.
DOMAIN ?= example.com
export DOMAIN
scan:
	docker compose exec -T -e SCAN_DOMAIN="$${DOMAIN}" -e SCAN_MODULE="$${MODULE}" \
		worker-platform python -m nc3_testing_platform.tools.seed_scan

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
