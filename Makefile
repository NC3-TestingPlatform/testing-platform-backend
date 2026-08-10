.PHONY: dev export-openapi lint typecheck test db-upgrade db-downgrade db-revision db-check db-current db-history

dev:
	uv run fastapi dev src/nc3_testing_platform/main.py

# Database migrations (docs/database-migrations.md).
# DATABASE_URL overrides the default local connection everywhere below.
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
