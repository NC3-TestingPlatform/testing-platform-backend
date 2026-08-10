.PHONY: dev export-openapi lint typecheck test

dev:
	uv run fastapi dev src/nc3_testing_platform/main.py

export-openapi:
	uv run export-openapi

lint:
	uv run ruff check .

typecheck:
	uv run --locked pyright

test:
	uv run pytest
