.PHONY: dev export-openapi lint test

dev:
	uv run fastapi dev src/nc3_testing_platform/main.py

export-openapi:
	uv run export-openapi

lint:
	uv run ruff check .

test:
	uv run pytest
