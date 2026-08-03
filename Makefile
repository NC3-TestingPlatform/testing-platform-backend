.PHONY: export-openapi lint

export-openapi:
	uv run export-openapi

lint:
	uv run ruff check .