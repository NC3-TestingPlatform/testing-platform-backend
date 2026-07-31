.PHONY: export-openapi lint

export-openapi:
	uv run python -m app.tools.export_openapi

lint:
	uv run ruff check .