# testing-platform-backend

Project repository for the NC3 Testing Platform backend (v4).

# Technical stack

**Current** — what the code actually uses:

- Python 3.13, [uv](https://docs.astral.sh/uv/) (packaging + virtualenv)
- FastAPI + Pydantic — the app and its request/response models
- openapi-spec-validator (dev) — validates the generated 3.1 spec

**Projected** — planned:

- SQLAlchemy 2.0 + Alembic — persistence + migrations
- PostgreSQL

# Getting started

Requires **Python ≥ 3.13** and **[uv](https://docs.astral.sh/uv/)**. Install dependencies from the lockfile:

```bash
uv sync
```

No environment variables or config are required yet.

# Running the mock server

```bash
uv run fastapi dev app/main.py
```

- API base: http://localhost:8000/api/v1
- Interactive docs (Swagger UI): http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/api/v1/openapi.json
- Health probes: http://localhost:8000/healthz, `/readyz`

Handlers return static stub data, so the running server doubles as a mock the frontend can develop against.

# Generating the OpenAPI contract

The OpenAPI 3.1 spec is generated from the FastAPI app (`app.main:app`) and written to `docs/openapi.json`.

```bash
uv run python -m app.tools.export_openapi                  # write docs/openapi.json
uv run openapi-spec-validator --schema 3.1 docs/openapi.json   # validate (exits 0 if valid)
```

Regenerate and re-validate after any change to a router or Pydantic schema. `docs/openapi.json` is the contract the
frontend interfaces with; commit it alongside the change that alters it.

# Project structure

> **Current scope:** the only working functionality is the Pydantic schemas and OpenAPI spec generation. Route handlers
> return stub data so the app runs as a live mock; there is no persistence, auth backend, or scan logic yet.

```
app/
  main.py              # FastAPI app; mounts every domain router under /api/v1
  core/                # shared, cross-cutting building blocks
    enums.py           #   canonical enums
    schemas.py         #   base model config + shared field types
    errors.py          #   RFC 9457 problem+json errors + handlers
    pagination.py      #   cursor pagination
    security.py        #   OpenAPI security schemes + rate-limit contract
  domains/             # one vertical slice per domain (router + schemas together)
    guest/  auth/  org/  assets/  scans/
    schedules/  findings/  reports/  notifications/  health/
  tools/
    export_openapi.py  # dumps app.openapi() -> docs/openapi.json
docs/
  openapi.json         # generated contract (see "Generating the OpenAPI contract")
  reference/           # source design docs (data-model, ADRs)
```