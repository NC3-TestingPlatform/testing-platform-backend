# testing-platform-backend

Project repository for the NC3 Testing Platform backend (v4).

# Technical stack

**Current** — what the code actually uses:

- Python 3.13, [uv](https://docs.astral.sh/uv/) (packaging + virtualenv)
- FastAPI + Pydantic — the app and its request/response models
- pytest + openapi-spec-validator (dev) — the contract test suite

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
make dev
```

- API base: http://localhost:8000/api/v1
- Interactive docs (Swagger UI): http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/api/v1/openapi.json
- Health probes: http://localhost:8000/healthz, `/readyz`

Handlers return static stub data, so the running server doubles as a mock the frontend can develop against.

# Generating the OpenAPI contract

The OpenAPI 3.1 spec is generated from the FastAPI app (`nc3_testing_platform.main:app`) and written to `api/openapi.json`.

```bash
make export-openapi   # write api/openapi.json
make lint             # ruff over the source
make test             # validate it, and check the committed file is current
```

The development routine after any change to a router or Pydantic schema is `make export-openapi && make lint`. `api/openapi.json` is the contract the frontend interfaces with; commit it alongside the change that alters it.

`make test` validates the generated document against OpenAPI 3.1 and fails if the committed file differs from it. CI runs the same command.

# Project structure

> **Current scope:** the only working functionality is the Pydantic schemas and OpenAPI spec generation. Route handlers
> return stub data so the app runs as a live mock; there is no persistence, auth backend, or scan logic yet.

```
src/nc3_testing_platform/
  main.py              # FastAPI app; mounts every domain router under /api/v1
  core/                # shared, cross-cutting building blocks
    enums.py           #   canonical enums
    schemas.py         #   base model config + shared field types
    errors.py          #   RFC 9457 problem+json errors + handlers
    pagination.py      #   cursor pagination
    security.py        #   OpenAPI security schemes + rate-limit contract
  domains/             # one vertical slice per domain
    scans/             #   every slice follows this layout
      models.py        #     SQLAlchemy models
      schemas.py       #     Pydantic request and response models
      repository.py    #     queries; session is the first argument
      service.py       #     business logic and transaction boundaries
      router.py        #     path operations
  tools/
    export_openapi.py  # dumps app.openapi() -> api/openapi.json
api/
  openapi.json         # generated API contract (see "Generating the OpenAPI contract")
docs/
  reference/           # reference documentation
```
