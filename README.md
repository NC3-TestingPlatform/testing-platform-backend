# testing-platform-backend

Project repository for the NC3 Testing Platform backend (v4).

# Technical stack

**Current** — what the code actually uses:

- Python 3.13, [uv](https://docs.astral.sh/uv/) (packaging + virtualenv)
- FastAPI + Pydantic — the app and its request/response models
- Celery + RabbitMQ (broker) + Redis (result backend) — the task queues, one per egress profile
- SQLAlchemy 2.0 + Alembic + PostgreSQL — the data model and its migration workflow (see [docs/database-migrations.md](docs/database-migrations.md))
- Docker Compose — the local stack and the Dokploy deployment
- pytest + openapi-spec-validator (dev) — the contract test suite


# Getting started

Requires **Python ≥ 3.13** and **[uv](https://docs.astral.sh/uv/)**. Install dependencies from the lockfile:

```bash
uv sync
```

Every setting has a working default, so nothing needs configuring on a fresh clone. To change one, copy the template and edit:

```bash
cp .env.example .env
```

Compose picks `.env` up automatically; `make dev` passes it to the host-run API.

# Running the mock server

```bash
make dev
```

- API base: http://localhost:8000/api/v1
- Interactive docs (Swagger UI): http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/api/v1/openapi.json
- Health probes: http://localhost:8000/healthz, `/readyz`

Handlers return static stub data, so the running server doubles as a mock the frontend can develop against.

# Running the full stack (Compose)

```bash
make up      # build and start everything, detached
make logs    # follow logs
make down    # stop
```

`docker compose up` starts the API (http://localhost:8000), PostgreSQL, Redis, RabbitMQ, the Celery workers (one per egress queue) and beat, plus a development identity provider. The root `docker-compose.yml` is an index of `include:`s; each service is defined in its own file under `infra/compose/`.

To see a job round-trip through the stack — RabbitMQ to the workers to a row in PostgreSQL:

```bash
make scan DOMAIN=example.com
```

This dispatches the mock `scan.dispatch` task: it fans out to mock modules on the scan queue, each reports step progress to the Redis result backend, and the collected findings persist as one row in the throwaway `scan_artifacts` table (replaced by the real ORM models and migrations).

Workers refuse to start if their image is missing the external binaries their queue requires (`worker/preflight.py`), and report health by pinging their own control queue.

# Deploying with Dokploy

`docker-compose.dokploy.yml` is the deployment stack: self-contained (no includes), no published ports except the API through Dokploy's reverse proxy, no development identity provider, and no default credentials — every secret must be set in the Dokploy application's environment tab or the stack refuses to start. Point the Dokploy compose service at that file and set: `POSTGRES_USER`, `POSTGRES_PASSWORD`, `RABBITMQ_USER`, `RABBITMQ_PASSWORD`, `RABBITMQ_COOKIE` (and optionally `OIDC_DISCOVERY_URL` for an external OIDC provider).

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
