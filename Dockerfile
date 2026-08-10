# Multi-stage: one shared Python base, then one final stage per runtime role.
# The API and each egress queue get their own image (US #78 ADR: per-egress-queue
# worker images, not one monolithic all-engines venv). Today the worker stages
# differ only in WORKER_QUEUE and system packages; engine binaries land in their
# queue's stage — and in worker/preflight.py's registry — as they are integrated.

# The interpreter version matches .python-version. With a mismatched base, uv
# quietly downloads its own interpreter into /root — which the runtime user
# cannot read, so every container dies at startup unable to find the stdlib.
FROM python:3.13-slim-trixie AS base

# Pinned rather than :latest so an image rebuild cannot change the resolver.
# Kept inside the same range as the build backend in pyproject.toml.
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /uvx /bin/

# `copy` avoids link warnings when the cache mount and the target sit on different filesystems.
# `downloads=never` turns the interpreter drift above into a loud build failure.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3

WORKDIR /app

# Dependencies resolve in their own layer, so editing source does not reinstall them.
# --locked fails rather than silently updating uv.lock.
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY . /app

RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev

# Puts `celery` and `fastapi` on PATH, so commands need no `uv run` prefix.
ENV PATH="/app/.venv/bin:$PATH"

RUN useradd --create-home --uid 10001 app


FROM base AS api

USER app
EXPOSE 8000
CMD ["fastapi", "run", "src/nc3_testing_platform/main.py", "--port", "8000"]


FROM base AS worker-base

# Beat writes its schedule database at runtime and the rest of /app is root-owned.
# A fresh named volume mounted here inherits this ownership.
RUN mkdir -p /var/lib/celery && chown app:app /var/lib/celery

# WORKER_QUEUE names the egress profile a container serves. worker/preflight.py
# reads it to check the image carries that profile's binaries, and refuses to
# start otherwise.


FROM worker-base AS worker-non-intrusive-scan

# openssl >= 3.5 for the post-quantum checks; trixie's package satisfies it.
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
ENV WORKER_QUEUE=non-intrusive-scan
USER app


FROM worker-base AS worker-intrusive-scan

# nmap and subdomainenum's Go tools join this stage with the engine-integration ticket.
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*
ENV WORKER_QUEUE=intrusive-scan
USER app


FROM worker-base AS worker-file-analysis

ENV WORKER_QUEUE=file-analysis
USER app


FROM worker-base AS worker-platform

ENV WORKER_QUEUE=platform
USER app
