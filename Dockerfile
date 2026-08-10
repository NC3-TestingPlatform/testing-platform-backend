FROM python:3.14-slim-trixie

# Pinned rather than :latest so an image rebuild cannot change the resolver.
# Kept inside the same range as the build backend in pyproject.toml.
COPY --from=ghcr.io/astral-sh/uv:0.12.3 /uv /uvx /bin/

# `copy` avoids link warnings when the cache mount and the target sit on different filesystems.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

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

# Beat writes its schedule database at runtime and the rest of /app is root-owned.
# A fresh named volume mounted here inherits this ownership.
RUN mkdir -p /var/lib/celery && chown app:app /var/lib/celery

USER app
