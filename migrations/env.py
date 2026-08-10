"""Alembic environment: diffs `nc3_testing_platform.models` against DATABASE_URL.

The aggregator import loads every domain's tables onto Base.metadata, so
autogenerate always sees the complete schema. The URL comes from the same
DATABASE_URL the application reads; there is no separate migration config to
drift from the deployment.
"""

import os

from alembic import context
from sqlalchemy import create_engine

from nc3_testing_platform.models import Base

target_metadata = Base.metadata

_DEFAULT_URL = "postgresql+psycopg://postgres:postgres@localhost:5432/nc3_testing_platform"


def _database_url() -> str:
    return os.getenv("DATABASE_URL", _DEFAULT_URL)


def run_migrations_offline() -> None:
    """Emit SQL to stdout instead of executing it (`alembic upgrade --sql`)."""
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        compare_type=True,
        compare_server_default=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the configured database."""
    engine = create_engine(_database_url())
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Both compare flags on: column type and server-default drift must
            # show up in `alembic check`, not in production.
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
