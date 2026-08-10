"""Alembic environment: diffs `nc3_testing_platform.models` against DATABASE_URL.

The aggregator import loads every domain's tables onto Base.metadata, so
autogenerate always sees the complete schema. The URL comes from the same
DATABASE_URL the application reads; there is no separate migration config to
drift from the deployment.
"""

import logging.config
import os

from alembic import context
from sqlalchemy import create_engine, pool

from nc3_testing_platform.models import Base

# Load alembic.ini's logging sections, so migration commands narrate what ran.
if context.config.config_file_name is not None:
    logging.config.fileConfig(context.config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    """The target database, from the environment and nowhere else.

    No fallback on purpose: `downgrade base` drops every table, so a missing
    or misspelled DATABASE_URL must fail here, not silently hit a default.
    The Makefile's db-* targets supply the local development value.
    """
    url = os.getenv("DATABASE_URL")
    if not url:
        raise RuntimeError(
            "DATABASE_URL is not set. Use the make db-* targets for local "
            "development, or export the deployment's URL explicitly."
        )
    return url


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
    # One short-lived process, one connection: pooling buys nothing here.
    engine = create_engine(_database_url(), poolclass=pool.NullPool)
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
