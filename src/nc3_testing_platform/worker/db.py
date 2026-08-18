"""Worker-side database access: one lazily built sync engine per process.

Workers use the synchronous SQLAlchemy engine (Stack decisions → Backend):
under the gevent pool psycopg's sockets are monkey-patched and cooperate, and
under prefork each child builds its own engine on first use — laziness is what
makes that per-process instead of per-fork-of-a-shared-pool, which would hand
children shared sockets.

This connects with the runtime role via ``APP_DATABASE_URL`` — never the
owning role, which is Alembic's alone (docs/database-roles.md). Which runtime
role the URL carries is per-service compose topology: the scan workers get
``nc3_app`` and open a per-transaction RLS context (`core/rls.py`), the
platform worker and beat get ``app_platform``, whose per-duty policies read
no GUC (IDR-012).
"""

from collections.abc import Iterator
from contextlib import contextmanager

import sqlalchemy as sa
from sqlalchemy.orm import Session, sessionmaker

# The aggregator import is load-bearing: mapper configuration needs every
# referenced table on the metadata (scan_task → asset → organization, …),
# and worker code imports only the models it touches.
from nc3_testing_platform import models as _models  # noqa: F401
from nc3_testing_platform.core.settings import settings

_engine: sa.Engine | None = None
_factory: sessionmaker[Session] | None = None


def get_engine() -> sa.Engine:
    """The process-wide sync engine, created on first use.

    ``pool_pre_ping`` because worker processes are long-lived and RabbitMQ
    redeliveries can arrive hours after the pool last spoke to PostgreSQL.
    """
    global _engine
    if _engine is None:
        _engine = sa.create_engine(settings.app_database_url, pool_pre_ping=True)
    return _engine


@contextmanager
def session() -> Iterator[Session]:
    """One unit of work: the caller commits, an escaping exception rolls back.

    Commit stays explicit at the call site because the orchestration code
    deliberately commits *before* publishing events (Datastore-split ADR) —
    an implicit commit-on-exit would make that ordering invisible.
    """
    global _factory
    if _factory is None:
        _factory = sessionmaker(bind=get_engine())
    unit = _factory()
    try:
        yield unit
    except BaseException:
        unit.rollback()
        raise
    finally:
        unit.close()
