"""Worker-side database access: one lazily built sync engine per process.

Workers use the synchronous SQLAlchemy engine (Stack decisions → Backend):
under the gevent pool psycopg's sockets are monkey-patched and cooperate, and
under prefork each child builds its own engine on first use — laziness is what
makes that per-process instead of per-fork-of-a-shared-pool, which would hand
children shared sockets.

This connects with the owner-role ``DATABASE_URL``. The RLS runtime role and
per-transaction org/user context (``APP_DATABASE_URL``, ``SET LOCAL``) are
B5 / US #81, which revalidates every write path added here.
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
        _engine = sa.create_engine(settings.database_url, pool_pre_ping=True)
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
