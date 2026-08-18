"""API-side database access: one lazily built sync engine per runtime role.

The API connects with two roles (docs/database-roles.md): ``nc3_app`` for
tenant work — the future domain realizations — and ``nc3_auth`` for the
credential surface, held by the API service alone so the scan workers that
share ``nc3_app`` never gain a privilege on `user_credential`/`user_session`
(US #79). Engines are lazy for the same reason as `worker/db.py`: importing
this module costs nothing in a process that never opens a session.

The request dependencies commit on handler success and roll back on an
escaping exception — deliberately unlike the worker's explicit-commit
contextmanager: the worker orders its commits before event publishes
(Datastore-split ADR), while an API request has no such ordering, and the
session-touch write of the authentication dependency (`core/security.py`)
must persist even under handlers that write nothing themselves.
"""

from collections.abc import Iterator
from typing import Annotated

import sqlalchemy as sa
from fastapi import Depends
from sqlalchemy.orm import Session, sessionmaker

# The aggregator import is load-bearing: mapper configuration needs every
# referenced table on the metadata, and API code imports only the models it
# touches (same rationale as worker/db.py).
from nc3_testing_platform import models as _models  # noqa: F401
from nc3_testing_platform.core.settings import settings

_app_engine: sa.Engine | None = None
_app_factory: sessionmaker[Session] | None = None
_auth_engine: sa.Engine | None = None
_auth_factory: sessionmaker[Session] | None = None


def get_app_engine() -> sa.Engine:
    """The process-wide ``nc3_app`` engine, created on first use."""
    global _app_engine
    if _app_engine is None:
        _app_engine = sa.create_engine(settings.app_database_url, pool_pre_ping=True)
    return _app_engine


def get_auth_engine() -> sa.Engine:
    """The process-wide ``nc3_auth`` engine, created on first use."""
    global _auth_engine
    if _auth_engine is None:
        _auth_engine = sa.create_engine(
            settings.auth_database_url, pool_pre_ping=True
        )
    return _auth_engine


def _unit_of_work(factory: sessionmaker[Session]) -> Iterator[Session]:
    unit = factory()
    try:
        yield unit
        unit.commit()
    except BaseException:
        unit.rollback()
        raise
    finally:
        unit.close()


def app_session() -> Iterator[Session]:
    """Request-scoped tenant session (``nc3_app``); commits on success."""
    global _app_factory
    if _app_factory is None:
        _app_factory = sessionmaker(bind=get_app_engine())
    yield from _unit_of_work(_app_factory)


def auth_session() -> Iterator[Session]:
    """Request-scoped credential-surface session (``nc3_auth``).

    One transaction per request: the RLS context asserted inside it
    (`core/rls.py`, ``SET LOCAL``) dies at the commit this dependency issues.
    """
    global _auth_factory
    if _auth_factory is None:
        _auth_factory = sessionmaker(bind=get_auth_engine())
    yield from _unit_of_work(_auth_factory)


AppDbSession = Annotated[Session, Depends(app_session)]
AuthDbSession = Annotated[Session, Depends(auth_session)]
