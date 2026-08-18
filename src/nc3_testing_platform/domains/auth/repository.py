"""Query layer of the auth domain: every statement it issues, in one place.

The one pre-context query is `auth_login_lookup` — a SECURITY DEFINER
function (IDR-012), called before any RLS arm can open because identity is
exactly what it resolves. Everything else runs in-policy under the user or
org context the service asserted first (`core/rls.py`).
"""

import uuid
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Session

from nc3_testing_platform.core import enums
from nc3_testing_platform.domains.auth.models import UserCredential, UserSession
from nc3_testing_platform.domains.org.models import AppUser, KeyEnvelope
from nc3_testing_platform.domains.statements.models import Statement

_LOGIN_LOOKUP = sa.text(
    "SELECT user_id, organization_id, disabled_at, password_ciphertext,"
    " failed_login_count, locked_until, observed_at"
    " FROM public.auth_login_lookup(:email)"
)


def login_lookup(db: Session, email: str) -> sa.Row[Any] | None:
    """The pre-context credential row for ``email``, or ``None``.

    ``observed_at`` is the database clock at lookup time; every timeout and
    lockout comparison uses it so the decision matches the stored stamps.
    """
    return db.execute(_LOGIN_LOOKUP, {"email": email}).one_or_none()


def active_acceptance_statements(db: Session) -> Sequence[Statement]:
    """The account-level acceptance statements registration must collect."""
    return db.scalars(
        sa.select(Statement).where(
            Statement.response_kind == enums.StatementResponseKind.ACCEPTANCE,
            Statement.required_context_type.is_(None),
            Statement.effective_at <= sa.func.now(),
            Statement.retired_at.is_(None),
        )
    ).all()


def user_envelope(db: Session, user_id: uuid.UUID) -> KeyEnvelope | None:
    """The user-scope key envelope, readable under the user arm."""
    return db.scalars(
        sa.select(KeyEnvelope).where(
            KeyEnvelope.user_id == user_id,
            KeyEnvelope.scope == enums.KeyScope.USER,
        )
    ).one_or_none()


def credential_for(db: Session, user_id: uuid.UUID) -> UserCredential | None:
    """The user's credential row, readable under the user arm."""
    return db.scalars(
        sa.select(UserCredential).where(UserCredential.user_id == user_id)
    ).one_or_none()


def user_by_id(db: Session, user_id: uuid.UUID) -> AppUser | None:
    """The user's own `app_user` row, readable under the user arm."""
    return db.get(AppUser, user_id)


def session_by_id(db: Session, session_id: uuid.UUID) -> UserSession | None:
    """One session row, readable under the user arm."""
    return db.get(UserSession, session_id)


def revoke_session(db: Session, session_id: uuid.UUID) -> None:
    """Mark one session revoked; a no-op if it already is."""
    db.execute(
        sa.update(UserSession)
        .where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
        .values(revoked_at=sa.func.now())
    )


def revoke_other_sessions(
    db: Session, user_id: uuid.UUID, *, keep_session_id: uuid.UUID
) -> None:
    """Revoke every live session of ``user_id`` except ``keep_session_id``."""
    db.execute(
        sa.update(UserSession)
        .where(
            UserSession.user_id == user_id,
            UserSession.id != keep_session_id,
            UserSession.revoked_at.is_(None),
        )
        .values(revoked_at=sa.func.now())
    )
