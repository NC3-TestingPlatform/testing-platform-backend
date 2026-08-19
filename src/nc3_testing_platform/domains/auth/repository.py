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
from nc3_testing_platform.domains.auth.models import (
    MfaRecoveryCode,
    UserCredential,
    UserMfa,
    UserSession,
)
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


def mfa_for(db: Session, user_id: uuid.UUID) -> UserMfa | None:
    """The user's MFA row, confirmed or not, readable under the user arm."""
    return db.scalars(
        sa.select(UserMfa).where(UserMfa.user_id == user_id)
    ).one_or_none()


def unused_recovery_code_count(db: Session, user_id: uuid.UUID) -> int:
    """How many live (unused, unsuperseded) recovery codes remain."""
    return db.scalar(
        sa.select(sa.func.count())
        .select_from(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.used_at.is_(None),
            MfaRecoveryCode.superseded_at.is_(None),
        )
    ) or 0


def insert_recovery_codes(
    db: Session, user_id: uuid.UUID, code_hashes: Sequence[bytes]
) -> None:
    """Store a fresh set of recovery-code hashes."""
    db.add_all(
        MfaRecoveryCode(user_id=user_id, code_hash=code_hash)
        for code_hash in code_hashes
    )
    db.flush()


def burn_recovery_codes(db: Session, user_id: uuid.UUID) -> None:
    """Supersede every live code — regeneration and disable replace the set.

    An UPDATE, never a DELETE: `nc3_auth` holds no DELETE on the table, and
    the burn history is exactly what an incident responder wants.
    """
    db.execute(
        sa.update(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.used_at.is_(None),
            MfaRecoveryCode.superseded_at.is_(None),
        )
        .values(superseded_at=sa.func.now())
    )


def consume_recovery_code(
    db: Session, user_id: uuid.UUID, code_hash: bytes
) -> bool:
    """Burn one live code; ``True`` when this call spent it.

    One conditional UPDATE is the whole one-time guarantee: two concurrent
    requests presenting the same code race on the row lock, and the loser's
    WHERE no longer matches — never SELECT-then-UPDATE.
    """
    spent_id = db.execute(
        sa.update(MfaRecoveryCode)
        .where(
            MfaRecoveryCode.user_id == user_id,
            MfaRecoveryCode.code_hash == code_hash,
            MfaRecoveryCode.used_at.is_(None),
            MfaRecoveryCode.superseded_at.is_(None),
        )
        .values(used_at=sa.func.now())
        .returning(MfaRecoveryCode.id)
    ).scalar_one_or_none()
    return spent_id is not None


def stamp_session_assurance(db: Session, session_id: uuid.UUID) -> None:
    """Refresh the session's MFA assurance stamp (step-up verify)."""
    db.execute(
        sa.update(UserSession)
        .where(UserSession.id == session_id, UserSession.revoked_at.is_(None))
        .values(mfa_verified_at=sa.func.now())
    )
