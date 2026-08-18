"""Business logic of platform-local authentication (B3 / US #79).

Registration is one RLS-context transaction (IDR-016): the organization and
user ids are generated application-side (UUIDv7, like the guest-launch path)
so `set_org_context` can precede the INSERTs, and the workspace organization,
admin user, both key envelopes, the encrypted credential, and the consent
receipts land atomically. Login resolves identity through the
`auth_login_lookup` SECURITY DEFINER function, then does every write
in-policy under the user arm.

Failure paths that must persist state (the lockout counter) commit
explicitly before raising — the request dependency rolls back on an escaping
exception, and a brute-force counter a failed login rolls back would count
nothing.

Log lines carry UUIDs only: email addresses are PII and stay out of shared
logs (Non-functional → GDPR); actor evidence goes into the encrypted consent
receipts instead.
"""

import json
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache

import sqlalchemy as sa
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pydantic import SecretStr
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from uuid6 import uuid7

from nc3_testing_platform.core import crypto, rls
from nc3_testing_platform.core.enums import KeyScope, OrganizationRole
from nc3_testing_platform.core.security import hash_session_token
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.domains.auth import repository
from nc3_testing_platform.domains.auth.models import UserCredential, UserSession
from nc3_testing_platform.domains.auth.schemas import RegistrationSubmission
from nc3_testing_platform.domains.org.models import (
    AppUser,
    KeyEnvelope,
    Organization,
)
from nc3_testing_platform.domains.statements.models import StatementResponse

logger = logging.getLogger("nc3_testing_platform.domains.auth")

# AAD purpose tags (core/crypto.py): a ciphertext can only ever open in the
# column it was written for.
_ENVELOPE_AAD = b"key_envelope.wrapped_kek"
_CREDENTIAL_AAD = b"user_credential.password"
_EVIDENCE_AAD = b"statement_response.evidence"
_DEK_AAD = b"statement_response.wrapped_dek"

# The local issuer of identity projection (OIDC-ready: issuer + subject).
_LOCAL_SUBJECT_PREFIX = "local:"

_hasher = PasswordHasher()


@lru_cache(maxsize=1)
def _dummy_hash() -> str:
    """A hash for constant-work verification when the email is unknown."""
    return _hasher.hash("platform-dummy-password")


class EmailTakenError(Exception):
    """An account with this email already exists (unique index refusal)."""


class ConsentError(Exception):
    """The submitted statement answers do not cover the active set."""

    def __init__(
        self,
        missing: list[tuple[str, str]],
        unknown: list[tuple[str, str]],
    ) -> None:
        self.missing = missing
        self.unknown = unknown
        super().__init__(f"missing={missing!r} unknown={unknown!r}")


class InvalidCredentialsError(Exception):
    """Unknown email, disabled account, or wrong password — one answer."""


class AccountLockedError(Exception):
    """The account is locked out after repeated failures."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"locked for {retry_after_seconds}s")


class WrongCurrentPasswordError(Exception):
    """Password change refused: the current password did not verify."""


@dataclass(frozen=True)
class LoginResult:
    """A fresh session: the plaintext token exists only in this value."""

    token: str
    user: AppUser
    session: UserSession


def _encrypt_password(password: SecretStr, user_kek: bytes) -> bytes:
    hashed = _hasher.hash(password.get_secret_value())
    return crypto.encrypt(hashed.encode("ascii"), user_kek, aad=_CREDENTIAL_AAD)


def _unwrap_user_kek(db: Session, user_id: uuid.UUID) -> bytes:
    envelope = repository.user_envelope(db, user_id)
    if envelope is None:
        # Registration always creates it, so absence is corruption, not input.
        raise RuntimeError(f"user {user_id} has no user-scope key envelope")
    return crypto.unwrap_key(
        envelope.wrapped_kek, envelope.wrapping_nonce, aad=_ENVELOPE_AAD
    )


def register(
    db: Session,
    submission: RegistrationSubmission,
    *,
    client_ip: str,
    user_agent: str,
) -> AppUser:
    """Provision the workspace organization and its admin user (IDR-016).

    :raises ConsentError: When the answers do not cover every active
        account-level acceptance statement, or name an unknown one.
    :raises EmailTakenError: When the email already has an account.
    :raises crypto.MasterKeyUnavailableError: When the deployment master key
        is unset — surfaced as a 500, never a plaintext fallback.
    """
    required = {
        (s.statement_key, s.version): s
        for s in repository.active_acceptance_statements(db)
    }
    answered = {
        (r.statement_key, r.version) for r in submission.statement_responses
    }
    missing = sorted(set(required) - answered)
    unknown = sorted(answered - set(required))
    if missing or unknown:
        raise ConsentError(missing=missing, unknown=unknown)

    org_id, user_id = uuid7(), uuid7()
    rls.set_org_context(db, org_id, user_id)

    org_kek, user_kek = crypto.generate_key(), crypto.generate_key()
    org_wrapped = crypto.wrap_key(org_kek, aad=_ENVELOPE_AAD)
    user_wrapped = crypto.wrap_key(user_kek, aad=_ENVELOPE_AAD)

    user = AppUser(
        id=user_id,
        organization_id=org_id,
        identity_subject=f"{_LOCAL_SUBJECT_PREFIX}{user_id}",
        email=submission.email.lower(),
        display_name=submission.display_name,
        organization_role=OrganizationRole.ORGANIZATION_ADMIN,
    )
    user_envelope = KeyEnvelope(
        scope=KeyScope.USER,
        organization_id=org_id,
        user_id=user_id,
        wrapped_kek=user_wrapped.ciphertext,
        wrapping_nonce=user_wrapped.nonce,
        wrapping_algorithm=user_wrapped.algorithm,
        master_key_version=user_wrapped.master_key_version,
    )
    # Staged flushes: without relationship() constructs the unit of work does
    # not order inserts by raw foreign keys, so each parent goes in explicitly
    # before the rows that reference it.
    # Unnamed org until the first successful DNS verification (IDR-016).
    db.add(Organization(id=org_id, name="Workspace"))
    db.flush()
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        if "uq_app_user_email_lower" in str(exc.orig):
            raise EmailTakenError from exc
        raise
    db.add_all(
        [
            KeyEnvelope(
                scope=KeyScope.ORGANIZATION,
                organization_id=org_id,
                wrapped_kek=org_wrapped.ciphertext,
                wrapping_nonce=org_wrapped.nonce,
                wrapping_algorithm=org_wrapped.algorithm,
                master_key_version=org_wrapped.master_key_version,
            ),
            user_envelope,
            UserCredential(
                user_id=user_id,
                password_ciphertext=_encrypt_password(
                    submission.password, user_kek
                ),
            ),
        ]
    )
    # Populates user_envelope.id (a flush-time column default), which the
    # consent receipts reference as their opaque envelope pointer (§3.5).
    db.flush()
    evidence = json.dumps(
        {
            "action": "registration",
            "actor_email": submission.email.lower(),
            "client_ip": client_ip,
            "user_agent": user_agent,
        }
    ).encode()
    for response in submission.statement_responses:
        dek = crypto.generate_key()
        db.add(
            StatementResponse(
                organization_id=org_id,
                statement_id=required[(response.statement_key, response.version)].id,
                envelope_id=user_envelope.id,
                responded_at=sa.func.now(),
                response_evidence_encrypted=crypto.encrypt(
                    evidence, dek, aad=_EVIDENCE_AAD
                ),
                wrapped_dek=crypto.encrypt(dek, user_kek, aad=_DEK_AAD),
                encryption_metadata={"algorithm": crypto.ENVELOPE_ALGORITHM},
            )
        )
    db.flush()
    logger.info(
        "registration provisioned organization %s with admin user %s",
        org_id,
        user_id,
    )
    return user


def login(db: Session, *, email: str, password: SecretStr) -> LoginResult:
    """Verify a password and open a fresh session.

    Unknown email, disabled account, and wrong password are one
    indistinguishable :class:`InvalidCredentialsError`, after constant-work
    hashing. The lockout counter commits even though the login fails.

    :raises AccountLockedError: While the per-account lockout stands.
    """
    row = repository.login_lookup(db, email.lower())
    if row is None or row.disabled_at is not None:
        _verify_expecting_mismatch(_dummy_hash(), password)
        raise InvalidCredentialsError
    if row.locked_until is not None and row.locked_until > row.observed_at:
        remaining = row.locked_until - row.observed_at
        raise AccountLockedError(int(remaining.total_seconds()) + 1)

    rls.set_user_context(db, row.user_id)
    user_kek = _unwrap_user_kek(db, row.user_id)
    stored = crypto.decrypt(
        row.password_ciphertext, user_kek, aad=_CREDENTIAL_AAD
    ).decode("ascii")

    try:
        _hasher.verify(stored, password.get_secret_value())
    except VerifyMismatchError:
        _record_failure(db, row.user_id, observed_at=row.observed_at)
        raise InvalidCredentialsError from None

    credential = repository.credential_for(db, row.user_id)
    if credential is not None:
        if credential.failed_login_count or credential.locked_until is not None:
            credential.failed_login_count = 0
            credential.locked_until = None
        if _hasher.check_needs_rehash(stored):
            credential.password_ciphertext = _encrypt_password(
                password, user_kek
            )
    user = repository.user_by_id(db, row.user_id)
    if user is None:  # pragma: no cover - the lookup just proved it exists
        raise InvalidCredentialsError
    token, session = _open_session(db, row.user_id)
    logger.info("login succeeded for user %s", row.user_id)
    return LoginResult(token=token, user=user, session=session)


def _verify_expecting_mismatch(hashed: str, password: SecretStr) -> None:
    """Constant-work verify whose mismatch is the expected outcome."""
    try:
        _hasher.verify(hashed, password.get_secret_value())
    except VerifyMismatchError:
        pass


def _record_failure(
    db: Session, user_id: uuid.UUID, *, observed_at: datetime
) -> None:
    """Count one failed login; lock at the threshold; always persist.

    Commits explicitly: the caller raises next, and the request dependency
    would otherwise roll the counter back with the failed request.
    """
    credential = repository.credential_for(db, user_id)
    if credential is None:  # pragma: no cover - registration always creates it
        return
    credential.failed_login_count += 1
    if credential.failed_login_count >= settings.auth_lockout_threshold:
        credential.locked_until = observed_at + timedelta(
            seconds=settings.auth_lockout_seconds
        )
        credential.failed_login_count = 0
        logger.warning("account lockout applied to user %s", user_id)
    db.commit()


def _open_session(db: Session, user_id: uuid.UUID) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    session = UserSession(user_id=user_id, token_hash=hash_session_token(token))
    db.add(session)
    db.flush()
    return token, session


def logout(db: Session, session_id: uuid.UUID) -> None:
    """Revoke the session; the router clears the cookie."""
    repository.revoke_session(db, session_id)


def session_snapshot(
    db: Session, *, user_id: uuid.UUID, session_id: uuid.UUID
) -> tuple[AppUser, UserSession]:
    """The user and session rows behind an authenticated request.

    Both were just proven to exist by the bootstrap in this same transaction
    snapshot, so absence is corruption, not input.
    """
    user = repository.user_by_id(db, user_id)
    session = repository.session_by_id(db, session_id)
    if user is None or session is None:  # pragma: no cover
        raise RuntimeError("authenticated session rows disappeared mid-request")
    return user, session


def session_expiries(session: UserSession) -> tuple[datetime, datetime]:
    """(idle_expires_at, absolute_expires_at) for one session row."""
    return (
        session.last_seen_at + timedelta(seconds=settings.auth_session_idle_seconds),
        session.created_at
        + timedelta(seconds=settings.auth_session_absolute_seconds),
    )


def change_password(
    db: Session,
    *,
    user_id: uuid.UUID,
    current_session_id: uuid.UUID,
    current_password: SecretStr,
    new_password: SecretStr,
) -> LoginResult:
    """Re-encrypt the credential and rotate every session (privilege change).

    Other sessions are revoked outright; the calling session is replaced by a
    fresh row so the browser gets a new token — session id regeneration on
    privilege change, per the US.

    :raises WrongCurrentPasswordError: When the current password does not verify.
    """
    credential = repository.credential_for(db, user_id)
    if credential is None:  # pragma: no cover - registration always creates it
        raise WrongCurrentPasswordError
    user_kek = _unwrap_user_kek(db, user_id)
    stored = crypto.decrypt(
        credential.password_ciphertext, user_kek, aad=_CREDENTIAL_AAD
    ).decode("ascii")
    try:
        _hasher.verify(stored, current_password.get_secret_value())
    except VerifyMismatchError:
        raise WrongCurrentPasswordError from None

    credential.password_ciphertext = _encrypt_password(new_password, user_kek)
    credential.password_updated_at = sa.func.now()
    repository.revoke_other_sessions(db, user_id, keep_session_id=current_session_id)
    repository.revoke_session(db, current_session_id)
    user = repository.user_by_id(db, user_id)
    if user is None:  # pragma: no cover - the session just proved it exists
        raise WrongCurrentPasswordError
    token, session = _open_session(db, user_id)
    logger.info("password changed for user %s; sessions rotated", user_id)
    return LoginResult(token=token, user=user, session=session)
