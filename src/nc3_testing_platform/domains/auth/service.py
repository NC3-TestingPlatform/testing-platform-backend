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

Success paths that mint client-actionable state (an account, a session
token, an assurance stamp, recovery codes) also commit explicitly before
returning: the unit-of-work commit lives in dependency teardown, which runs
after the response is sent, so an immediate follow-up request — register →
login, login → verify — would otherwise race its own durability (observed
live, US #80). The teardown commit remains as the safety net for writes that
need no read-your-response guarantee, like the session touch.

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
from nc3_testing_platform.domains.auth import repository, totp
from nc3_testing_platform.domains.auth.models import (
    UserCredential,
    UserMfa,
    UserSession,
)
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
_MFA_SECRET_AAD = b"user_mfa.totp_secret"

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
    """A step-up action refused: the current password did not verify."""


class MfaAlreadyEnrolledError(Exception):
    """MFA is already confirmed — disable it before re-enrolling."""


class MfaNotEnrolledError(Exception):
    """No confirmed (or, for confirm, started) MFA enrollment exists."""


class InvalidMfaCodeError(Exception):
    """Wrong, replayed, or already-spent code — one indistinguishable answer."""


class SessionRevokedError(Exception):
    """The session was revoked concurrently, mid-request, by another caller."""


class MfaLockedError(Exception):
    """MFA verification is locked out after repeated failures."""

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = retry_after_seconds
        super().__init__(f"locked for {retry_after_seconds}s")


@dataclass(frozen=True)
class LoginResult:
    """A fresh session: the plaintext token exists only in this value."""

    token: str
    user: AppUser
    session: UserSession


@dataclass(frozen=True)
class MfaEnrollment:
    """The TOTP provisioning material, shown once at enrollment."""

    secret_base32: str
    otpauth_uri: str


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
    # Durable before the 201: the client's very next call is the login.
    db.commit()
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
    db.commit()
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


def _open_session(
    db: Session, user_id: uuid.UUID, *, assured_at: datetime | None = None
) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    session = UserSession(
        user_id=user_id,
        token_hash=hash_session_token(token),
        mfa_verified_at=assured_at,
    )
    db.add(session)
    db.flush()
    return token, session


def logout(db: Session, session_id: uuid.UUID) -> None:
    """Revoke the session; the router clears the cookie."""
    repository.revoke_session(db, session_id)
    db.commit()


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
    user_kek = _verify_current_password(db, user_id, current_password)
    credential = repository.credential_for(db, user_id)
    if credential is None:  # pragma: no cover - registration always creates it
        raise WrongCurrentPasswordError

    credential.password_ciphertext = _encrypt_password(new_password, user_kek)
    credential.password_updated_at = sa.func.now()
    repository.revoke_other_sessions(db, user_id, keep_session_id=current_session_id)
    repository.revoke_session(db, current_session_id)
    user = repository.user_by_id(db, user_id)
    if user is None:  # pragma: no cover - the session just proved it exists
        raise WrongCurrentPasswordError
    token, session = _open_session(db, user_id)
    logger.info("password changed for user %s; sessions rotated", user_id)
    db.commit()
    return LoginResult(token=token, user=user, session=session)


# --- MFA (B4 / US #80). Log lines carry UUIDs and event names only: the
# secret, the otpauth URI, and the recovery codes are never logged.


def _verify_current_password(
    db: Session, user_id: uuid.UUID, password: SecretStr
) -> bytes:
    """Verify the password and return the unwrapped user KEK.

    The shared step-up gate: password change, MFA enrollment, disable, and
    recovery-code regeneration all re-authenticate — a stolen session cookie
    alone must not reach any of them.

    :raises WrongCurrentPasswordError: When the password does not verify.
    """
    credential = repository.credential_for(db, user_id)
    if credential is None:  # pragma: no cover - registration always creates it
        raise WrongCurrentPasswordError
    user_kek = _unwrap_user_kek(db, user_id)
    stored = crypto.decrypt(
        credential.password_ciphertext, user_kek, aad=_CREDENTIAL_AAD
    ).decode("ascii")
    try:
        _hasher.verify(stored, password.get_secret_value())
    except VerifyMismatchError:
        raise WrongCurrentPasswordError from None
    return user_kek


def _db_now(db: Session) -> datetime:
    """The database clock, so every lockout comparison matches the stamps."""
    return db.execute(sa.select(sa.func.now())).scalar_one()


def _confirmed_mfa(
    db: Session, user_id: uuid.UUID, *, for_update: bool = False
) -> UserMfa:
    """The user's confirmed factor row.

    ``for_update`` row-locks it for the transaction: every caller that goes
    on to check-and-consume a code (verify, disable) must serialize against
    a concurrent attempt on the same row (`repository.mfa_for_update`).
    Callers that only check enrollment (recovery-code regeneration) skip
    the lock — they never touch `last_used_step` or the failure counters.

    :raises MfaNotEnrolledError: When no confirmed enrollment exists.
    """
    row = (
        repository.mfa_for_update(db, user_id)
        if for_update
        else repository.mfa_for(db, user_id)
    )
    if row is None or row.confirmed_at is None or row.totp_secret_ciphertext is None:
        raise MfaNotEnrolledError
    return row


def _require_mfa_unlocked(row: UserMfa, observed_at: datetime) -> None:
    if row.locked_until is not None and row.locked_until > observed_at:
        remaining = row.locked_until - observed_at
        raise MfaLockedError(int(remaining.total_seconds()) + 1)


def _record_mfa_failure(
    db: Session, row: UserMfa, *, observed_at: datetime
) -> None:
    """Count one failed code; escalate the lockout at the threshold; persist.

    Stricter than the password lockout and escalating (doubling per
    consecutive lockout, capped): a 6-digit code space cannot afford the
    login numbers (`core/settings.py`). Commits explicitly, like
    :func:`_record_failure` — the caller raises next.
    """
    row.failed_count += 1
    if row.failed_count >= settings.auth_mfa_failed_threshold:
        row.lockout_count += 1
        duration = min(
            settings.auth_mfa_lockout_base_seconds * 2 ** (row.lockout_count - 1),
            settings.auth_mfa_lockout_cap_seconds,
        )
        row.locked_until = observed_at + timedelta(seconds=duration)
        row.failed_count = 0
        logger.warning(
            "mfa lockout %d applied to user %s for %ds",
            row.lockout_count,
            row.user_id,
            duration,
        )
    db.commit()


def _spend_code(
    db: Session,
    row: UserMfa,
    *,
    user_id: uuid.UUID,
    observed_at: datetime,
    totp_code: str | None,
    recovery_code: SecretStr | None,
) -> None:
    """Verify and consume one second-factor code against the confirmed row.

    Wrong, replayed, and already-spent codes are one indistinguishable
    :class:`InvalidMfaCodeError`, each counted toward the escalating lockout.
    On success the failure counters reset.
    """
    if totp_code is not None:
        ciphertext = row.totp_secret_ciphertext
        if ciphertext is None:  # pragma: no cover - _confirmed_mfa proved it
            raise MfaNotEnrolledError
        secret = crypto.decrypt(
            ciphertext, _unwrap_user_kek(db, user_id), aad=_MFA_SECRET_AAD
        )
        step = totp.matching_step(
            secret, totp_code, at_step=totp.step_at(observed_at.timestamp())
        )
        # Replay refusal: a step at or before the last accepted one is spent.
        # Deliberate consequence: after accepting step N+1 (clock skew), the
        # user's next code can be refused for up to one step (60 s).
        if step is None or (
            row.last_used_step is not None and step <= row.last_used_step
        ):
            _record_mfa_failure(db, row, observed_at=observed_at)
            raise InvalidMfaCodeError
        row.last_used_step = step
    elif recovery_code is not None:
        spent = repository.consume_recovery_code(
            db, user_id, totp.hash_recovery_code(recovery_code.get_secret_value())
        )
        if not spent:
            _record_mfa_failure(db, row, observed_at=observed_at)
            raise InvalidMfaCodeError
        logger.warning(
            "recovery code spent by user %s; %d remain",
            user_id,
            repository.unused_recovery_code_count(db, user_id),
        )
    else:
        raise ValueError("one of totp_code or recovery_code is required")
    row.failed_count = 0
    row.lockout_count = 0
    row.locked_until = None


def enroll_mfa(
    db: Session, *, user_id: uuid.UUID, password: SecretStr
) -> MfaEnrollment:
    """Start (or restart) TOTP enrollment; a confirmed factor refuses.

    Requires the current password: enrollment is a privilege change, and a
    stolen session must not be able to plant an attacker factor. Restarting
    an unconfirmed enrollment replaces the seed. The plaintext material
    exists only in the returned value.

    :raises WrongCurrentPasswordError: When the password does not verify.
    :raises MfaAlreadyEnrolledError: When a confirmed factor exists.
    """
    user_kek = _verify_current_password(db, user_id, password)
    row = repository.mfa_for(db, user_id)
    if row is not None and row.confirmed_at is not None:
        raise MfaAlreadyEnrolledError
    secret = totp.generate_secret()
    ciphertext = crypto.encrypt(secret, user_kek, aad=_MFA_SECRET_AAD)
    if row is None:
        db.add(UserMfa(user_id=user_id, totp_secret_ciphertext=ciphertext))
    else:
        row.totp_secret_ciphertext = ciphertext
        row.last_used_step = None
        row.failed_count = 0
    db.flush()
    user = repository.user_by_id(db, user_id)
    if user is None:  # pragma: no cover - the session just proved it exists
        raise WrongCurrentPasswordError
    logger.info("mfa enrollment started for user %s", user_id)
    # Durable before the 201: the client's very next call is the confirm.
    db.commit()
    return MfaEnrollment(
        secret_base32=totp.secret_base32(secret),
        otpauth_uri=totp.provisioning_uri(
            secret, account_name=user.email, issuer=settings.auth_totp_issuer
        ),
    )


def confirm_mfa(
    db: Session, *, user_id: uuid.UUID, session_id: uuid.UUID, code: str
) -> list[str]:
    """Prove possession, activate the factor, and mint the recovery codes.

    The calling session is stamped assured — possession was just proven —
    and every other session is revoked, the same privilege-change treatment
    as a password change. The returned codes exist only in this value.

    :raises MfaNotEnrolledError: When no enrollment was started.
    :raises MfaAlreadyEnrolledError: When the factor is already confirmed.
    :raises MfaLockedError: While the MFA lockout stands.
    :raises InvalidMfaCodeError: When the code does not verify.
    :raises SessionRevokedError: When the calling session was revoked
        concurrently, mid-request.
    """
    # Locked: this is a code-guessing surface (a wrong code counts toward
    # the lockout, same as verify/disable) — see `mfa_for_update`.
    row = repository.mfa_for_update(db, user_id)
    if row is None or row.totp_secret_ciphertext is None:
        raise MfaNotEnrolledError
    if row.confirmed_at is not None:
        raise MfaAlreadyEnrolledError
    observed_at = _db_now(db)
    _require_mfa_unlocked(row, observed_at)
    secret = crypto.decrypt(
        row.totp_secret_ciphertext,
        _unwrap_user_kek(db, user_id),
        aad=_MFA_SECRET_AAD,
    )
    step = totp.matching_step(
        secret, code, at_step=totp.step_at(observed_at.timestamp())
    )
    if step is None:
        _record_mfa_failure(db, row, observed_at=observed_at)
        raise InvalidMfaCodeError
    row.confirmed_at = observed_at
    row.last_used_step = step
    row.failed_count = 0
    row.lockout_count = 0
    row.locked_until = None
    if not repository.stamp_session_assurance(db, session_id):
        # Revoked concurrently between the router's gate check and this
        # write (e.g. a parallel logout): the factor is confirmed, but the
        # calling session no longer exists to be assured.
        raise SessionRevokedError
    repository.revoke_other_sessions(db, user_id, keep_session_id=session_id)
    codes = totp.generate_recovery_codes()
    repository.burn_recovery_codes(db, user_id)
    repository.insert_recovery_codes(
        db, user_id, [totp.hash_recovery_code(code) for code in codes]
    )
    logger.info("mfa confirmed for user %s; other sessions revoked", user_id)
    db.commit()
    return codes


def verify_mfa(
    db: Session,
    *,
    user_id: uuid.UUID,
    session_id: uuid.UUID,
    pending: bool,
    totp_code: str | None = None,
    recovery_code: SecretStr | None = None,
) -> LoginResult | None:
    """Complete a pending login, or refresh assurance on an assured session.

    A pending session is revoked and replaced — rotation on the
    pending→assured privilege change — and the fresh `LoginResult` carries
    the new cookie token. An assured session refreshes its stamp in place
    and returns ``None``.

    :raises MfaNotEnrolledError: When no confirmed factor exists.
    :raises MfaLockedError: While the MFA lockout stands.
    :raises InvalidMfaCodeError: When the code does not verify.
    :raises SessionRevokedError: When the calling session was revoked
        concurrently, mid-request (step-up path only).
    """
    row = _confirmed_mfa(db, user_id, for_update=True)
    observed_at = _db_now(db)
    _require_mfa_unlocked(row, observed_at)
    _spend_code(
        db,
        row,
        user_id=user_id,
        observed_at=observed_at,
        totp_code=totp_code,
        recovery_code=recovery_code,
    )
    if not pending:
        if not repository.stamp_session_assurance(db, session_id):
            # Same concurrent-revoke race as confirm_mfa: fail closed rather
            # than report a step-up that was never actually granted.
            raise SessionRevokedError
        logger.info("mfa step-up refreshed for user %s", user_id)
        db.commit()
        return None
    repository.revoke_session(db, session_id)
    user = repository.user_by_id(db, user_id)
    if user is None:  # pragma: no cover - the session just proved it exists
        raise MfaNotEnrolledError
    token, session = _open_session(db, user_id, assured_at=observed_at)
    logger.info("mfa verify completed login for user %s", user_id)
    db.commit()
    return LoginResult(token=token, user=user, session=session)


def disable_mfa(
    db: Session,
    *,
    user_id: uuid.UUID,
    current_session_id: uuid.UUID,
    password: SecretStr,
    totp_code: str | None = None,
    recovery_code: SecretStr | None = None,
) -> LoginResult:
    """Soft-revoke the factor behind password + a valid code; rotate sessions.

    The row and the spent codes stay behind (`nc3_auth` holds no DELETE):
    "MFA was disabled at T" is incident-response residue, not garbage.

    :raises WrongCurrentPasswordError: When the password does not verify.
    :raises MfaNotEnrolledError: When no confirmed factor exists.
    :raises MfaLockedError: While the MFA lockout stands.
    :raises InvalidMfaCodeError: When the code does not verify.
    """
    row = _confirmed_mfa(db, user_id, for_update=True)
    observed_at = _db_now(db)
    _require_mfa_unlocked(row, observed_at)
    _verify_current_password(db, user_id, password)
    _spend_code(
        db,
        row,
        user_id=user_id,
        observed_at=observed_at,
        totp_code=totp_code,
        recovery_code=recovery_code,
    )
    row.totp_secret_ciphertext = None
    row.confirmed_at = None
    row.last_used_step = None
    repository.burn_recovery_codes(db, user_id)
    repository.revoke_other_sessions(
        db, user_id, keep_session_id=current_session_id
    )
    repository.revoke_session(db, current_session_id)
    user = repository.user_by_id(db, user_id)
    if user is None:  # pragma: no cover - the session just proved it exists
        raise WrongCurrentPasswordError
    token, session = _open_session(db, user_id)
    logger.warning("mfa disabled for user %s; sessions rotated", user_id)
    db.commit()
    return LoginResult(token=token, user=user, session=session)


def regenerate_recovery_codes(
    db: Session, *, user_id: uuid.UUID, password: SecretStr
) -> list[str]:
    """Replace the whole recovery-code set; the old set is burned.

    The router additionally requires current assurance; the password gate
    here keeps a hijacked assured session from silently invalidating the
    owner's codes.

    :raises WrongCurrentPasswordError: When the password does not verify.
    :raises MfaNotEnrolledError: When no confirmed factor exists.
    """
    _verify_current_password(db, user_id, password)
    _confirmed_mfa(db, user_id)
    codes = totp.generate_recovery_codes()
    repository.burn_recovery_codes(db, user_id)
    repository.insert_recovery_codes(
        db, user_id, [totp.hash_recovery_code(code) for code in codes]
    )
    logger.warning("recovery codes regenerated for user %s", user_id)
    db.commit()
    return codes


def mfa_status(db: Session, user_id: uuid.UUID) -> tuple[bool, int | None]:
    """(enrolled, live recovery codes remaining) for the session view."""
    row = repository.mfa_for(db, user_id)
    enrolled = row is not None and row.confirmed_at is not None
    remaining = (
        repository.unused_recovery_code_count(db, user_id) if enrolled else None
    )
    return enrolled, remaining
