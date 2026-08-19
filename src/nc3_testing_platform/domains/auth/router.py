"""The `/auth` operations: register, login, logout, session, password, MFA.

`register` and `login` are anonymous by construction (they mint the identity
everything else consumes) and sit behind the per-IP rate-limit dependencies.
Everything else requires the session cookie (`core/security.py`), which also
publishes the `SessionCookie` scheme into the contract entries. A pending-MFA
session is accepted by exactly three operations — `POST /auth/mfa/verify`
(completes the factor), `POST /auth/logout` (revocation needs no assurance),
and `GET /auth/session` (a reload mid-login must render the prompt) — via
`PendingMfaSession`. Cookie writes happen here and nowhere else.
"""

from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from sqlalchemy.orm import Session

from nc3_testing_platform.core import rls
from nc3_testing_platform.core.api_db import AuthDbSession
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.security import (
    NO_STORE_HEADERS,
    SESSION_COOKIE_CLEAR,
    SESSION_COOKIE_NAME,
    CurrentMfaAssuredSession,
    CurrentSession,
    PendingMfaSession,
    rate_limited,
)
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.domains.auth import service
from nc3_testing_platform.domains.auth.dependencies import (
    LoginRateLimited,
    MfaVerifyRateLimited,
    RegisterRateLimited,
)
from nc3_testing_platform.domains.auth.models import UserSession
from nc3_testing_platform.domains.auth.schemas import (
    LoginSubmission,
    MfaConfirmSubmission,
    MfaDisableSubmission,
    MfaEnrollment,
    MfaEnrollSubmission,
    MfaVerifySubmission,
    PasswordChangeSubmission,
    RecoveryCodes,
    RecoveryCodesRegenerateSubmission,
    RegisteredUser,
    RegistrationSubmission,
    SessionInfo,
)
from nc3_testing_platform.domains.org.models import AppUser

router = APIRouter(prefix="/auth", tags=["auth"])


def _set_session_cookie(response: Response, token: str) -> None:
    # `__Host-` requires Secure and Path=/ with no Domain; SameSite=Lax plus
    # the origin-check middleware are the CSRF countermeasures (IDR-010).
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )


def _session_info(db: Session, user: AppUser, session: UserSession) -> SessionInfo:
    idle_expires_at, absolute_expires_at = service.session_expiries(session)
    mfa_enrolled, codes_remaining = service.mfa_status(db, user.id)
    mfa_required = mfa_enrolled and session.mfa_verified_at is None
    assurance_expires_at = (
        session.mfa_verified_at
        + timedelta(seconds=settings.auth_mfa_assurance_max_age_seconds)
        if session.mfa_verified_at is not None
        else None
    )
    return SessionInfo(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        # A pending session withholds the profile fields: a correct password
        # alone reveals nothing it did not itself prove.
        display_name=None if mfa_required else user.display_name,
        organization_role=None if mfa_required else user.organization_role,
        session_created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
        mfa_enrolled=mfa_enrolled,
        mfa_required=mfa_required,
        mfa_verified_at=session.mfa_verified_at,
        mfa_assurance_expires_at=assurance_expires_at,
        recovery_codes_remaining=codes_remaining,
    )


def _consent_validation_error(exc: service.ConsentError) -> RequestValidationError:
    """Consent gaps in the shape of every other validation failure."""
    errors = [
        {
            "type": "value_error",
            "loc": ("body", "statement_responses"),
            "msg": f"Missing acceptance of {key!r} version {version!r}.",
            "input": None,
        }
        for key, version in exc.missing
    ] + [
        {
            "type": "value_error",
            "loc": ("body", "statement_responses"),
            "msg": f"Unknown statement {key!r} version {version!r}.",
            "input": None,
        }
        for key, version in exc.unknown
    ]
    return RequestValidationError(errors)


@router.post(
    "/register",
    status_code=status.HTTP_201_CREATED,
    summary="Register a platform-local account",
    responses={**problem_responses(409, 422, 500), **rate_limited()},
    dependencies=[RegisterRateLimited],
)
def register(
    body: RegistrationSubmission, request: Request, db: AuthDbSession
) -> RegisteredUser:
    """Provision the account and its workspace organization (IDR-016).

    The registrant becomes `organization_admin` of a fresh workspace, and the
    consent receipts for every active account-level statement are recorded
    atomically with the account. Registration does not log in — call
    `POST /auth/login` next.
    """
    try:
        user = service.register(
            db,
            body,
            client_ip=request.client.host if request.client else "unknown",
            user_agent=request.headers.get("user-agent", "")[:400],
        )
    except service.ConsentError as exc:
        raise _consent_validation_error(exc) from None
    except service.EmailTakenError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        ) from None
    return RegisteredUser(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        display_name=user.display_name,
        organization_role=user.organization_role,
    )


@router.post(
    "/login",
    summary="Log in with email and password",
    responses={**problem_responses(401, 422, 500), **rate_limited()},
    dependencies=[LoginRateLimited],
)
def login(
    body: LoginSubmission, response: Response, db: AuthDbSession
) -> SessionInfo:
    """Open a server-side session and set the `__Host-session` cookie.

    Unknown email, disabled account, and wrong password all answer the same
    `401`. A locked account answers `429` with `Retry-After`. An MFA-enrolled
    account receives a **pending** session (`mfa_required` true, profile
    fields withheld): complete login via `POST /auth/mfa/verify`.
    """
    try:
        result = service.login(db, email=body.email, password=body.password)
    except service.AccountLockedError as exc:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="The account is temporarily locked after repeated failures.",
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from None
    except service.InvalidCredentialsError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        ) from None
    _set_session_cookie(response, result.token)
    # The service committed (durability before the response), which ended the
    # SET LOCAL context; the body's MFA-status read needs the user arm again.
    rls.set_user_context(db, result.user.id)
    return _session_info(db, result.user, result.session)


@router.get(
    "/session",
    summary="The authenticated session",
    responses=problem_responses(401),
)
def read_session(current: PendingMfaSession, db: AuthDbSession) -> SessionInfo:
    """The current user, organization, and server-side expiry horizon.

    Accepts a pending-MFA session, reporting `mfa_required` with the profile
    fields withheld, so a reload mid-login can render the second-factor step.
    """
    user, session = service.session_snapshot(
        db, user_id=current.user_id, session_id=current.session_id
    )
    return _session_info(db, user, session)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out",
    responses=problem_responses(401),
)
def logout(
    current: PendingMfaSession, response: Response, db: AuthDbSession
) -> None:
    """Revoke the session server-side and clear the cookie.

    Accepts a pending-MFA session: revocation needs no assurance, and an
    abandoned or suspect pending login must be killable on the spot.
    """
    service.logout(db, current.session_id)
    response.headers["Set-Cookie"] = SESSION_COOKIE_CLEAR


@router.post(
    "/password",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Change the password",
    responses=problem_responses(401, 403, 422, 500),
)
def change_password(
    body: PasswordChangeSubmission,
    current: CurrentSession,
    response: Response,
    db: AuthDbSession,
) -> None:
    """Verify the current password, re-encrypt, and rotate every session.

    Sessions on other devices are revoked; this one is replaced and the new
    cookie is set on the response (session regeneration on privilege change).
    """
    try:
        result = service.change_password(
            db,
            user_id=current.user_id,
            current_session_id=current.session_id,
            current_password=body.current_password,
            new_password=body.new_password,
        )
    except service.WrongCurrentPasswordError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The current password did not verify.",
        ) from None
    _set_session_cookie(response, result.token)


def _mfa_locked(exc: service.MfaLockedError) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="MFA verification is temporarily locked after repeated failures.",
        headers={"Retry-After": str(exc.retry_after_seconds)},
    )


def _wrong_password() -> HTTPException:
    # A fresh instance per raise: a module-global shared across requests
    # would accumulate `__traceback__` frames — including this handler's
    # locals, which hold the submitted plaintext password — on one object
    # reachable for the life of the process.
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="The current password did not verify.",
    )


def _invalid_code() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="The code did not verify.",
    )


def _session_revoked() -> HTTPException:
    # Same shape and clear-cookie treatment as core/security.py's
    # `_session_refused`: the session died mid-request, so the client's
    # cached cookie is as dead as the row it named.
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated: the session is missing, expired, or revoked.",
        headers={"Set-Cookie": SESSION_COOKIE_CLEAR},
    )


@router.post(
    "/mfa/enroll",
    status_code=status.HTTP_201_CREATED,
    summary="Start TOTP enrollment",
    responses={
        201: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 403, 409, 422, 500),
    },
)
def enroll_mfa(
    body: MfaEnrollSubmission,
    current: CurrentSession,
    response: Response,
    db: AuthDbSession,
) -> MfaEnrollment:
    """Mint a TOTP seed and return the provisioning material once.

    Requires the current password — enrollment is a privilege change. A
    confirmed factor answers `409`: disable it first. Restarting an
    unconfirmed enrollment replaces the seed.
    """
    try:
        enrollment = service.enroll_mfa(
            db, user_id=current.user_id, password=body.password
        )
    except service.WrongCurrentPasswordError:
        raise _wrong_password() from None
    except service.MfaAlreadyEnrolledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already enrolled; disable it before re-enrolling.",
        ) from None
    response.headers["Cache-Control"] = "no-store"
    return MfaEnrollment(
        secret_base32=enrollment.secret_base32,
        otpauth_uri=enrollment.otpauth_uri,
    )


@router.post(
    "/mfa/confirm",
    summary="Confirm enrollment and mint the recovery codes",
    responses={
        200: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 403, 409, 422, 500),
        **rate_limited(),
    },
    # Shares the auth:mfa:{ip} bucket with verify: a combined per-IP guess
    # budget across every code-consuming MFA endpoint.
    dependencies=[MfaVerifyRateLimited],
)
def confirm_mfa(
    body: MfaConfirmSubmission,
    current: CurrentSession,
    response: Response,
    db: AuthDbSession,
) -> RecoveryCodes:
    """Prove possession of the authenticator and activate the factor.

    The calling session becomes assured and every other session is revoked
    (privilege change). The recovery codes are shown exactly once.
    """
    try:
        codes = service.confirm_mfa(
            db,
            user_id=current.user_id,
            session_id=current.session_id,
            code=body.totp_code,
        )
    except service.MfaNotEnrolledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No enrollment to confirm; start with POST /auth/mfa/enroll.",
        ) from None
    except service.MfaAlreadyEnrolledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA is already confirmed.",
        ) from None
    except service.MfaLockedError as exc:
        raise _mfa_locked(exc) from None
    except service.InvalidMfaCodeError:
        raise _invalid_code() from None
    except service.SessionRevokedError:
        raise _session_revoked() from None
    response.headers["Cache-Control"] = "no-store"
    return RecoveryCodes(recovery_codes=codes)


@router.post(
    "/mfa/verify",
    summary="Complete login or refresh MFA assurance",
    responses={**problem_responses(401, 403, 409, 422, 500), **rate_limited()},
    dependencies=[MfaVerifyRateLimited],
)
def verify_mfa(
    body: MfaVerifySubmission,
    current: PendingMfaSession,
    response: Response,
    db: AuthDbSession,
) -> SessionInfo:
    """Present a TOTP or recovery code against the confirmed factor.

    On a pending session this completes login: the session is rotated and
    the fresh cookie set (assurance starts now). On an assured session it
    refreshes the assurance stamp in place — the step-up for operations that
    answer `403` with problem type `mfa-stepup-required`.
    """
    pending = current.mfa_enrolled and current.mfa_verified_at is None
    try:
        result = service.verify_mfa(
            db,
            user_id=current.user_id,
            session_id=current.session_id,
            pending=pending,
            totp_code=body.totp_code,
            recovery_code=body.recovery_code,
        )
    except service.MfaNotEnrolledError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No confirmed MFA factor exists on this account.",
        ) from None
    except service.MfaLockedError as exc:
        raise _mfa_locked(exc) from None
    except service.InvalidMfaCodeError:
        raise _invalid_code() from None
    except service.SessionRevokedError:
        raise _session_revoked() from None
    # Same post-commit context re-assertion as the login handler.
    rls.set_user_context(db, current.user_id)
    if result is not None:
        _set_session_cookie(response, result.token)
        return _session_info(db, result.user, result.session)
    user, session = service.session_snapshot(
        db, user_id=current.user_id, session_id=current.session_id
    )
    return _session_info(db, user, session)


@router.post(
    "/mfa/recovery-codes",
    summary="Regenerate the recovery codes",
    responses={
        200: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 403, 409, 422, 500),
    },
)
def regenerate_recovery_codes(
    body: RecoveryCodesRegenerateSubmission,
    current: CurrentMfaAssuredSession,
    response: Response,
    db: AuthDbSession,
) -> RecoveryCodes:
    """Replace the whole recovery-code set; the previous set stops working.

    Requires current MFA assurance and the current password: a hijacked
    assured session must not silently invalidate the owner's codes.
    """
    try:
        codes = service.regenerate_recovery_codes(
            db, user_id=current.user_id, password=body.password
        )
    except service.WrongCurrentPasswordError:
        raise _wrong_password() from None
    except service.MfaNotEnrolledError:  # pragma: no cover - gate proved it
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No confirmed MFA factor exists on this account.",
        ) from None
    response.headers["Cache-Control"] = "no-store"
    return RecoveryCodes(recovery_codes=codes)


@router.post(
    "/mfa/disable",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable MFA",
    responses={**problem_responses(401, 403, 409, 422, 500), **rate_limited()},
    # Shares the auth:mfa:{ip} bucket with verify: a combined per-IP guess
    # budget across every code-consuming MFA endpoint.
    dependencies=[MfaVerifyRateLimited],
)
def disable_mfa(
    body: MfaDisableSubmission,
    current: CurrentMfaAssuredSession,
    response: Response,
    db: AuthDbSession,
) -> None:
    """Soft-revoke the factor behind fresh assurance, password, and a code.

    Sessions rotate (privilege change): the new cookie is set on this
    response, other sessions are revoked. Spent material stays behind for
    incident response; nothing is hard-deleted.
    """
    try:
        result = service.disable_mfa(
            db,
            user_id=current.user_id,
            current_session_id=current.session_id,
            password=body.password,
            totp_code=body.totp_code,
            recovery_code=body.recovery_code,
        )
    except service.WrongCurrentPasswordError:
        raise _wrong_password() from None
    except service.MfaNotEnrolledError:  # pragma: no cover - gate proved it
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="No confirmed MFA factor exists on this account.",
        ) from None
    except service.MfaLockedError as exc:
        raise _mfa_locked(exc) from None
    except service.InvalidMfaCodeError:
        raise _invalid_code() from None
    _set_session_cookie(response, result.token)
