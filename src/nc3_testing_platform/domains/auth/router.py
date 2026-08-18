"""The `/auth` operations: register, login, logout, session, password.

`register` and `login` are anonymous by construction (they mint the identity
everything else consumes) and sit behind the per-IP rate-limit dependencies.
The other three require the session cookie via `CurrentSession`
(`core/security.py`), which also publishes the `SessionCookie` scheme into
their contract entries. Cookie writes happen here and nowhere else.
"""

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError

from nc3_testing_platform.core.api_db import AuthDbSession
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.security import (
    SESSION_COOKIE_CLEAR,
    SESSION_COOKIE_NAME,
    CurrentSession,
    rate_limited,
)
from nc3_testing_platform.domains.auth import service
from nc3_testing_platform.domains.auth.dependencies import (
    LoginRateLimited,
    RegisterRateLimited,
)
from nc3_testing_platform.domains.auth.models import UserSession
from nc3_testing_platform.domains.auth.schemas import (
    LoginSubmission,
    PasswordChangeSubmission,
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


def _session_info(user: AppUser, session: UserSession) -> SessionInfo:
    idle_expires_at, absolute_expires_at = service.session_expiries(session)
    return SessionInfo(
        user_id=user.id,
        organization_id=user.organization_id,
        email=user.email,
        display_name=user.display_name,
        organization_role=user.organization_role,
        session_created_at=session.created_at,
        last_seen_at=session.last_seen_at,
        idle_expires_at=idle_expires_at,
        absolute_expires_at=absolute_expires_at,
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
    `401`. A locked account answers `429` with `Retry-After`.
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
    return _session_info(result.user, result.session)


@router.get(
    "/session",
    summary="The authenticated session",
    responses=problem_responses(401),
)
def read_session(current: CurrentSession, db: AuthDbSession) -> SessionInfo:
    """The current user, organization, and server-side expiry horizon."""
    user, session = service.session_snapshot(
        db, user_id=current.user_id, session_id=current.session_id
    )
    return _session_info(user, session)


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Log out",
    responses=problem_responses(401),
)
def logout(
    current: CurrentSession, response: Response, db: AuthDbSession
) -> None:
    """Revoke the session server-side and clear the cookie."""
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
