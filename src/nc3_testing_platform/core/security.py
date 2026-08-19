"""Security schemes, the session dependency, and the rate-limit response contract.

Since B3 (US #79) the platform is its own identity provider (Non-functional
v0.11): registration, argon2id credentials, and sessions are platform-managed
in `domains/auth`. Browser authentication is one server-side `user_session`
row behind one `__Host-` cookie (IDR-010). The live gates in this module are
the two session dependencies (full and pending-MFA, B4) and the session-based
MFA assurance gate; everything the session needs before an RLS context exists
goes through the `auth_session_bootstrap` SECURITY DEFINER lookup (IDR-012),
while MFA state is read in-policy after the user arm opens.

The OpenID Connect and API-key schemes stay published in the contract:
API keys remain machine-to-machine only and their verification lands with the
API-key story, while the OIDC scheme is the federation seam of a later phase —
v4.0 ships no SSO, so its discovery URL keeps a reserved-invalid default and
`verify_token` stays a `NotImplementedError` seam.

`auto_error` is off throughout. The declaration-only dependencies publish
requirements into the contract for operations that are still live mocks.

Developer note: A frontend may route calls through its own proxy backend
("BFF"). That changes how the browser authenticates to the BFF, not this
contract: the BFF calls this API as an ordinary client.
"""

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Annotated
from uuid import UUID

import sqlalchemy as sa
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie, APIKeyHeader, OpenIdConnect
from sqlalchemy.orm import Session

from nc3_testing_platform.core import rls
from nc3_testing_platform.core.api_db import AuthDbSession
from nc3_testing_platform.core.errors import (
    PROBLEM_MEDIA_TYPE,
    PROBLEM_MFA_ENROLLMENT_REQUIRED,
    PROBLEM_MFA_REQUIRED,
    PROBLEM_MFA_STEPUP_REQUIRED,
    ProblemDetail,
    ProblemException,
)
from nc3_testing_platform.core.settings import settings

# Re-exported name; the environment read lives on the settings module.
OIDC_DISCOVERY_URL = settings.oidc_discovery_url

oidc = OpenIdConnect(
    openIdConnectUrl=OIDC_DISCOVERY_URL,
    scheme_name="OpenIdConnect",
    auto_error=False,
    description=(
        "OpenID Connect token — the federation seam of a later SSO phase; "
        "v4.0 ships no SSO and issues no tokens. When federation lands, the "
        "token's `amr`/`auth_time` populate the platform session's MFA "
        "assurance at login; the currency rule stays platform-side."
    ),
)

api_key = APIKeyHeader(
    name="Authorization",
    scheme_name="ApiKey",
    auto_error=False,
    description=(
        "Platform API key: `Authorization: Bearer <key>`. Scopes are `read_only` "
        "and `full_scan`. A scan launched with a key is recorded with "
        "`source = api`. Creating or revoking a key requires a browser session "
        "with current MFA assurance — a key carries no assurance."
    ),
)

SESSION_COOKIE_NAME = "__Host-session"

session_cookie = APIKeyCookie(
    name=SESSION_COOKIE_NAME,
    scheme_name="SessionCookie",
    auto_error=False,
    description=(
        "Browser session cookie set by `POST /auth/login`. HttpOnly, Secure, "
        "SameSite=Lax; the session record and its idle/absolute timeouts are "
        "enforced server-side."
    ),
)

OidcAuth = Annotated[str | None, Depends(oidc)]
ApiKeyAuth = Annotated[str | None, Depends(api_key)]
SessionAuth = Annotated[str | None, Depends(session_cookie)]

# Clears the session cookie on the response that refuses it, so a browser
# stops replaying a token the server will never accept again.
SESSION_COOKIE_CLEAR = (
    f'{SESSION_COOKIE_NAME}=""; HttpOnly; Max-Age=0; Path=/; '
    "SameSite=lax; Secure"
)


def hash_session_token(token: str) -> bytes:
    """The stored form of a session token: its SHA-256 digest.

    A hash, not an encryption: the value must stay an index key for the
    pre-context SECURITY DEFINER lookup, and it never needs to be reversed —
    session rows are hard-deleted on erasure, so there is nothing to
    crypto-shred.
    """
    return hashlib.sha256(token.encode("ascii")).digest()


@dataclass(frozen=True)
class AuthenticatedSession:
    """The request's authenticated identity, resolved from the session cookie."""

    session_id: UUID
    user_id: UUID
    organization_id: UUID
    # MFA state (B4): enrollment derived from `user_mfa`, assurance from the
    # session row (§13.6), and the database clock the currency check compares
    # against. Defaults keep pre-B4 constructions (tests, fakes) valid.
    mfa_enrolled: bool = False
    mfa_verified_at: datetime | None = None
    observed_at: datetime | None = None


# The pre-context lookup (IDR-012): runs as the nc3_auth_definer-owned
# SECURITY DEFINER function because before identity is known no RLS arm can
# open. Raw SQL, not the ORM model — core must not import `domains/auth`.
_SESSION_BOOTSTRAP = sa.text(
    "SELECT session_id, user_id, organization_id, session_created_at,"
    " last_seen_at, revoked_at, user_disabled_at, observed_at"
    " FROM public.auth_session_bootstrap(:token_hash)"
)
_SESSION_TOUCH = sa.text(
    "UPDATE user_session SET last_seen_at = now() WHERE id = :session_id"
)


def _session_refused(clear_cookie: bool) -> HTTPException:
    headers = {"Set-Cookie": SESSION_COOKIE_CLEAR} if clear_cookie else None
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated: the session is missing, expired, or revoked.",
        headers=headers,
    )


# In-policy MFA state, read after the user arm opens: assurance lives on the
# session row and enrollment is derived from `user_mfa` (§13.6). Deliberately
# NOT part of the definer bootstrap, whose read surface stays at B3's three
# tables — the definer owner never reaches the seed table. Raw SQL, not the
# ORM model — core must not import `domains/auth`.
_MFA_STATE = sa.text(
    "SELECT s.mfa_verified_at,"
    " EXISTS (SELECT 1 FROM user_mfa m"
    " WHERE m.user_id = :user_id AND m.confirmed_at IS NOT NULL)"
    " AS mfa_enrolled"
    " FROM user_session s WHERE s.id = :session_id"
)


def _resolve_session(
    token: str | None, db: Session, *, allow_pending: bool
) -> AuthenticatedSession:
    """The single owner of session policy behind both session dependencies.

    Timeout policy runs application-side against the database clock returned
    by the lookup (idle and absolute caps, Non-functional v0.11); the
    `last_seen_at` touch is an in-policy UPDATE under the user context, never
    a definer write. Every failure answers `401`; expiry and revocation clear
    the cookie, the pending-MFA refusal keeps it — that session is live and
    exactly what `POST /auth/mfa/verify` consumes.
    """
    if not token:
        raise _session_refused(clear_cookie=False)
    row = db.execute(
        _SESSION_BOOTSTRAP, {"token_hash": hash_session_token(token)}
    ).one_or_none()
    if row is None or row.revoked_at is not None or row.user_disabled_at is not None:
        raise _session_refused(clear_cookie=True)
    idle = timedelta(seconds=settings.auth_session_idle_seconds)
    absolute = timedelta(seconds=settings.auth_session_absolute_seconds)
    if (
        row.observed_at - row.session_created_at >= absolute
        or row.observed_at - row.last_seen_at >= idle
    ):
        raise _session_refused(clear_cookie=True)
    rls.set_user_context(db, row.user_id)
    state = db.execute(
        _MFA_STATE, {"user_id": row.user_id, "session_id": row.session_id}
    ).one()
    if (
        not allow_pending
        and state.mfa_enrolled
        and state.mfa_verified_at is None
    ):
        raise ProblemException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=(
                "The session awaits its second factor: "
                "complete login via POST /auth/mfa/verify."
            ),
            problem_type=PROBLEM_MFA_REQUIRED,
        )
    db.execute(_SESSION_TOUCH, {"session_id": row.session_id})
    return AuthenticatedSession(
        session_id=row.session_id,
        user_id=row.user_id,
        organization_id=row.organization_id,
        mfa_enrolled=bool(state.mfa_enrolled),
        mfa_verified_at=state.mfa_verified_at,
        observed_at=row.observed_at,
    )


def require_session(token: SessionAuth, db: AuthDbSession) -> AuthenticatedSession:
    """Resolve the session cookie to a fully authenticated identity.

    An MFA-enrolled session that has not completed its second factor answers
    problem type `mfa-required` (`401`, cookie kept). Only the operations on
    :data:`PendingMfaSession` accept such a session.
    """
    return _resolve_session(token, db, allow_pending=False)


def require_pending_or_current_session(
    token: SessionAuth, db: AuthDbSession
) -> AuthenticatedSession:
    """Resolve the session cookie, accepting a pending-MFA session.

    Same lookup, timeout, and revocation policy as :func:`require_session` —
    only the pending refusal is skipped. The scope stays deliberately tiny:
    the MFA verify (completes the factor), logout (revocation needs no
    assurance), and the session view (a reload mid-login must still render
    the second-factor prompt). A test pins the exact operation set.
    """
    return _resolve_session(token, db, allow_pending=True)


CurrentSession = Annotated[AuthenticatedSession, Depends(require_session)]
PendingMfaSession = Annotated[
    AuthenticatedSession, Depends(require_pending_or_current_session)
]


def require_authentication(oidc_token: OidcAuth, key: ApiKeyAuth) -> None:
    """Declares that the operation requires one of the two credentials.

    The parameter list is the entire effect:
    FastAPI reads the two credential dependencies and publishes both schemes into the operation's `security`.
    Verification of a presented credential is :func:`verify_token` and :func:`verify_api_key`.
    """


# Attach as `dependencies=[CredentialRequired]` on an operation.
CredentialRequired = Depends(require_authentication)


def require_current_mfa_assurance(current: CurrentSession) -> AuthenticatedSession:
    """The session, proven to carry current MFA assurance.

    Identity, not authorization: role gates (e.g. IDR-016's admin-only
    verification) stay with the operation. Currency is
    `settings.auth_mfa_assurance_max_age_seconds` against the database clock;
    a step-up `POST /auth/mfa/verify` refreshes the stamp.
    """
    if not current.mfa_enrolled:
        raise ProblemException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "This operation requires MFA: "
                "enroll via POST /auth/mfa/enroll first."
            ),
            problem_type=PROBLEM_MFA_ENROLLMENT_REQUIRED,
        )
    max_age = timedelta(seconds=settings.auth_mfa_assurance_max_age_seconds)
    if (
        current.mfa_verified_at is None
        or current.observed_at is None
        or current.observed_at - current.mfa_verified_at >= max_age
    ):
        raise ProblemException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "MFA assurance has aged out: "
                "step up via POST /auth/mfa/verify."
            ),
            problem_type=PROBLEM_MFA_STEPUP_REQUIRED,
        )
    return current


# Attach as `dependencies=[MfaAssuranceRequired]`, or take the parameter form
# `CurrentMfaAssuredSession` when the handler needs the identity.
MfaAssuranceRequired = Depends(require_current_mfa_assurance)
CurrentMfaAssuredSession = Annotated[
    AuthenticatedSession, Depends(require_current_mfa_assurance)
]


def declare_mfa_assurance(token: SessionAuth) -> None:
    """Declares the SessionCookie scheme and its assurance rule, enforcing nothing.

    The parameter list is the entire effect. Belongs on assurance-gated
    operations that are still live mocks (assets verification, API keys):
    B6 and the API-key story swap this for the live
    :data:`MfaAssuranceRequired` when the handlers become real — a live gate
    today would put a full enroll flow in front of mock sample data.
    """


# Attach as `dependencies=[MfaAssuranceDeclared]` on a mock operation.
MfaAssuranceDeclared = Depends(declare_mfa_assurance)


def verify_token(token: str) -> dict[str, object]:
    """The verified claims of an OpenID Connect token.

    Verification covers the signature against the identity provider's published keys, the issuer, the audience, and the expiry.
    A failure answers `401` with a `WWW-Authenticate: Bearer` challenge.
    """
    raise NotImplementedError


def verify_api_key(key: str) -> None:
    """Validates a platform API key against its stored hash.

    A failure answers `401`.
    """
    raise NotImplementedError


def verify_claim_token(token: str) -> None:
    """Validates a guest scan's claim token against the job's stored hash.

    A failure answers `404`, so an unclaimed scan is indistinguishable from an absent one.
    """
    raise NotImplementedError


def verify_feed_token(token: str) -> None:
    """Validates a feed token against its stored hash.

    An unknown token answers `404`; a revoked feed answers `410`.
    """
    raise NotImplementedError


def require_platform_admin(claims: dict[str, object]) -> None:
    """Rejects claims that do not carry the identity provider's platform-administrator claim.

    A failure answers `403`.
    """
    raise NotImplementedError


def read_optional_credentials(oidc_token: OidcAuth, key: ApiKeyAuth) -> None:
    """Declares both credentials without requiring either.

    The parameter list is the entire effect:
    FastAPI reads the two credential dependencies and publishes both schemes into the operation's `security`.
    The body applies no gate, because a guest presents a claim token in place of a credential.

    Belongs on an operation that an owner reaches with a credential and a guest reaches with a claim token.
    """


# Attach as `dependencies=[OptionallyAuthenticated]`, together with
# ANONYMOUS_ALTERNATIVE in `openapi_extra`, so the operation declares both schemes
# and the anonymous alternative.
OptionallyAuthenticated = Depends(read_optional_credentials)

# Adds the anonymous alternative to an operation's `security`, marking it callable
# without credentials.
ANONYMOUS_ALTERNATIVE: list[dict[str, list[str]]] = [{}]

# Declared on a response no cache may store: secret-bearing bodies and feed delivery.
NO_STORE_HEADERS: dict[str, dict] = {
    "Cache-Control": {
        "schema": {"type": "string"},
        "description": "Always `no-store`.",
    }
}


# IETF-draft rate-limit headers, surfaced on quota-bearing responses. Counters
# themselves live in the anti-abuse subsystem, outside this model.
RATE_LIMIT_HEADERS: dict[str, dict] = {
    "RateLimit": {
        "schema": {"type": "string"},
        "description": "Quota-window state, e.g. `limit=100, remaining=42, reset=30`.",
    },
    "RateLimit-Policy": {
        "schema": {"type": "string"},
        "description": "Advertised quota policy, e.g. `100;w=60`.",
    },
    "Retry-After": {
        "schema": {"type": "integer"},
        "description": "Seconds until the quota resets. Sent with `429`.",
    },
}


def rate_limited() -> dict[int | str, dict]:
    """A `429` response carrying the rate-limit headers and a problem body.

    Merge into the ``responses`` of any operation under a guest, user, or
    organization quota.
    """
    return {
        429: {
            "model": ProblemDetail,
            "description": "Too Many Requests",
            "content": {PROBLEM_MEDIA_TYPE: {}},
            "headers": RATE_LIMIT_HEADERS,
        }
    }
