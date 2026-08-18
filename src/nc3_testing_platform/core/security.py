"""Security schemes, the session dependency, and the rate-limit response contract.

Since B3 (US #79) the platform is its own identity provider (Non-functional
v0.11): registration, argon2id credentials, and sessions are platform-managed
in `domains/auth`. Browser authentication is one server-side `user_session`
row behind one `__Host-` cookie (IDR-010), enforced by :func:`require_session`
— the only live gate in this module. Everything the session needs before an
RLS context exists goes through the `auth_session_bootstrap` SECURITY DEFINER
lookup (IDR-012).

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
from datetime import timedelta
from typing import Annotated
from uuid import UUID

import sqlalchemy as sa
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie, APIKeyHeader, OpenIdConnect

from nc3_testing_platform.core import rls
from nc3_testing_platform.core.api_db import AuthDbSession
from nc3_testing_platform.core.errors import PROBLEM_MEDIA_TYPE, ProblemDetail
from nc3_testing_platform.core.settings import settings

# Re-exported name; the environment read lives on the settings module.
OIDC_DISCOVERY_URL = settings.oidc_discovery_url

oidc = OpenIdConnect(
    openIdConnectUrl=OIDC_DISCOVERY_URL,
    scheme_name="OpenIdConnect",
    auto_error=False,
    description=(
        "OpenID Connect token issued by the platform identity provider. Some "
        "operations additionally require current MFA assurance, read from the "
        "token at request time."
    ),
)

api_key = APIKeyHeader(
    name="Authorization",
    scheme_name="ApiKey",
    auto_error=False,
    description=(
        "Platform API key: `Authorization: Bearer <key>`. Scopes are `read_only` "
        "and `full_scan`. A scan launched with a key is recorded with "
        "`source = api`. Creating or revoking a key requires an OpenID Connect "
        "token with current MFA assurance."
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


def require_session(token: SessionAuth, db: AuthDbSession) -> AuthenticatedSession:
    """Resolve the session cookie to an identity and open its RLS user arm.

    Timeout policy runs application-side against the database clock returned
    by the lookup (idle and absolute caps, Non-functional v0.11); the
    `last_seen_at` touch is an in-policy UPDATE under the user context, never
    a definer write. Every failure answers `401` and clears the cookie.
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
    db.execute(_SESSION_TOUCH, {"session_id": row.session_id})
    return AuthenticatedSession(
        session_id=row.session_id,
        user_id=row.user_id,
        organization_id=row.organization_id,
    )


CurrentSession = Annotated[AuthenticatedSession, Depends(require_session)]


def require_authentication(oidc_token: OidcAuth, key: ApiKeyAuth) -> None:
    """Declares that the operation requires one of the two credentials.

    The parameter list is the entire effect:
    FastAPI reads the two credential dependencies and publishes both schemes into the operation's `security`.
    Verification of a presented credential is :func:`verify_token` and :func:`verify_api_key`.
    """


# Attach as `dependencies=[CredentialRequired]` on an operation.
CredentialRequired = Depends(require_authentication)


def require_oidc_token(oidc_token: OidcAuth) -> None:
    """Declares that the operation accepts only the OpenID Connect scheme.

    Belongs on an operation that consumes current MFA assurance:
    assurance is read from the identity provider's token, which a platform API key cannot carry.
    Verification and assurance evaluation are :func:`verify_token` and :func:`require_current_mfa_assurance`.
    """


# Attach as `dependencies=[OidcRequired]` on an operation.
OidcRequired = Depends(require_oidc_token)


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


def require_current_mfa_assurance(claims: dict[str, object]) -> None:
    """Rejects claims whose authentication event lacks current MFA assurance.

    Assurance is `amr` carrying an MFA method within the configured `max_age`.
    A failure answers `401` with the RFC 9470 `insufficient_user_authentication` challenge.
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
