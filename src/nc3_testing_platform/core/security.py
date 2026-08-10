"""OpenAPI security schemes and the rate-limit response contract.

Contract-only, the identity provider itself is external.

The identity provider owns identity, credentials, authentication methods,
sessions, MFA enrollment, and current assurance; this service only projects
an `app_user` row from a verified subject. A caller therefore presents
either an OIDC token or a platform API key.

`auto_error` is off throughout.
Dependencies in this module declare requirements into the published contract and enforce nothing.
Credential verification and assurance evaluation are `NotImplementedError` seams, unwired while the application is a live mock.

Developer note: A frontend may route calls through its own proxy backend ("BFF").
That changes how the browser authenticates to the BFF (httpOnly session cookie),
not this contract: the BFF calls this API as an ordinary client, presenting an
OIDC bearer token or an API key.
"""

from typing import Annotated

from fastapi import Depends
from fastapi.security import APIKeyHeader, OpenIdConnect

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

OidcAuth = Annotated[str | None, Depends(oidc)]
ApiKeyAuth = Annotated[str | None, Depends(api_key)]


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
