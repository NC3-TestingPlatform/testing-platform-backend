"""OpenAPI security schemes and the rate-limit response contract.

Contract-only, the identity provider itself is external.

The identity provider owns identity, credentials, authentication methods,
sessions, MFA enrollment, and current assurance; this service only projects
an `app_user` row from a verified subject. A caller therefore presents
either an OIDC token or a platform API key.

`auto_error` is off throughout, authentication gates are server-side and
evaluated per operation.

Developer note: A frontend may route calls through its own proxy backend ("BFF").
That changes how the browser authenticates to the BFF (httpOnly session cookie),
not this contract: the BFF calls this API as an ordinary client, presenting an
OIDC bearer token or an API key.
"""

import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyHeader, OpenIdConnect

from nc3_testing_platform.core.errors import PROBLEM_MEDIA_TYPE, ProblemDetail

OIDC_DISCOVERY_URL = os.getenv(
    "OIDC_DISCOVERY_URL",
    "https://idp.example.invalid/.well-known/openid-configuration",
)

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
    """Reject a caller presenting neither credential.

    Belongs on the operation.
    `POST /scans` accepts anonymous callers, and a guest reads their own scan
    with a token instead of a credential.
    """
    if not (oidc_token or key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Present an OpenID Connect token or a platform API key.",
        )


# Attach as `dependencies=[Authenticated]` on an operation.
Authenticated = Depends(require_authentication)


def require_oidc_token(oidc_token: OidcAuth) -> None:
    """Rejects a caller without an OpenID Connect token.

    Belongs on an operation that consumes current MFA assurance.
    Assurance is read from the identity provider's token, so a platform API key cannot satisfy the gate and the operation declares only the OIDC scheme.
    """
    if not oidc_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Present an OpenID Connect token carrying current MFA assurance.",
        )


# Attach as `dependencies=[MfaGated]` on an operation.
MfaGated = Depends(require_oidc_token)


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
