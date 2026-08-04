"""Programmatic access credentials.

A key belongs either to one user or to the organization as a whole. A user key is
revoked when its owner is disabled or erased; an organization key is unaffected by
membership changes, so it suits long-lived automation.

The plaintext secret exists in exactly one response and is never recoverable
afterward — only a lookup prefix and a hash are stored.
"""

from pydantic import BaseModel, Field

from nc3_testing_platform.core.enums import ApiKeyScope
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp


class ApiKey(BaseSchema):
    """A key's metadata and lifecycle."""

    id: ResourceId
    organization_id: ResourceId
    owner_user_id: ResourceId | None = Field(
        default=None,
        description=(
            "The owning user, or null for an organization key. Organization keys "
            "require the `organization_admin` role to create."
        ),
    )
    created_by_user_id: ResourceId | None = None
    name: str
    scope: ApiKeyScope = Field(
        description=(
            "`read_only` permits `GET` operations. `full_scan` is additionally "
            "required to launch a scan."
        )
    )
    key_prefix: str = Field(
        description="Non-secret prefix identifying the key in logs and in this list."
    )
    expires_at: Timestamp | None = None
    revoked_at: Timestamp | None = None
    revocation_reason: str | None = None
    last_used_at: Timestamp | None = None
    created_at: Timestamp


class ApiKeyCreate(BaseModel):
    """Issue a key."""

    name: str = Field(
        min_length=1, description="Human label, so a key can be recognized later."
    )
    scope: ApiKeyScope
    organization_key: bool = Field(
        default=False,
        description=(
            "Issue a key owned by the organization rather than by the caller. "
            "Requires the `organization_admin` role."
        ),
    )
    expires_at: Timestamp | None = Field(
        default=None, description="Optional expiry. Absent means no expiry."
    )


class ApiKeyCreated(ApiKey):
    """Creation response. The only place the secret ever appears."""

    secret: str = Field(
        description="Plaintext key. Shown once; only a hash is stored.",
        examples=["nc3_sk_live_7pL4vR8nT1mQ2xK9jH5gF3dS6aW0zY"],
    )


class ApiKeyRevoke(BaseModel):
    """Revoke a key, optionally recording why."""

    revocation_reason: str | None = Field(
        default=None,
        description="Free-text note kept with the row for later investigation.",
    )
