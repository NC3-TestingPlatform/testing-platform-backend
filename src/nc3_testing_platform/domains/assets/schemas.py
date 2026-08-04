"""Assets, domain-ownership verification, and syndication feeds.

An Asset is organization-owned, not user-owned: `created_by_user_id` is attribution
and nothing more, so a member leaving never orphans an asset or its history.

Verification is a separate nested resource with zero or one current state, not a
field on the Asset. An asset list therefore carries no verification badge; a
client that wants one issues a second call per asset.
"""

from pydantic import BaseModel, Field

from nc3_testing_platform.core.enums import (
    AssetOrigin,
    AssetType,
    DnsRecordType,
    FeedFormat,
    VerificationScope,
    VerificationStatus,
)
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp


class Asset(BaseSchema):
    """An organization-owned monitored domain."""

    id: ResourceId
    organization_id: ResourceId
    asset_type: AssetType
    value: str = Field(
        description="Canonical IDNA domain without a trailing dot.",
        examples=["example.lu"],
    )
    origin: AssetOrigin = Field(
        description="Whether a user registered this domain or discovery found it."
    )
    parent_asset_id: ResourceId | None = Field(
        default=None,
        description="The asset whose subdomain discovery produced this one.",
    )
    created_by_user_id: ResourceId | None = Field(
        default=None,
        description="Attribution only. Null once the creating user is erased.",
    )
    regression_alerts_enabled: bool = Field(
        default=False,
        description="Notify the organization when a resolved finding reappears.",
    )
    created_at: Timestamp
    updated_at: Timestamp


class AssetCreate(BaseModel):
    """Register a domain to monitor."""

    value: str = Field(
        description="Canonical IDNA domain without a trailing dot.",
        examples=["example.lu"],
    )
    asset_type: AssetType = AssetType.DOMAIN


class AssetUpdate(BaseModel):
    """Change the one mutable property of an asset.

    `value` and `asset_type` are immutable: a different domain is a different asset,
    with its own scan history and its own ownership proof. Retargeting one in place
    would silently reattribute both.
    """

    regression_alerts_enabled: bool


class DomainVerification(BaseSchema):
    """Current state of one domain-ownership challenge.

    Only the current state lives here. Attempts and transitions are recorded in
    the audit log.
    """

    id: ResourceId
    asset_id: ResourceId
    status: VerificationStatus
    requested_scope: VerificationScope = Field(
        description="Coverage the user asked for."
    )
    verified_scope: VerificationScope | None = Field(
        default=None,
        description=(
            "Coverage actually proven. Non-null only when verified. Re-requesting a "
            "wider scope does not widen this until a check succeeds, so an existing "
            "proof is never silently upgraded."
        ),
    )
    record_type: DnsRecordType = Field(
        default=DnsRecordType.TXT,
        description="Type of DNS record to create.",
    )
    record_name: str = Field(
        description=(
            "Name of the DNS record to create. Computed by the server from the "
            "asset's domain and a deployment-configured vendor prefix. Display the "
            "returned value; do not rebuild it."
        ),
        examples=["_nc3-verify.example.lu"],
    )
    verification_token: str = Field(
        description=(
            "Complete value of the record, pasted verbatim. The client does not "
            "wrap, prefix, or encode it."
        ),
        examples=["verify-4f7a2c9e1b8d3056"],
    )
    token_expires_at: Timestamp = Field(
        description=(
            "When the challenge stops being answerable. Seven days from issue by "
            "default. Reaching it moves an unanswered challenge to `expired`; a "
            "verification that already succeeded is unaffected."
        )
    )
    requested_by_user_id: ResourceId | None = None
    requested_at: Timestamp
    verified_at: Timestamp | None = None
    last_recheck_at: Timestamp | None = Field(
        default=None,
        description=(
            "When the record was last looked for, whatever triggered the lookup — a "
            "user pressing verify, or the recheck that runs before an intrusive "
            "task is queued. Null until the first check. Pair it with "
            "`failure_code` to show why the last attempt did not succeed."
        ),
    )
    failure_code: str | None = Field(
        default=None,
        description="Stable namespaced reason the last check did not succeed.",
    )
    updated_at: Timestamp


class VerificationCreate(BaseModel):
    """Start a domain-ownership challenge at a chosen coverage."""

    requested_scope: VerificationScope = Field(
        description=(
            "`exact` covers this domain alone. `zone` covers it and everything "
            "beneath it, evaluated by DNS-label ancestry rather than string suffix, "
            "so `evil-example.lu` is never treated as part of `example.lu`."
        )
    )


class AssetFeed(BaseSchema):
    """A per-asset syndication feed with a revocable token."""

    id: ResourceId
    asset_id: ResourceId
    format: FeedFormat
    created_by_user_id: ResourceId | None = None
    revoked_at: Timestamp | None = Field(
        default=None, description="Set on revocation. The row is kept."
    )
    last_used_at: Timestamp | None = None
    created_at: Timestamp


class AssetFeedCreate(BaseModel):
    """Create a feed for an asset."""

    format: FeedFormat


class AssetFeedCreated(AssetFeed):
    """Creation response. The only time the token is ever readable.

    Only the hash is stored, so a lost token cannot be recovered — revoke the feed
    and create another.
    """

    token: str = Field(description="Plaintext feed token. Shown once.")
    feed_url: str = Field(
        description="Fully-qualified URL to subscribe to. Shown once.",
        examples=["https://api.testing.nc3.lu/api/v1/feeds/fd_9xK2mQ7pL4vR8nT1"],
    )
