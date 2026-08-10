"""Assets, domain-ownership verification, and syndication feeds.

An Asset is organization-owned, not user-owned: `created_by_user_id` is attribution
and nothing more, so a member leaving never orphans an asset or its history.

Verification is a separate nested resource carrying the coverage proven and the
challenge running, not a field on the Asset. An asset list therefore carries no
verification badge; a client that wants one issues a second call per asset.
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
from nc3_testing_platform.core.schemas import (
    BaseSchema,
    DomainName,
    HttpsUrl,
    ResourceId,
    Timestamp,
)


class Asset(BaseSchema):
    """An organization-owned monitored domain."""

    id: ResourceId
    organization_id: ResourceId
    asset_type: AssetType
    value: DomainName = Field(
        description="Canonical domain: lowercase IDNA (A-label) form without a trailing dot.",
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

    value: DomainName = Field(
        description=(
            "Domain to monitor. Unicode or ASCII input is accepted and "
            "canonicalized to lowercase IDNA (A-label) form without a trailing dot."
        ),
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


class VerificationChallenge(BaseSchema):
    """A DNS record to publish to prove control of the domain.

    Present while a challenge is answerable, and while its last check is being shown.
    Absent once the challenge has produced its proof and absent on a domain with no challenge running.
    """

    id: ResourceId
    requested_scope: VerificationScope = Field(
        description="Coverage this challenge proves if it succeeds."
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
            "default. Reaching it retires the challenge; a proof already recorded is "
            "unaffected."
        )
    )
    requested_by_user_id: ResourceId | None = None
    requested_at: Timestamp
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


class DomainVerification(BaseSchema):
    """Current ownership state of one domain: the proof, plus any challenge running against it.

    The proof and the challenge are independent.
    A domain that is already verified keeps `verified_scope` while a new challenge runs, so re-proving ownership or widening coverage never withdraws coverage that is already proven.

    Only the current state lives here.
    Attempts and transitions are recorded in the audit log.
    """

    asset_id: ResourceId
    status: VerificationStatus = Field(
        description=(
            "`verified` whenever a proof exists, whatever the challenge is doing. "
            "`pending` while an unanswered challenge is still answerable. `expired` "
            "once it is no longer answerable and no proof exists."
        )
    )
    verified_scope: VerificationScope | None = Field(
        default=None,
        description=(
            "Coverage actually proven, null until a challenge first succeeds. "
            "Requesting a wider scope does not widen this until that challenge "
            "succeeds, so an existing proof is never silently upgraded."
        ),
    )
    verified_at: Timestamp | None = Field(
        default=None,
        description="When the proof was recorded. Non-null exactly when `verified_scope` is.",
    )
    challenge: VerificationChallenge | None = Field(
        default=None,
        description=(
            "The challenge currently running, or null when none is. It appears "
            "alongside `verified_scope` while an already-verified domain re-proves "
            "ownership or widens its coverage."
        ),
    )


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
    feed_url: HttpsUrl = Field(
        description="Fully-qualified URL to subscribe to. Shown once.",
        examples=["https://api.testing.nc3.lu/api/v1/feeds/fd_9xK2mQ7pL4vR8nT1"],
    )
