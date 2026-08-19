"""Deterministic sample data for the assets domain. Fixed ids, fixed clock."""

from datetime import UTC, datetime
from uuid import UUID

from pydantic import AnyUrl

from nc3_testing_platform.core.config import (
    VERIFICATION_TOKEN_TTL,
    verification_record_name,
)
from nc3_testing_platform.core.enums import (
    AssetOrigin,
    AssetType,
    FeedFormat,
    VerificationScope,
)
from nc3_testing_platform.domains.assets.schemas import (
    Asset,
    AssetFeed,
    AssetFeedCreated,
    VerificationChallenge,
)
from nc3_testing_platform.domains.scans.examples import (
    ASSET_ID,
    ORGANIZATION_ID,
    USER_ID,
)

_T0 = datetime(2026, 6, 1, 8, 30, tzinfo=UTC)
_T1 = datetime(2026, 7, 31, 9, 1, 12, tzinfo=UTC)

_SUBDOMAIN_ASSET_ID = UUID("019ee1a3-0011-7a22-8b33-4c44d5e66f77")
_CHALLENGE_ID = UUID("019ee1a3-1122-7b33-9c44-5d55e6f77a88")
_FEED_ID = UUID("019ee1a3-2233-7c44-ad55-6e66f7a88b99")


def sample_asset() -> Asset:
    """A registered, monitored domain."""
    return Asset(
        id=ASSET_ID,
        organization_id=ORGANIZATION_ID,
        asset_type=AssetType.DOMAIN,
        value="example.lu",
        origin=AssetOrigin.ADDED,
        created_by_user_id=USER_ID,
        regression_alerts_enabled=True,
        created_at=_T0,
        updated_at=_T1,
    )


def sample_discovered_asset() -> Asset:
    """A subdomain that discovery found, linked back to its parent.

    Included because `origin` and `parent_asset_id` only make sense together, and a
    client that never sees a discovered asset will not handle one correctly.
    """
    return Asset(
        id=_SUBDOMAIN_ASSET_ID,
        organization_id=ORGANIZATION_ID,
        asset_type=AssetType.DOMAIN,
        value="mail.example.lu",
        origin=AssetOrigin.DISCOVERED,
        parent_asset_id=ASSET_ID,
        created_by_user_id=None,
        created_at=_T1,
        updated_at=_T1,
    )


def sample_challenge(checked: bool = False) -> VerificationChallenge:
    """A zone-scoped challenge awaiting its DNS record.

    `checked` marks a challenge a lookup has just run against, which is what sets
    `last_recheck_at` and the failure code beside it.
    """
    return VerificationChallenge(
        id=_CHALLENGE_ID,
        requested_scope=VerificationScope.ZONE,
        record_name=verification_record_name("example.lu"),
        verification_token="verify-4f7a2c9e1b8d3056",
        token_expires_at=_T0 + VERIFICATION_TOKEN_TTL,
        requested_by_user_id=USER_ID,
        requested_at=_T0,
        last_recheck_at=_T1 if checked else None,
        failure_code="dns.txt_record_not_found" if checked else None,
    )




def sample_feed() -> AssetFeed:
    """An active Atom feed for the asset."""
    return AssetFeed(
        id=_FEED_ID,
        asset_id=ASSET_ID,
        format=FeedFormat.ATOM,
        created_by_user_id=USER_ID,
        last_used_at=_T1,
        created_at=_T0,
    )


def sample_feed_created() -> AssetFeedCreated:
    """The one response that carries the plaintext token."""
    return AssetFeedCreated(
        **sample_feed().model_dump(),
        token="fd_9xK2mQ7pL4vR8nT1",
        feed_url=AnyUrl("https://api.testing.nc3.lu/api/v1/feeds/fd_9xK2mQ7pL4vR8nT1"),
    )
