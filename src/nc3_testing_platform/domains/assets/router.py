"""Asset inventory, domain-ownership verification, and syndication feeds.

Every operation here is organization-scoped. Two routers ship from this module:
the authenticated asset router, and a separate unauthenticated one for public feed
delivery, which is authorized by a token in the path rather than by a caller.
"""

from fastapi import APIRouter, Response, status

from nc3_testing_platform.core.enums import VerificationStatus
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import (
    NO_STORE_HEADERS,
    CredentialRequired,
    MfaAssuranceDeclared,
)
from nc3_testing_platform.domains.assets import examples
from nc3_testing_platform.domains.assets.schemas import (
    Asset,
    AssetCreate,
    AssetFeed,
    AssetFeedCreate,
    AssetFeedCreated,
    AssetUpdate,
    DomainVerification,
    VerificationCreate,
)
from nc3_testing_platform.domains.scans import examples as scan_examples
from nc3_testing_platform.domains.scans.schemas import ScanJob

router = APIRouter(
    prefix="/assets",
    tags=["assets"],
)

# Public feed delivery. Deliberately outside the authenticated router: the token in
# the path is the entire authorization, which is what makes a feed subscribable by
# a reader that cannot hold credentials.
public_feed_router = APIRouter(prefix="/feeds", tags=["assets"])


@router.get(
    "",
    summary="List assets",
    responses=problem_responses(401),
    dependencies=[CredentialRequired],
)
async def list_assets(page: CursorPage) -> Page[Asset]:
    """Assets owned by the caller's organization."""
    return Page(
        items=[examples.sample_asset(), examples.sample_discovered_asset()],
        next_cursor=None,
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Register a domain",
    responses=problem_responses(401, 409, 422),
    dependencies=[CredentialRequired],
)
async def create_asset(body: AssetCreate) -> Asset:
    """Register a domain to monitor.

    Conflicts with an existing asset for the same organization and value.
    """
    return examples.sample_asset()


@router.get(
    "/{asset_id}",
    summary="Get an asset",
    responses=problem_responses(401, 404),
    dependencies=[CredentialRequired],
)
async def get_asset(asset_id: ResourceId) -> Asset:
    """One asset. Verification state is a separate nested resource."""
    return examples.sample_asset()


@router.patch(
    "/{asset_id}",
    summary="Update an asset",
    responses=problem_responses(401, 404, 422),
    dependencies=[CredentialRequired],
)
async def update_asset(asset_id: ResourceId, body: AssetUpdate) -> Asset:
    """Change regression alerting. Nothing else about an asset is mutable."""
    return examples.sample_asset()


@router.delete(
    "/{asset_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an asset",
    responses=problem_responses(401, 403, 404, 409),
    dependencies=[CredentialRequired],
)
async def delete_asset(asset_id: ResourceId) -> Response:
    """Remove an asset from the inventory.

    Answers `409` while scan history, discovered children, a verification, a schedule, or a feed reference the asset.
    """
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/{asset_id}/scans",
    summary="List scans for an asset",
    responses=problem_responses(401, 404),
    dependencies=[CredentialRequired],
)
async def list_asset_scans(asset_id: ResourceId, page: CursorPage) -> Page[ScanJob]:
    """This asset's scan history, newest first."""
    return Page(items=[scan_examples.sample_job()], next_cursor=None)


@router.get(
    "/{asset_id}/verification",
    summary="Get verification state",
    responses=problem_responses(401, 404),
    dependencies=[CredentialRequired],
)
async def get_verification(asset_id: ResourceId) -> DomainVerification:
    """Current ownership-verification state. `404` when none was ever started."""
    return examples.sample_verification()


@router.post(
    "/{asset_id}/verification",
    status_code=status.HTTP_201_CREATED,
    summary="Start a verification challenge",
    responses=problem_responses(401, 403, 404, 409, 422),
    dependencies=[MfaAssuranceDeclared],
)
async def create_verification(
    asset_id: ResourceId, body: VerificationCreate
) -> DomainVerification:
    """Issue a challenge at the requested coverage.

    Requires current MFA assurance, read from the platform session rather than
    from any stored User flag (declaration-only while this handler is a mock;
    B6 swaps in the live gate) — proving control of a domain is what later
    authorizes scanning it.

    On an already-verified asset the response carries both the standing proof and
    the new challenge, so coverage in force is never withdrawn while ownership is
    re-proven.
    """
    return examples.sample_reverification()


@router.post(
    "/{asset_id}/verification/checks",
    summary="Check the DNS record now",
    responses=problem_responses(401, 404, 409),
    dependencies=[CredentialRequired],
)
async def check_verification(asset_id: ResourceId) -> DomainVerification:
    """Resolve the challenge record and update the state.

    Always sets `last_recheck_at`, so a user who presses this while DNS is still
    propagating can see that it ran. Propagation takes anywhere from minutes to
    two days, which makes "not found yet" the common outcome rather than an
    exceptional one.

    A check that ran and found nothing is a result, not a fault: the response is
    `200` with the state still `pending` and a `failure_code` saying why.
    """
    return examples.sample_verification(checked=True)


@router.post(
    "/{asset_id}/verification/token",
    summary="Replace the verification token",
    responses=problem_responses(401, 403, 404, 409),
    dependencies=[CredentialRequired],
)
async def regenerate_verification_token(asset_id: ResourceId) -> DomainVerification:
    """Issue a fresh token and expiry for a stalled challenge.

    Answers `409` when the asset is already verified. Regeneration exists for a
    challenge that expired or whose token was lost, and a verified asset has
    neither — replacing its token would discard a working proof and make the user
    edit DNS again to get back where they started.

    To re-prove ownership, or to widen the scope, start a new challenge with
    `POST .../verification`. The existing `verified_scope` holds until that
    challenge succeeds, so nothing depending on the current proof breaks meanwhile.
    """
    return examples.sample_verification(status=VerificationStatus.PENDING)


@router.get(
    "/{asset_id}/feeds",
    summary="List feeds for an asset",
    responses=problem_responses(401, 404),
    dependencies=[CredentialRequired],
)
async def list_asset_feeds(asset_id: ResourceId) -> list[AssetFeed]:
    """Feeds configured for this asset, including revoked ones."""
    return [examples.sample_feed()]


@router.post(
    "/{asset_id}/feeds",
    status_code=status.HTTP_201_CREATED,
    summary="Create a feed",
    responses={
        201: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 404, 422),
    },
    dependencies=[CredentialRequired],
)
async def create_asset_feed(
    asset_id: ResourceId, body: AssetFeedCreate, response: Response
) -> AssetFeedCreated:
    """Create a syndication feed.

    The response is the only time the token and URL are readable; only the hash is
    stored. A lost token is replaced by revoking and creating another.
    """
    response.headers["Cache-Control"] = "no-store"
    return examples.sample_feed_created()


@router.post(
    "/{asset_id}/feeds/{feed_id}/revoke",
    summary="Revoke a feed",
    responses=problem_responses(401, 404, 409),
    dependencies=[CredentialRequired],
)
async def revoke_asset_feed(asset_id: ResourceId, feed_id: ResourceId) -> AssetFeed:
    """Stop serving a feed while keeping its row.

    A `POST` rather than a `DELETE`, because revocation is a recorded event and the
    lifecycle survives it.
    """
    feed = examples.sample_feed()
    feed.revoked_at = feed.created_at
    return feed


@public_feed_router.get(
    "/{token}",
    summary="Fetch a syndication feed",
    response_class=Response,
    responses={
        200: {
            "description": "RSS or Atom document, per the feed's configured format.",
            "headers": NO_STORE_HEADERS,
            "content": {
                "application/rss+xml": {"schema": {"type": "string"}},
                "application/atom+xml": {"schema": {"type": "string"}},
            },
        },
        **problem_responses(404, 410),
    },
)
async def get_feed(token: str) -> Response:
    """Serve a feed to a subscriber.

    Unauthenticated: the token is the authorization. A revoked feed answers `410`,
    which tells an aggregator to stop polling rather than to retry.
    """
    return Response(
        content='<?xml version="1.0" encoding="utf-8"?>\n<feed xmlns="http://www.w3.org/2005/Atom"/>\n',
        media_type="application/atom+xml",
        headers={"Cache-Control": "no-store"},
    )
