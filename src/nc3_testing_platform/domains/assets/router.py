"""Asset inventory, domain-ownership verification, and syndication feeds.

Every operation here is organization-scoped. Two routers ship from this module:
the authenticated asset router, and a separate unauthenticated one for public feed
delivery, which is authorized by a token in the path rather than by a caller.
"""

from fastapi import APIRouter, HTTPException, Response, status

from nc3_testing_platform.core import rls
from nc3_testing_platform.core.errors import (
    PROBLEM_DOMAIN_CLAIM_LOST,
    PROBLEM_RESOLVER_UNAVAILABLE,
    ProblemException,
    problem_responses,
)
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import (
    NO_STORE_HEADERS,
    CredentialRequired,
    CurrentSession,
    MfaAssuranceRequired,
    OrgAdminRequired,
    OrgScopedAppSession,
    rate_limited,
)
from nc3_testing_platform.domains.assets import examples, service
from nc3_testing_platform.domains.assets.dependencies import (
    ChallengeRateLimited,
    CheckRateLimited,
    GlobalVerificationCapped,
    OrgVerificationCapped,
)
from nc3_testing_platform.domains.assets.schemas import (
    Asset,
    AssetCreate,
    AssetFeed,
    AssetFeedCreate,
    AssetFeedCreated,
    AssetUpdate,
    DomainVerification,
    VerificationChallenge,
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


def _asset_not_found() -> HTTPException:
    # One answer for absent and for another organization's: under FORCE RLS the
    # row is invisible rather than refused, and distinguishing them would be a
    # cross-tenant existence oracle even if the service could.
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="No such asset."
    )


def _verification_not_started() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail="Verification was never started for this asset.",
    )


def _not_a_domain() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="DNS-TXT verification applies to domain assets only.",
    )


def _already_verified() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            "The asset is already verified; replacing its token would discard a "
            "working proof. Start a new challenge to re-prove or widen scope."
        ),
    )


def _challenge_expired() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            "The verification token has expired. Replace it, or start a new "
            "challenge, before checking again."
        ),
    )


def _claim_lost() -> ProblemException:
    """Refuse without naming the other organization, and point at the remedy.

    The body says the domain is claimed and stops there: the conflicting row
    belongs to another tenant, and identifying it would be a cross-tenant
    disclosure. Releasing a stale claim is a platform-operator procedure in v4.0
    (IDR-016, `docs/verification-claim-release.md`), so the refusal names it —
    otherwise a legitimate owner whose domain was claimed first has nowhere to go.
    """
    return ProblemException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            "This domain is already verified by another organization. A verified "
            "claim is released by the platform operator; contact support with the "
            "domain and evidence of control."
        ),
        problem_type=PROBLEM_DOMAIN_CLAIM_LOST,
    )


def _resolver_unavailable() -> ProblemException:
    """The check could not run. Deliberately not a `failure_code` on the challenge.

    Stamping one would tell the user their DNS is wrong when the fault is ours.
    """
    return ProblemException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(
            "The verification check could not run because no DNS resolver was "
            "available. Nothing about your record has been recorded; try again."
        ),
        problem_type=PROBLEM_RESOLVER_UNAVAILABLE,
    )


def _as_response(
    asset_id: ResourceId, state: service.VerificationState
) -> DomainVerification:
    """Map the service state onto the response schema, adding nothing.

    The status is computed in the service against the database clock; the
    challenge is echoed in full because the token is the whole point of the
    response — the caller cannot publish what it cannot read.
    """
    challenge = state.challenge
    return DomainVerification(
        asset_id=asset_id,
        status=state.status,
        verified_scope=state.proof.verified_scope if state.proof else None,
        verified_at=state.proof.verified_at if state.proof else None,
        challenge=(
            None
            if challenge is None
            else VerificationChallenge(
                id=challenge.id,
                requested_scope=challenge.requested_scope,
                record_type=challenge.record_type,
                record_name=challenge.record_name,
                verification_token=challenge.verification_token,
                token_expires_at=challenge.token_expires_at,
                requested_by_user_id=challenge.requested_by_user_id,
                requested_at=challenge.requested_at,
                last_recheck_at=challenge.last_recheck_at,
                failure_code=challenge.failure_code,
            )
        ),
    )


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
    responses={
        200: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 404),
    },
)
def get_verification(
    asset_id: ResourceId, response: Response, db: OrgScopedAppSession
) -> DomainVerification:
    """Current ownership-verification state. `404` when none was ever started.

    Takes the org-scoped session even though it only reads: without the context
    the policy matches nothing and the read would answer `404` for rows that do
    exist, which is indistinguishable from the genuine not-started case.
    """
    try:
        state = service.read_state(db, asset_id)
    except service.AssetNotFoundError:
        raise _asset_not_found() from None
    except service.VerificationNotStartedError:
        raise _verification_not_started() from None
    # The body carries the challenge token, which the caller is about to publish
    # in DNS. Same treatment as the feed token below: no shared proxy or browser
    # disk cache should keep it for a back-button view on a shared machine.
    response.headers["Cache-Control"] = "no-store"
    return _as_response(asset_id, state)


@router.post(
    "/{asset_id}/verification",
    status_code=status.HTTP_201_CREATED,
    summary="Start a verification challenge",
    responses={
        201: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 403, 404, 409, 422),
        **rate_limited(),
    },
    dependencies=[OrgAdminRequired, MfaAssuranceRequired, ChallengeRateLimited],
)
def create_verification(
    asset_id: ResourceId,
    body: VerificationCreate,
    current: CurrentSession,
    response: Response,
    db: OrgScopedAppSession,
) -> DomainVerification:
    """Issue a challenge at the requested coverage.

    Requires current MFA assurance, read from the platform session rather than
    from any stored User flag — proving control of a domain is what later
    authorizes scanning it. Also `organization_admin`: a successful
    verification names the organization and locks the domain platform-wide
    (IDR-016), so it is an admin act, while asset creation and non-intrusive
    scanning stay member-level.

    On an already-verified asset the response carries both the standing proof
    and the new challenge, so coverage in force is never withdrawn while
    ownership is re-proven. Creating a challenge replaces any challenge the
    asset already had, and is idempotent under concurrency.
    """
    try:
        state = service.start_challenge(
            db,
            asset_id=asset_id,
            organization_id=current.organization_id,
            user_id=current.user_id,
            requested_scope=body.requested_scope,
        )
    except service.AssetNotFoundError:
        raise _asset_not_found() from None
    except service.NotADomainAssetError:
        raise _not_a_domain() from None
    # The service committed, which drops SET LOCAL; re-assert before anything
    # else on this session reads (core/security.org_scoped_app_session).
    rls.set_org_context(db, current.organization_id, current.user_id)
    response.headers["Cache-Control"] = "no-store"
    return _as_response(asset_id, state)


@router.post(
    "/{asset_id}/verification/checks",
    summary="Check the DNS record now",
    responses={
        200: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 403, 404, 409, 503),
        **rate_limited(),
    },
    dependencies=[
        OrgAdminRequired,
        MfaAssuranceRequired,
        GlobalVerificationCapped,
        OrgVerificationCapped,
        CheckRateLimited,
    ],
)
def check_verification(
    asset_id: ResourceId,
    current: CurrentSession,
    response: Response,
    db: OrgScopedAppSession,
) -> DomainVerification:
    """Resolve the challenge record and update the state.

    Always sets `last_recheck_at`, so a user who presses this while DNS is still
    propagating can see that it ran. Propagation takes anywhere from minutes to
    two days, which makes "not found yet" the common outcome rather than an
    exceptional one.

    A check that ran and found nothing is a result, not a fault: the response is
    `200` with the state still `pending` and a `failure_code` saying why. `503`
    means the opposite — the check never ran, and nothing was recorded.

    Gated on `organization_admin` and current MFA assurance, because success names
    the organization and locks the domain platform-wide (IDR-016). Synchronous on
    purpose: the DNS lookup blocks, so FastAPI runs this on a worker thread, and
    the bulkhead in `core/dns_utils` is what bounds how many of those a flood can
    occupy.
    """
    try:
        state = service.run_check(
            db,
            asset_id=asset_id,
            organization_id=current.organization_id,
            user_id=current.user_id,
        )
    except service.AssetNotFoundError:
        raise _asset_not_found() from None
    except service.NotADomainAssetError:
        raise _not_a_domain() from None
    except service.VerificationNotStartedError:
        raise _verification_not_started() from None
    except service.ChallengeExpiredError:
        raise _challenge_expired() from None
    except service.DomainClaimLostError:
        # The service committed the stamped refusal; re-assert before the response
        # path touches the session again.
        rls.set_org_context(db, current.organization_id, current.user_id)
        raise _claim_lost() from None
    except service.ResolverUnavailableError:
        raise _resolver_unavailable() from None
    response.headers["Cache-Control"] = "no-store"
    return _as_response(asset_id, state)


@router.post(
    "/{asset_id}/verification/token",
    summary="Replace the verification token",
    responses={
        200: {"headers": NO_STORE_HEADERS},
        **problem_responses(401, 403, 404, 409),
        **rate_limited(),
    },
    dependencies=[OrgAdminRequired, MfaAssuranceRequired, ChallengeRateLimited],
)
def regenerate_verification_token(
    asset_id: ResourceId,
    current: CurrentSession,
    response: Response,
    db: OrgScopedAppSession,
) -> DomainVerification:
    """Issue a fresh token and expiry for a stalled challenge.

    Answers `409` when the asset is already verified. Regeneration exists for a
    challenge that expired or whose token was lost, and a verified asset has
    neither — replacing its token would discard a working proof and make the
    user edit DNS to get back where they started.

    The scope is carried over, not re-taken: changing coverage while replacing a
    token would be a privilege change disguised as a retry. To re-prove
    ownership, or to widen the scope, start a new challenge with
    `POST .../verification`, where the scope is explicit. The existing
    `verified_scope` holds until that challenge succeeds, so nothing depending
    on the current proof breaks meanwhile.
    """
    try:
        state = service.regenerate_token(
            db,
            asset_id=asset_id,
            organization_id=current.organization_id,
            user_id=current.user_id,
        )
    except service.AssetNotFoundError:
        raise _asset_not_found() from None
    except service.AlreadyVerifiedError:
        raise _already_verified() from None
    except service.VerificationNotStartedError:
        raise _verification_not_started() from None
    rls.set_org_context(db, current.organization_id, current.user_id)
    response.headers["Cache-Control"] = "no-store"
    return _as_response(asset_id, state)


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
    return examples.revoked_feed()


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
