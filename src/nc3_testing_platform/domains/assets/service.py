"""Domain-verification lifecycle: issue a challenge, replace a stalled token.

The challenge half of B6 (US #82). Running the DNS check and writing the proof
belong to B6b (US #263); this module deliberately never resolves a name, so
nothing here touches the network and every function is one transaction against
the organization context the request already asserted.

Commit doctrine follows `domains/auth/service`: a path that hands the client
state it must act on — a token to publish — commits explicitly before
returning, rather than relying on the dependency's teardown commit. The caller
re-asserts the RLS context afterwards (`core/security.org_scoped_app_session`),
because ``SET LOCAL`` does not survive that commit.
"""

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Session

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.config import (
    VERIFICATION_TOKEN_TTL,
    verification_record_name,
)
from nc3_testing_platform.domains.assets import repository, verification
from nc3_testing_platform.domains.assets.models import (
    DomainVerification,
    DomainVerificationChallenge,
)

logger = logging.getLogger("nc3_testing_platform.domains.assets")


@dataclass(frozen=True)
class VerificationState:
    """The asset's verification state: both rows plus the status they imply.

    Assembled here rather than in the router because the status is derived
    against the *database* clock, which only this layer holds. The router maps
    it to the response schema and adds nothing.
    """

    status: enums.VerificationStatus
    proof: DomainVerification | None
    challenge: DomainVerificationChallenge | None


class AssetNotFoundError(Exception):
    """No such asset in the caller's organization.

    Absent and belonging-to-another-organization are one answer: under FORCE
    RLS the row is invisible rather than refused, so the service cannot tell
    them apart — and telling a caller which one it was would be a cross-tenant
    existence oracle even if it could.
    """


class NotADomainAssetError(Exception):
    """DNS-TXT verification applies to domain assets only.

    The `asset_type = domain` rule is cross-table, so the schema cannot express
    it (data model §14 closing note) and it is enforced here instead.
    """


class VerificationNotStartedError(Exception):
    """The asset has neither a proof nor a challenge — nothing to report."""


class AlreadyVerifiedError(Exception):
    """The asset already holds a proof, so there is no stalled token to replace."""


def _db_now(db: Session) -> datetime:
    """The database clock, so every expiry comparison matches the stored stamps."""
    return db.execute(sa.select(sa.func.now())).scalar_one()


def _state(
    now: datetime,
    proof: DomainVerification | None,
    challenge: DomainVerificationChallenge | None,
) -> VerificationState:
    """Assemble the state against an already-read clock.

    `now` is passed rather than read here so a caller that is about to commit
    can take the clock *before* doing so. Reading it afterwards would issue a
    query between the commit and the router's context re-assertion — harmless
    for `select now()`, which touches no policy-protected table, but it would
    put a statement in the one window where a tenant read silently matches
    nothing, and the next person to add a lookup here would inherit that bug.
    """
    return VerificationState(
        status=verification.compute_status(
            has_proof=proof is not None,
            token_expires_at=challenge.token_expires_at if challenge else None,
            now=now,
        ),
        proof=proof,
        challenge=challenge,
    )


def read_state(db: Session, asset_id: uuid.UUID) -> VerificationState:
    """The asset's proof and challenge, either of which may be absent.

    Both rows together are the state: the API status is computed from them and
    is not stored (§4.2-4.3). A verified asset may carry a challenge as well —
    re-proving or widening runs beside the standing proof, so coverage in force
    is never withdrawn while ownership is proven again.

    :raises AssetNotFoundError: When the asset is not visible.
    :raises VerificationNotStartedError: When verification was never started.
    """
    if repository.asset_for(db, asset_id) is None:
        raise AssetNotFoundError
    proof = repository.proof_for(db, asset_id)
    challenge = repository.challenge_for(db, asset_id)
    if proof is None and challenge is None:
        raise VerificationNotStartedError
    return _state(_db_now(db), proof, challenge)


def start_challenge(
    db: Session,
    *,
    asset_id: uuid.UUID,
    organization_id: uuid.UUID,
    user_id: uuid.UUID | None,
    requested_scope: enums.VerificationScope,
) -> VerificationState:
    """Issue a challenge at the requested coverage, replacing any in progress.

    Permitted on an already-verified asset, and the standing proof is returned
    alongside: that is how coverage is widened, and withdrawing the old proof
    first would strip rights the user still holds while they edit DNS.

    :raises AssetNotFoundError: When the asset is not visible.
    :raises NotADomainAssetError: When the asset is not a domain.
    """
    asset = repository.asset_for(db, asset_id)
    if asset is None:
        raise AssetNotFoundError
    if asset.asset_type is not enums.AssetType.DOMAIN:
        raise NotADomainAssetError
    challenge = repository.upsert_challenge(
        db,
        asset_id=asset_id,
        organization_id=organization_id,
        requested_scope=requested_scope,
        record_name=verification_record_name(asset.value),
        token=verification.generate_token(),
        ttl=VERIFICATION_TOKEN_TTL,
        requested_by_user_id=user_id,
    )
    proof = repository.proof_for(db, asset_id)
    # B7 audit call site: challenge issued (asset, requested scope, actor).
    # Never the token — it is the credential the caller is about to publish.
    logger.info(
        "verification challenge issued for asset %s at scope %s by user %s",
        asset_id,
        requested_scope.value,
        user_id,
    )
    db.commit()
    return _state(_db_now(db), proof, challenge)


def regenerate_token(
    db: Session,
    *,
    asset_id: uuid.UUID,
    organization_id: uuid.UUID,
    user_id: uuid.UUID | None,
) -> VerificationState:
    """Replace a stalled challenge's token and expiry, keeping its scope.

    The scope is carried over rather than re-taken: this operation exists for a
    challenge whose token expired or was lost, and silently changing coverage
    while replacing a token would be a privilege change disguised as a retry.
    Widening is `start_challenge`'s job, where the scope is explicit.

    :raises AssetNotFoundError: When the asset is not visible.
    :raises AlreadyVerifiedError: When a proof stands — replacing the token
        would discard a working proof and make the user edit DNS to get back
        to where they already are.
    :raises VerificationNotStartedError: When there is no challenge to replace.
    """
    asset = repository.asset_for(db, asset_id)
    if asset is None:
        raise AssetNotFoundError
    if repository.proof_for(db, asset_id) is not None:
        raise AlreadyVerifiedError
    existing = repository.challenge_for(db, asset_id)
    if existing is None:
        raise VerificationNotStartedError
    challenge = repository.upsert_challenge(
        db,
        asset_id=asset_id,
        organization_id=organization_id,
        requested_scope=existing.requested_scope,
        record_name=verification_record_name(asset.value),
        token=verification.generate_token(),
        ttl=VERIFICATION_TOKEN_TTL,
        requested_by_user_id=user_id,
    )
    # B7 audit call site: token regenerated (asset, actor). Not the token.
    logger.info(
        "verification token regenerated for asset %s by user %s", asset_id, user_id
    )
    now = _db_now(db)
    db.commit()
    return _state(now, None, challenge)
