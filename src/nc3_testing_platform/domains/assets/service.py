"""Domain-verification lifecycle: issue a challenge, check it, write the proof.

The challenge half is B6a (US #82); `run_check` and the claim adjudication are
B6b (US #263).

`run_check` is the one function here that is not a single transaction, and
deliberately so: it ends its read transaction **before** resolving, so the pooled
connection is not held across a network wait. The engine is built on SQLAlchemy's
defaults (5 plus 10 overflow, so 15 per process), and a check that pinned a
connection for the DNS budget would let a handful of accounts starve every other
operation on the `nc3_app` role — one tenant's action, everyone's outage.

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
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from nc3_testing_platform.core import dns_utils, enums, rls
from nc3_testing_platform.core.config import (
    VERIFICATION_TOKEN_TTL,
    verification_record_name,
)
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.domains.assets import repository, verification
from nc3_testing_platform.domains.assets.models import (
    DomainVerification,
    DomainVerificationChallenge,
)
from nc3_testing_platform.domains.assets.verification import VerificationFailureCode
from nc3_testing_platform.domains.org import service as org_service

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


class ChallengeExpiredError(Exception):
    """The token lapsed before it was proved, so this challenge answers no checks.

    Enforced rather than cosmetic: without it the seven-day lifetime means nothing
    and a TXT record left behind on a domain that has since changed hands would
    still win a terminal, platform-wide claim years later. The remedy is a new
    token, not a retry, which is why it refuses instead of reporting a failed
    check (api-design §5.1, data-model §4.3).
    """


class DomainClaimLostError(Exception):
    """Another organization already holds the verified claim on this domain.

    Detected only as a unique-constraint violation, and that is deliberate. The
    conflicting row belongs to another tenant, so under FORCE RLS it is invisible
    to every read this session can issue; looking it up would need a SECURITY
    DEFINER function and would turn the refusal into a cross-tenant disclosure.
    The caller learns that the domain is claimed, never by whom.
    """


class ResolverUnavailableError(Exception):
    """The check could not run: nothing is configured, or capacity is exhausted.

    Distinct from a check that ran and failed. Nothing is recorded, because
    recording a `failure_code` would tell the user their DNS is wrong when the
    fault is entirely ours.
    """


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


# Codes that mean the platform failed, not the user's DNS. They travel as `503`
# with nothing recorded; every other code is a result the user can act on.
_PLATFORM_FAULTS = frozenset(
    {
        VerificationFailureCode.RESOLVER_UNAVAILABLE,
        VerificationFailureCode.CAPACITY_EXHAUSTED,
    }
)


def _stamp(db: Session, asset_id: uuid.UUID, code: VerificationFailureCode | None) -> None:
    """Record that a check ran, and refuse to continue if the write vanished.

    Under FORCE RLS a lost organization context makes the update match nothing and
    raise nothing, which is indistinguishable from success. The rowcount is the
    only detector, so it is checked rather than trusted.
    """
    if repository.stamp_check(db, asset_id, code=code.value if code else None) != 1:
        raise RuntimeError(
            "verification check stamp matched no row; the organization context "
            "was lost before the write"
        )


def _claim_conflict(exc: IntegrityError) -> bool:
    """Whether this violation is the global claim index and not some other bug.

    Discriminated by constraint name on purpose. The proof row carries two unique
    constraints, a composite foreign key and a check, so a blanket `IntegrityError`
    handler would tell a user "another organization owns your domain" when the
    real fault was a denormalisation or referential bug of ours.
    """
    diagnostic = getattr(getattr(exc, "orig", None), "diag", None)
    return getattr(diagnostic, "constraint_name", None) == "uq_domain_verification_value"


def run_check(
    db: Session,
    *,
    asset_id: uuid.UUID,
    organization_id: uuid.UUID,
    user_id: uuid.UUID | None,
) -> VerificationState:
    """Resolve the challenge record and, if it proves control, write the proof.

    Three outcomes, and the caller maps each to a status code: the proof was
    written; the check ran and did not succeed, so a `failure_code` is stamped and
    the challenge stands; or the domain is already claimed by another organization,
    which is a refusal.

    The org-admin gate on this operation is **insider governance, not resistance to
    an anonymous attacker**: registration provisions the registrant as
    `organization_admin` of their own workspace organization, so an attacker is an
    admin of a throwaway org from the first second. It constrains a non-admin
    member of a real multi-person organization and nothing else. What actually
    stands between an attacker and a claim is the DNS proof itself, the global
    uniqueness constraint, and the rate limits — do not cite this gate as evidence
    that this surface resists abuse.

    :raises AssetNotFoundError: When the asset is not visible.
    :raises NotADomainAssetError: When the asset is not a domain.
    :raises VerificationNotStartedError: When no challenge is in progress.
    :raises ChallengeExpiredError: When the token lapsed.
    :raises DomainClaimLostError: When another organization holds the claim.
    :raises ResolverUnavailableError: When the check could not run at all.
    """
    asset = repository.asset_for(db, asset_id)
    if asset is None:
        raise AssetNotFoundError
    if asset.asset_type is not enums.AssetType.DOMAIN:
        raise NotADomainAssetError
    challenge = repository.challenge_for(db, asset_id)
    if challenge is None:
        raise VerificationNotStartedError
    if challenge.token_expires_at <= _db_now(db):
        raise ChallengeExpiredError
    record_name, token = challenge.record_name, challenge.verification_token
    requested_scope = challenge.requested_scope

    # End the transaction before the network call. This is what returns the pooled
    # connection for the duration of the lookup; it also means the next statement
    # runs on a *different* connection, which is the real reason `SET LOCAL` has to
    # be re-asserted afterwards rather than merely because a transaction ended.
    db.commit()
    try:
        outcomes = dns_utils.resolve_txt(record_name)
    except (dns_utils.DnsNotConfiguredError, dns_utils.DnsCapacityError) as exc:
        raise ResolverUnavailableError from exc

    rls.set_org_context(db, organization_id, user_id)
    # Re-read as **values**, not as an entity. The session keeps loaded rows
    # un-expired across a commit (`expire_on_commit=False`), so re-selecting the
    # entity would hand back the very object read before the lookup and compare a
    # value against itself — the check would silently always pass. Reading columns
    # goes to the database every time.
    fresh = repository.challenge_credentials_for(db, asset_id)
    if fresh is None:
        raise VerificationNotStartedError
    current_token, current_expiry = fresh
    if current_expiry <= _db_now(db):
        # The token lapsed *during* the lookup. Checking expiry only before the
        # network call would let a challenge that died mid-flight still win a
        # terminal claim.
        raise ChallengeExpiredError
    challenge = repository.challenge_for(db, asset_id)
    if challenge is None:
        raise VerificationNotStartedError
    if current_token != token:
        # Not "record not found": this check resolved the *old* token, so it says
        # nothing about the one that now stands, and claiming the record is missing
        # would be a false statement about DNS the user may have published
        # correctly. The recheck stamp still lands, so the attempt is visible.
        _stamp(db, asset_id, VerificationFailureCode.CHALLENGE_SUPERSEDED)
        db.commit()
        rls.set_org_context(db, organization_id, user_id)
        return _state(_db_now(db), repository.proof_for(db, asset_id), challenge)

    verdict = verification.evaluate(
        outcomes,
        token=token,
        requested_scope=requested_scope,
        quorum=settings.verification_resolver_quorum,
    )
    if not verdict.verified:
        if verdict.failure_code in _PLATFORM_FAULTS:
            # The check could not run. Stamping a reason here would tell the user
            # their DNS is wrong when every resolver was unreachable — which is
            # exactly what happens while the egress allowlist is unprovisioned.
            raise ResolverUnavailableError
        _stamp(db, asset_id, verdict.failure_code)
        # B7 audit call site: check ran and did not succeed (asset, code, actor).
        # Never the token, and never the domain: it is personal data that must not
        # reach shared logs.
        logger.info(
            "verification check for asset %s did not succeed: %s",
            asset_id,
            verdict.failure_code.value if verdict.failure_code else "unknown",
        )
        now = _db_now(db)
        db.commit()
        rls.set_org_context(db, organization_id, user_id)
        return _state(now, repository.proof_for(db, asset_id), challenge)

    try:
        # A savepoint, so a lost claim rolls back the proof write without taking
        # the transaction — and therefore the RLS context set before it — with it.
        with db.begin_nested():
            proof = repository.upsert_proof(
                db,
                asset_id=asset_id,
                organization_id=organization_id,
                value=asset.value,
                verified_scope=requested_scope,
                verified_by_user_id=user_id,
                dnssec_validated=verdict.dnssec_validated,
                resolvers=verdict.resolvers,
                corroborating_answers=verdict.corroborating_answers,
            )
            org_service.name_organization_if_unnamed(
                db, organization_id=organization_id, value=asset.value
            )
    except IntegrityError as exc:
        if not _claim_conflict(exc):
            raise
        # The savepoint is gone; the transaction and all three GUCs are intact, so
        # the refusal can be recorded in the same transaction rather than a second
        # one. Stamping here is the point: a refusal the user cannot see the reason
        # for is a support ticket.
        _stamp(db, asset_id, VerificationFailureCode.CLAIM_LOST)
        db.commit()
        raise DomainClaimLostError from None

    _stamp(db, asset_id, None)
    # B7 audit call site: ownership proven (asset, scope, actor, provenance).
    logger.info(
        "verification succeeded for asset %s at scope %s by user %s "
        "(dnssec=%s, corroborated=%d)",
        asset_id,
        requested_scope.value,
        user_id,
        verdict.dnssec_validated,
        verdict.corroborating_answers,
    )
    now = _db_now(db)
    db.commit()
    rls.set_org_context(db, organization_id, user_id)
    return _state(now, proof, repository.challenge_for(db, asset_id))
