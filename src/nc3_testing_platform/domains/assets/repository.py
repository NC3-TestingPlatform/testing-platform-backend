"""Query layer of the assets domain: every statement it issues, in one place.

Everything here runs **in-policy**, under the organization context the request
asserted through `OrgScopedAppSession` (`core/security.py`). There is no
pre-context lookup in this domain — nothing here resolves identity, so nothing
needs the SECURITY DEFINER escape the auth domain has (IDR-012).

That has a consequence worth stating once: a row belonging to another
organization is not *refused*, it is *invisible*. Every read below returns
``None`` for "no such row in this organization" and for "no such row at all"
alike, and the service must not try to tell those apart — under FORCE RLS it
cannot, which is the point.
"""

import uuid
from datetime import timedelta

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from nc3_testing_platform.core import enums
from nc3_testing_platform.domains.assets.models import (
    Asset,
    DomainVerification,
    DomainVerificationChallenge,
)


def asset_for(db: Session, asset_id: uuid.UUID) -> Asset | None:
    """The asset, or ``None`` when it is absent or belongs to another org.

    A `select`, deliberately not `Session.get`: `get` consults the identity map
    before issuing SQL, so a row loaded earlier in the request would be handed
    back **without** re-evaluating the policy. That matters here because
    `SET LOCAL` dies at a commit and the context has to be re-asserted after
    one; a cached hit would quietly survive a dropped context and return a row
    where the policy would have returned nothing. Every read in this module
    goes to the database for that reason.
    """
    return db.scalars(sa.select(Asset).where(Asset.id == asset_id)).one_or_none()


def challenge_for(
    db: Session, asset_id: uuid.UUID
) -> DomainVerificationChallenge | None:
    """The asset's challenge in progress, if one stands."""
    return db.scalars(
        sa.select(DomainVerificationChallenge).where(
            DomainVerificationChallenge.asset_id == asset_id
        )
    ).one_or_none()


def proof_for(db: Session, asset_id: uuid.UUID) -> DomainVerification | None:
    """The asset's standing ownership proof, if it has one.

    Presence *is* the verified status — there is no status column (§4.2).
    """
    return db.scalars(
        sa.select(DomainVerification).where(DomainVerification.asset_id == asset_id)
    ).one_or_none()


def upsert_challenge(
    db: Session,
    *,
    asset_id: uuid.UUID,
    organization_id: uuid.UUID,
    requested_scope: enums.VerificationScope,
    record_name: str,
    token: str,
    ttl: timedelta,
    requested_by_user_id: uuid.UUID | None,
) -> DomainVerificationChallenge:
    """Issue a challenge for the asset, replacing any challenge it already has.

    One statement, not read-then-write: `asset_id` is unique, so two concurrent
    requests would otherwise race — the loser raising a unique violation on a
    path whose contract is "creating a challenge replaces the existing one"
    (§4.3). ``ON CONFLICT DO UPDATE`` makes replacement the same operation as
    creation, so concurrency yields one surviving challenge rather than a 500.
    Same reasoning as `domains/auth/repository.consume_recovery_code`; a
    different shape because the invariant is different.

    Attempt state is reset, not carried over: a fresh token has never been
    checked, so `last_recheck_at` and `failure_code` must not go on describing
    the challenge this one replaced. They live on the challenge row precisely
    because they belong to *this* attempt.

    Timestamps come from the database clock, never the application's, so expiry
    is comparable with every other stamp on the row.
    """
    expires_at = sa.func.now() + ttl
    fresh = {
        "requested_scope": requested_scope,
        "record_name": record_name,
        "verification_token": token,
        "token_expires_at": expires_at,
        "requested_by_user_id": requested_by_user_id,
        "requested_at": sa.func.now(),
        "last_recheck_at": None,
        "failure_code": None,
    }
    statement = (
        pg_insert(DomainVerificationChallenge)
        .values(
            asset_id=asset_id,
            organization_id=organization_id,
            record_type=enums.DnsRecordType.TXT,
            **fresh,
        )
        .on_conflict_do_update(
            index_elements=[DomainVerificationChallenge.asset_id],
            set_=fresh,
        )
        .returning(DomainVerificationChallenge)
    )
    return db.scalars(statement).one()
