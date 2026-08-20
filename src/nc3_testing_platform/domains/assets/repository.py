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
from collections.abc import Sequence
from datetime import datetime, timedelta

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
    """The asset's challenge in progress, if one stands.

    ``populate_existing=True`` for the same reason as `upsert_challenge` and
    `upsert_proof`, and it is not optional here either. The sessions this runs on
    are built with `expire_on_commit=False`, so a commit leaves loaded rows
    un-expired: without it this SELECT still goes to the database and then
    **discards what it returned**, handing back the instance already in the
    identity map. `run_check` reads a challenge, commits, spends up to the DNS
    budget on the network and reads it again — and the second read is what the
    response is built from, so a token regenerated in that window would be
    answered with the retired one, beside the very code that says it was
    superseded. Refreshing costs nothing: the query is issued regardless.
    """
    return db.scalars(
        sa.select(DomainVerificationChallenge)
        .where(DomainVerificationChallenge.asset_id == asset_id)
        .execution_options(populate_existing=True)
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
        # `populate_existing` is load-bearing, not tidiness. RETURNING hydrates
        # through the identity map, so when the row is already loaded — which it
        # is on the regeneration path, where the service reads the challenge
        # first to carry its scope over — SQLAlchemy hands back the *cached*
        # instance and discards the returned values. The database would hold the
        # new token while the response carried the old one, and the caller would
        # publish a value that can never verify. Found by the live suite; no
        # amount of compiled-SQL assertion would have shown it.
        .execution_options(populate_existing=True)
    )
    return db.scalars(statement).one()


def challenge_credentials_for(
    db: Session, asset_id: uuid.UUID
) -> tuple[str, datetime] | None:
    """The challenge's token and expiry as **plain values**, not an ORM instance.

    Deliberately a column select. The sessions this runs on are built with
    `expire_on_commit=False` (`core/api_db`), which is load-bearing elsewhere but
    means a commit does **not** expire a loaded row: a plain `select()` finds the
    identity key present and un-expired, discards what the database returned, and
    hands back the same Python object. Re-reading an entity would therefore be a
    no-op that silently compares a value against itself.

    That is the same identity-map behaviour `upsert_proof`, `upsert_challenge` and
    `challenge_for` defuse with `populate_existing=True`; here the caller wants
    values rather than a managed instance, so a column select is both simpler and
    impossible to get wrong by omission — the comparison that decides whether a
    claim is written does not depend on anyone remembering an execution option.

    :returns: ``(verification_token, token_expires_at)``, or ``None`` when no
        challenge stands.
    """
    row = db.execute(
        sa.select(
            DomainVerificationChallenge.verification_token,
            DomainVerificationChallenge.token_expires_at,
        ).where(DomainVerificationChallenge.asset_id == asset_id)
    ).one_or_none()
    return (row.verification_token, row.token_expires_at) if row else None


def upsert_proof(
    db: Session,
    *,
    asset_id: uuid.UUID,
    organization_id: uuid.UUID,
    value: str,
    verified_scope: enums.VerificationScope,
    verified_by_user_id: uuid.UUID | None,
    dnssec_validated: bool,
    resolvers: Sequence[str],
    corroborating_answers: int,
) -> DomainVerification:
    """Write the asset's ownership proof, replacing any proof it already holds.

    ``ON CONFLICT DO UPDATE``, never ``DO NOTHING``. Widening coverage is the
    primary re-verification path and arrives here as a conflict on `asset_id`:
    with ``DO NOTHING`` that would be a silent no-op answering `200` with the
    **old** scope, and a second concurrent caller would get no row back at all.

    The statement can raise on the *other* unique constraint,
    ``uq_domain_verification_value``, which is global rather than
    per-organization. That is the claim adjudication (IDR-016), and it is the only
    signal available: the conflicting row belongs to another organization, so
    under FORCE RLS it is invisible to every read this session could issue. The
    service discriminates that violation by constraint name and must not try to
    look the row up — doing so would need a definer function and would turn the
    refusal into a cross-tenant disclosure.

    :raises sqlalchemy.exc.IntegrityError: On a lost claim, discriminated by
        constraint name at the call site.
    """
    fresh = {
        "verified_scope": verified_scope,
        "value": value,
        "verified_at": sa.func.now(),
        "verified_by_user_id": verified_by_user_id,
        "dnssec_validated": dnssec_validated,
        "resolvers": list(resolvers),
        "corroborating_answers": corroborating_answers,
    }
    statement = (
        pg_insert(DomainVerification)
        .values(asset_id=asset_id, organization_id=organization_id, **fresh)
        .on_conflict_do_update(
            index_elements=[DomainVerification.asset_id], set_=fresh
        )
        .returning(DomainVerification)
        # Same reasoning as `upsert_challenge`, and the same bug if omitted: the
        # service reads the proof before running the check, so the row is already
        # in the identity map and RETURNING would hand back the cached instance,
        # discarding the scope just written. The database would hold the widened
        # scope while the response reported the old one.
        .execution_options(populate_existing=True)
    )
    return db.scalars(statement).one()


def stamp_check(db: Session, asset_id: uuid.UUID, *, code: str | None) -> int:
    """Record that a check ran, and why it did not succeed.

    Both columns in one statement, always: the schema's `failure_follows_recheck`
    check refuses a `failure_code` without a `last_recheck_at`, so writing them
    apart is a constraint violation waiting for the first failing check. `code`
    of ``None`` clears a previous failure, which is what a success must do — the
    field is echoed in the response, so a stale one would report a verified asset
    alongside yesterday's reason.

    :returns: How many challenges were stamped, which the caller **must** check.
        Under FORCE RLS a lost organization context makes this match nothing and
        raise nothing, so it is the only way to tell a refusal that was recorded
        from one that silently was not. `RETURNING` rather than a rowcount, for
        the same reason `domains/auth/repository` uses it: the returned rows are
        the write's own account of itself.
    """
    stamped = db.scalars(
        sa.update(DomainVerificationChallenge)
        .where(DomainVerificationChallenge.asset_id == asset_id)
        .values(last_recheck_at=sa.func.now(), failure_code=code)
        .returning(DomainVerificationChallenge.asset_id)
    ).all()
    return len(stamped)
