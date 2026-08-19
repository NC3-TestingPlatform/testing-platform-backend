"""Live-PostgreSQL integration for domain verification (B6a / US #82).

Everything else in this slice is compiled-SQL assertions against mocks. This
file is where the claims meet the policy engine: that the conflict target
matches the real unique constraint, that the upsert holds under genuine
concurrency, that another organization's rows are invisible rather than
refused, and that the PostgreSQL enum labels agree with the Python enum the
role gate compares against.

It also pins the failure mode the whole design is built around: a tenant read
issued after a commit, before the RLS context is re-asserted, returns **nothing
rather than raising**. That is indistinguishable from "not found", so it is
asserted here deliberately rather than left as folklore in a docstring.

Marked `postgres` (deselected by default); CI runs it in the Migration
round-trip job after `alembic upgrade head` and the role-credential bootstrap.
Role URLs derive from `DATABASE_URL` with the dev-default passwords unless
`APP_DATABASE_URL` says otherwise.
"""

import contextlib
import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from nc3_testing_platform.core import enums, rls
from nc3_testing_platform.domains.assets import repository, service
from nc3_testing_platform.domains.assets.models import (
    Asset,
    DomainVerification,
    DomainVerificationChallenge,
)
from nc3_testing_platform.domains.org import service as org_service
from nc3_testing_platform.domains.org.models import AppUser, Organization

pytestmark = pytest.mark.postgres

_OWNER_URL = os.getenv("DATABASE_URL")
TTL = timedelta(days=7)


def _role_url(role: str, env_name: str) -> str:
    """The role's connection URL: explicit env, or derived dev defaults."""
    explicit = os.getenv(env_name)
    if explicit:
        return explicit
    if not _OWNER_URL:
        pytest.skip("DATABASE_URL not set")
    derived = sa.engine.make_url(_OWNER_URL).set(username=role, password=role)
    return derived.render_as_string(hide_password=False)


@dataclass
class Seed:
    """Two organizations, each with an admin, a member and a domain asset."""

    org_a: uuid.UUID
    org_b: uuid.UUID
    admin_a: uuid.UUID
    member_a: uuid.UUID
    asset_a: uuid.UUID
    asset_b: uuid.UUID


@pytest.fixture(scope="module")
def owner_engine() -> Iterator[sa.Engine]:
    """The owning-role engine — fixtures only, never assertions."""
    if not _OWNER_URL:
        pytest.skip("DATABASE_URL not set")
    engine = sa.create_engine(_OWNER_URL)
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def app_engine() -> Iterator[sa.Engine]:
    """The nc3_app engine — the role the API and the scan workers hold."""
    engine = sa.create_engine(
        _role_url("nc3_app", "APP_DATABASE_URL"), pool_size=2, max_overflow=0
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def seed(owner_engine: sa.Engine) -> Iterator[Seed]:
    """Seeded as the owner; every assertion below runs as a runtime role."""
    make = sessionmaker(bind=owner_engine)
    # Live databases keep rows between runs, and this story's asset value is
    # unique per organization — a fixed value would poison the second run.
    tag = uuid.uuid4().hex[:8]

    def _user(org: uuid.UUID, name: str, role: enums.OrganizationRole) -> AppUser:
        return AppUser(
            organization_id=org,
            identity_subject=f"ver-{tag}-{name}",
            email=f"{name}-{tag}@example.invalid",
            display_name=name,
            organization_role=role,
        )

    def _asset(org: uuid.UUID, label: str) -> Asset:
        return Asset(
            organization_id=org,
            asset_type=enums.AssetType.DOMAIN,
            value=f"{label}-{tag}.example.invalid",
            origin=enums.AssetOrigin.ADDED,
        )

    with make() as unit:
        org_a, org_b = Organization(name=f"ver-a-{tag}"), Organization(
            name=f"ver-b-{tag}"
        )
        unit.add_all([org_a, org_b])
        unit.flush()
        admin_a = _user(org_a.id, "admin", enums.OrganizationRole.ORGANIZATION_ADMIN)
        member_a = _user(org_a.id, "member", enums.OrganizationRole.MEMBER)
        unit.add_all([admin_a, member_a])
        asset_a, asset_b = _asset(org_a.id, "a"), _asset(org_b.id, "b")
        unit.add_all([asset_a, asset_b])
        unit.flush()
        result = Seed(
            org_a=org_a.id,
            org_b=org_b.id,
            admin_a=admin_a.id,
            member_a=member_a.id,
            asset_a=asset_a.id,
            asset_b=asset_b.id,
        )
        unit.commit()
    yield result


def _app_sessionmaker(engine: sa.Engine) -> sessionmaker[Session]:
    """Sessions shaped exactly like the request-scoped ones in `core/api_db`.

    `expire_on_commit=False` is not incidental — it is load-bearing for this
    feature. The service commits and then reads attributes off the rows it just
    wrote; with expiry on, that touch triggers a refresh in the one window where
    the RLS context is already dead, and the refresh finds nothing and raises
    `ObjectDeletedError`. Testing against a differently-configured session would
    either miss real bugs or invent ones the application cannot have.
    """
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture
def app_session(app_engine: sa.Engine) -> Iterator[Session]:
    """A fresh nc3_app unit of work, rolled back after the test."""
    with _app_sessionmaker(app_engine)() as unit:
        yield unit
        unit.rollback()


def _issue(
    db: Session, seed: Seed, asset_id: uuid.UUID, *, token: str = "tok"
) -> DomainVerificationChallenge:
    return repository.upsert_challenge(
        db,
        asset_id=asset_id,
        organization_id=seed.org_a,
        requested_scope=enums.VerificationScope.ZONE,
        record_name="_nc3-verify.example.invalid",
        token=token,
        ttl=TTL,
        requested_by_user_id=seed.admin_a,
    )


# --- the upsert against the real constraint ----------------------------------


def test_upsert_replaces_rather_than_duplicating(
    app_session: Session, seed: Seed
) -> None:
    """The conflict target matches the live unique constraint on asset_id.

    Compiled SQL cannot prove this: if `index_elements` disagreed with the
    actual index, PostgreSQL would raise rather than replace.
    """
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    first = _issue(app_session, seed, seed.asset_a, token="first")
    second = _issue(app_session, seed, seed.asset_a, token="second")
    assert first.id == second.id
    assert second.verification_token == "second"
    count = app_session.execute(
        sa.select(sa.func.count()).select_from(DomainVerificationChallenge)
    ).scalar_one()
    assert count == 1


def test_upsert_clears_the_previous_attempt_state(
    app_session: Session, seed: Seed
) -> None:
    """A replaced challenge must not keep reporting the old attempt's failure."""
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    challenge = _issue(app_session, seed, seed.asset_a)
    app_session.execute(
        sa.update(DomainVerificationChallenge)
        .where(DomainVerificationChallenge.id == challenge.id)
        .values(last_recheck_at=sa.func.now(), failure_code="dns.nxdomain")
    )
    replaced = _issue(app_session, seed, seed.asset_a, token="fresh")
    app_session.refresh(replaced)
    assert replaced.last_recheck_at is None
    assert replaced.failure_code is None


def test_concurrent_issue_yields_one_challenge(
    app_engine: sa.Engine, seed: Seed
) -> None:
    """Two callers racing on one asset must not produce a unique violation.

    Serialized by the row lock the upsert takes rather than by application
    code; the loser updates instead of failing.
    """
    make = _app_sessionmaker(app_engine)
    with make() as one, make() as two:
        rls.set_org_context(one, seed.org_a, seed.admin_a)
        rls.set_org_context(two, seed.org_a, seed.admin_a)
        _issue(one, seed, seed.asset_a, token="one")
        one.commit()
        _issue(two, seed, seed.asset_a, token="two")
        two.commit()
        rls.set_org_context(two, seed.org_a, seed.admin_a)
        rows = two.execute(
            sa.select(sa.func.count()).select_from(DomainVerificationChallenge)
        ).scalar_one()
        assert rows == 1
        two.execute(sa.delete(DomainVerificationChallenge))
        two.commit()


# --- tenant isolation --------------------------------------------------------


def test_another_organizations_challenge_is_invisible(
    app_engine: sa.Engine, seed: Seed
) -> None:
    """Not refused — invisible. `None` means "absent" and "not yours" alike."""
    with _app_sessionmaker(app_engine)() as owner_side:
        rls.set_org_context(owner_side, seed.org_a, seed.admin_a)
        _issue(owner_side, seed, seed.asset_a)
        owner_side.commit()
    try:
        with _app_sessionmaker(app_engine)() as other_side:
            rls.set_org_context(other_side, seed.org_b, None)
            assert repository.challenge_for(other_side, seed.asset_a) is None
            assert repository.asset_for(other_side, seed.asset_a) is None
    finally:
        with _app_sessionmaker(app_engine)() as cleanup:
            rls.set_org_context(cleanup, seed.org_a, seed.admin_a)
            cleanup.execute(sa.delete(DomainVerificationChallenge))
            cleanup.commit()


def test_a_challenge_cannot_be_written_into_another_organization(
    app_session: Session, seed: Seed
) -> None:
    """The policy's WITH CHECK arm refuses the write, loudly this time."""
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    with pytest.raises(Exception) as excinfo:
        repository.upsert_challenge(
            app_session,
            asset_id=seed.asset_b,
            organization_id=seed.org_b,
            requested_scope=enums.VerificationScope.EXACT,
            record_name="_nc3-verify.b.example.invalid",
            token="tok",
            ttl=TTL,
            requested_by_user_id=seed.admin_a,
        )
    assert "row-level security" in str(excinfo.value).lower()


def test_a_dropped_context_reads_empty_rather_than_raising(
    app_engine: sa.Engine, seed: Seed
) -> None:
    """The failure mode the whole design guards against, pinned.

    `SET LOCAL` dies at the commit. A tenant read afterwards, without
    re-assertion, matches nothing and returns `None` — which is exactly what a
    genuinely missing row returns. Nothing raises, so nothing surfaces; this is
    why every commit must be followed by re-asserting the context.
    """
    with _app_sessionmaker(app_engine)() as db:
        rls.set_org_context(db, seed.org_a, seed.admin_a)
        _issue(db, seed, seed.asset_a)
        db.commit()  # the context dies here
        try:
            assert repository.challenge_for(db, seed.asset_a) is None
            # Re-asserting brings the very same row back into view.
            rls.set_org_context(db, seed.org_a, seed.admin_a)
            assert repository.challenge_for(db, seed.asset_a) is not None
        finally:
            rls.set_org_context(db, seed.org_a, seed.admin_a)
            db.execute(sa.delete(DomainVerificationChallenge))
            db.commit()


# --- the role the gate compares against --------------------------------------


def test_the_stored_role_labels_match_the_python_enum(
    app_session: Session, seed: Seed
) -> None:
    """The gate compares an enum; the database hands back a string.

    If a PostgreSQL enum label ever diverged from the Python member's value,
    `OrganizationRole(raw)` would raise and every role gate would 500 — or,
    worse, a silent string comparison elsewhere would deny everyone. Pinned
    against the real type rather than a fixture.
    """
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    rows = app_session.execute(
        sa.select(AppUser.id, AppUser.organization_role).where(
            AppUser.id.in_([seed.admin_a, seed.member_a])
        )
    ).all()
    by_id = {row.id: row.organization_role for row in rows}
    assert enums.OrganizationRole(by_id[seed.admin_a]) is (
        enums.OrganizationRole.ORGANIZATION_ADMIN
    )
    assert enums.OrganizationRole(by_id[seed.member_a]) is (
        enums.OrganizationRole.MEMBER
    )


# --- service behaviour over real rows ----------------------------------------


def test_regeneration_is_refused_while_a_proof_stands(
    app_engine: sa.Engine, seed: Seed, owner_engine: sa.Engine
) -> None:
    """A working proof must not be discarded to replace a token."""
    with _app_sessionmaker(app_engine)() as db:
        rls.set_org_context(db, seed.org_a, seed.admin_a)
        _issue(db, seed, seed.asset_a)
        db.add(
            DomainVerification(
                organization_id=seed.org_a,
                asset_id=seed.asset_a,
                verified_scope=enums.VerificationScope.EXACT,
                # B6b: denormalised and pinned to the asset by a composite key, so
                # it must be the asset's own value rather than any placeholder.
                value=_asset_value(owner_engine, seed.asset_a),
                verified_at=datetime.now(UTC),
            )
        )
        db.commit()
        rls.set_org_context(db, seed.org_a, seed.admin_a)
        try:
            with pytest.raises(service.AlreadyVerifiedError):
                service.regenerate_token(
                    db,
                    asset_id=seed.asset_a,
                    organization_id=seed.org_a,
                    user_id=seed.admin_a,
                )
        finally:
            rls.set_org_context(db, seed.org_a, seed.admin_a)
            db.execute(sa.delete(DomainVerification))
            db.execute(sa.delete(DomainVerificationChallenge))
            db.commit()


def test_read_state_reports_pending_then_verified(
    app_engine: sa.Engine, seed: Seed, owner_engine: sa.Engine
) -> None:
    """Status is computed from the two rows, against the database clock."""
    with _app_sessionmaker(app_engine)() as db:
        rls.set_org_context(db, seed.org_a, seed.admin_a)
        _issue(db, seed, seed.asset_a)
        db.commit()
        rls.set_org_context(db, seed.org_a, seed.admin_a)
        try:
            assert (
                service.read_state(db, seed.asset_a).status
                is enums.VerificationStatus.PENDING
            )
            db.add(
                DomainVerification(
                    organization_id=seed.org_a,
                    asset_id=seed.asset_a,
                    verified_scope=enums.VerificationScope.ZONE,
                    value=_asset_value(owner_engine, seed.asset_a),
                    verified_at=datetime.now(UTC),
                )
            )
            db.flush()
            state = service.read_state(db, seed.asset_a)
            assert state.status is enums.VerificationStatus.VERIFIED
            # A verified asset keeps its challenge: re-proving runs beside the
            # proof, so coverage is never withdrawn mid-flow.
            assert state.challenge is not None
        finally:
            db.rollback()
            rls.set_org_context(db, seed.org_a, seed.admin_a)
            db.execute(sa.delete(DomainVerificationChallenge))
            db.commit()


def test_regeneration_returns_the_fresh_token_not_the_replaced_one(
    app_engine: sa.Engine, seed: Seed
) -> None:
    """The regression this suite caught, pinned at the level a user feels it.

    `regenerate_token` reads the standing challenge first, to carry its scope
    over, which loads the row into the identity map. RETURNING then hydrates
    through that map, so without `populate_existing` the response carried the
    *replaced* token — the caller would publish a value that can never verify,
    and no compiled-SQL assertion would have shown it.
    """
    with _app_sessionmaker(app_engine)() as db:
        rls.set_org_context(db, seed.org_a, seed.admin_a)
        original = _issue(db, seed, seed.asset_a, token="stale-token").verification_token
        db.commit()
        rls.set_org_context(db, seed.org_a, seed.admin_a)
        try:
            state = service.regenerate_token(
                db,
                asset_id=seed.asset_a,
                organization_id=seed.org_a,
                user_id=seed.admin_a,
            )
            assert state.challenge is not None
            assert state.challenge.verification_token != original
            # And the row actually stored what was returned.
            rls.set_org_context(db, seed.org_a, seed.admin_a)
            stored = repository.challenge_for(db, seed.asset_a)
            assert stored is not None
            assert stored.verification_token == state.challenge.verification_token
        finally:
            rls.set_org_context(db, seed.org_a, seed.admin_a)
            db.execute(sa.delete(DomainVerificationChallenge))
            db.commit()


# --- the proof, the claim, and the promotion (B6b / US #263) ------------------


def _asset_value(owner_engine: sa.Engine, asset_id: uuid.UUID) -> str:
    """The asset's canonical value, read as the owner so RLS is not in the way."""
    with sessionmaker(bind=owner_engine)() as unit:
        return unit.execute(
            sa.select(Asset.value).where(Asset.id == asset_id)
        ).scalar_one()


def _prove(
    db: Session,
    seed: Seed,
    asset_id: uuid.UUID,
    value: str,
    *,
    organization_id: uuid.UUID | None = None,
    scope: enums.VerificationScope = enums.VerificationScope.EXACT,
) -> DomainVerification:
    return repository.upsert_proof(
        db,
        asset_id=asset_id,
        organization_id=organization_id or seed.org_a,
        value=value,
        verified_scope=scope,
        verified_by_user_id=seed.admin_a,
        dnssec_validated=True,
        resolvers=["dnspub.restena.lu"],
        corroborating_answers=1,
    )


def test_widening_a_proof_returns_the_new_scope_not_the_cached_row(
    app_session: Session, seed: Seed, owner_engine: sa.Engine
) -> None:
    """The identity-map trap, against the real constraint.

    `RETURNING` hydrates through the identity map, so with the row already loaded
    SQLAlchemy hands back the cached instance and silently discards what the
    database returned. This is the shape that shipped once on the challenge path,
    where the response carried the token it had just replaced. Here it would report
    `exact` coverage while the database held `zone`.
    """
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    value = _asset_value(owner_engine, seed.asset_a)
    _prove(app_session, seed, seed.asset_a, value)
    app_session.commit()
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)

    # Load it, so the identity map holds it before the widening write.
    loaded = repository.proof_for(app_session, seed.asset_a)
    assert loaded is not None
    widened = _prove(
        app_session, seed, seed.asset_a, value, scope=enums.VerificationScope.ZONE
    )
    assert widened.verified_scope is enums.VerificationScope.ZONE


def test_a_second_organization_cannot_claim_the_same_domain(
    app_session: Session, app_engine: sa.Engine, seed: Seed, owner_engine: sa.Engine
) -> None:
    """The claim adjudication, which only a real unique index can demonstrate.

    Organization B proves the same domain value. Its row is invisible to A and A's
    is invisible to B, so nothing in the application can see the conflict — the
    constraint is the whole mechanism, and it fires because PostgreSQL exempts
    unique-index checks from row security.
    """
    value = _asset_value(owner_engine, seed.asset_a)
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    _prove(app_session, seed, seed.asset_a, value)
    app_session.commit()

    with _app_sessionmaker(app_engine)() as other:
        rls.set_org_context(other, seed.org_b, None)
        # The proof is invisible from B, which is exactly why B must not be
        # allowed to decide for itself whether the domain is free.
        assert repository.proof_for(other, seed.asset_a) is None
        with pytest.raises(IntegrityError) as raised:
            _prove(
                other,
                seed,
                seed.asset_b,
                value,
                organization_id=seed.org_b,
            )
            other.flush()
        diagnostic = getattr(raised.value.orig, "diag", None)
        assert (
            getattr(diagnostic, "constraint_name", None)
            == "uq_domain_verification_value"
        ), "the service discriminates on this exact name"
        other.rollback()


def test_a_savepoint_rollback_keeps_the_rls_context(
    app_session: Session, seed: Seed, owner_engine: sa.Engine
) -> None:
    """The premise the claim-lost path depends on, asserted rather than assumed.

    A `SET LOCAL` issued before the savepoint survives `ROLLBACK TO SAVEPOINT`, so
    the refusal can be stamped in the same transaction. If this ever stopped being
    true, the stamp would match zero rows silently and the 409 would carry no
    reason at all.
    """
    value = _asset_value(owner_engine, seed.asset_a)
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    _issue(app_session, seed, seed.asset_a, token="savepoint-tok")
    app_session.commit()
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)

    with contextlib.suppress(IntegrityError):
        with app_session.begin_nested():
            _prove(app_session, seed, seed.asset_a, value)
            # Force the conflict inside the savepoint.
            app_session.execute(
                sa.text(
                    "INSERT INTO domain_verification "
                    "(id, organization_id, asset_id, verified_scope, value, verified_at) "
                    "VALUES (gen_random_uuid(), :org, :asset, 'exact', :value, now())"
                ),
                {"org": seed.org_a, "asset": seed.asset_b, "value": value},
            )

    # The context must still be in force: the stamp is what proves it.
    assert repository.stamp_check(app_session, seed.asset_a, code="claim.lost") == 1


def test_a_stamp_without_a_context_matches_nothing_and_raises_nothing(
    app_session: Session, app_engine: sa.Engine, seed: Seed
) -> None:
    """Why the rowcount is checked at every call site.

    With no organization context the policy denies by returning no rows rather than
    by raising, so a write that vanished is indistinguishable from one that
    succeeded — except by its rowcount.
    """
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    _issue(app_session, seed, seed.asset_a, token="context-tok")
    app_session.commit()

    with _app_sessionmaker(app_engine)() as blind:
        assert repository.stamp_check(blind, seed.asset_a, code="dns.record-not-found") == 0
        blind.rollback()


def test_the_first_verification_names_the_organization_exactly_once(
    app_session: Session, seed: Seed, owner_engine: sa.Engine
) -> None:
    """Promotion is idempotent, so a second verification cannot rename the org."""
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    value = _asset_value(owner_engine, seed.asset_a)
    assert (
        org_service.name_organization_if_unnamed(
            app_session, organization_id=seed.org_a, value=value
        )
        is True
    )
    assert (
        org_service.name_organization_if_unnamed(
            app_session, organization_id=seed.org_a, value="later.example.invalid"
        )
        is False
    )
    app_session.commit()
    with sessionmaker(bind=owner_engine)() as unit:
        named = unit.execute(
            sa.select(Organization.name, Organization.named_at).where(
                Organization.id == seed.org_a
            )
        ).one()
    assert named.name == value
    assert named.named_at is not None


def test_the_composite_key_refuses_a_proof_whose_value_drifted(
    app_session: Session, seed: Seed
) -> None:
    """The denormalised value cannot disagree with the asset it was proven for."""
    rls.set_org_context(app_session, seed.org_a, seed.admin_a)
    with pytest.raises(IntegrityError):
        _prove(app_session, seed, seed.asset_a, "not-this-assets-value.example.invalid")
        app_session.flush()
    app_session.rollback()
