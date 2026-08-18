"""The RLS isolation suite — the standing regression gate for policy changes.

Connects as the *runtime* roles (`nc3_app`, `app_platform`) against a live
PostgreSQL carrying the migrations, because that is the only honest vantage
point: the dev/CI owner is a superuser and bypasses RLS unconditionally, so
nothing run as the owner can prove isolation. Fixtures seed through the owner
engine (`DATABASE_URL`); role URLs derive from it with the dev-default
passwords unless `APP_DATABASE_URL` / `PLATFORM_DATABASE_URL` say otherwise.

Every assertion is id-scoped — a dev database may carry compose-smoke leftovers
and the suite must not care. Marked `postgres` (deselected by default); CI runs
it inside the Migration round trip job after `alembic upgrade head`.
"""

import os
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
import sqlalchemy as sa
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from nc3_testing_platform.core import enums, rls
from nc3_testing_platform.domains.api_keys.models import ApiKey
from nc3_testing_platform.domains.assets.models import Asset
from nc3_testing_platform.domains.findings.models import Finding
from nc3_testing_platform.domains.notifications.models import Notification
from nc3_testing_platform.domains.org.models import AppUser, Organization
from nc3_testing_platform.domains.scans.models import ScanJob, ScanResult, ScanTask

pytestmark = pytest.mark.postgres

_OWNER_URL = os.getenv("DATABASE_URL")


def _rowcount(result: sa.Result[Any]) -> int:
    """The DML row count (`Result` is typed without it; DML returns a cursor)."""
    return cast("sa.CursorResult[Any]", result).rowcount


def _role_url(role: str, env_name: str) -> str:
    """The role's connection URL: explicit env, or derived dev defaults."""
    explicit = os.getenv(env_name)
    if explicit:
        return explicit
    assert _OWNER_URL is not None
    derived = sa.engine.make_url(_OWNER_URL).set(username=role, password=role)
    # str(URL) masks the password as '***'; render it usable.
    return derived.render_as_string(hide_password=False)


@dataclass
class Seed:
    """Ids of the seeded two-org / two-user / one-guest dataset."""

    org_a: uuid.UUID
    org_b: uuid.UUID
    user_x: uuid.UUID  # org A
    user_y: uuid.UUID  # org A — user_x's colleague
    asset_a: uuid.UUID
    asset_b: uuid.UUID
    job_a: uuid.UUID
    task_a: uuid.UUID
    result_a: uuid.UUID
    finding_a: uuid.UUID
    job_b: uuid.UUID
    guest_job: uuid.UUID
    guest_task: uuid.UUID
    guest_result: uuid.UUID
    key_x: uuid.UUID
    key_y: uuid.UUID
    notif_x: uuid.UUID
    notif_y: uuid.UUID


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
    """The nc3_app engine, pinned to one pooled connection.

    ``pool_size=1, max_overflow=0`` makes every session in the suite reuse the
    same DBAPI connection — which is what turns the leak test into a real
    proof that ``SET LOCAL`` context cannot survive into the next checkout.
    """
    engine = sa.create_engine(
        _role_url("nc3_app", "APP_DATABASE_URL"), pool_size=1, max_overflow=0
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def platform_engine() -> Iterator[sa.Engine]:
    """The app_platform engine (duty allowlist, no GUC arms)."""
    engine = sa.create_engine(
        _role_url("app_platform", "PLATFORM_DATABASE_URL"), pool_size=1, max_overflow=0
    )
    yield engine
    engine.dispose()


@pytest.fixture(scope="module")
def seed(owner_engine: sa.Engine) -> Iterator[Seed]:
    """Two orgs with parallel data, two same-org users, one guest job."""
    make = sessionmaker(bind=owner_engine)
    tag = uuid.uuid4().hex[:8]  # unique-column suffix, dirty-DB safe
    now = datetime.now(UTC)

    def _user(org: uuid.UUID, name: str) -> AppUser:
        return AppUser(
            organization_id=org,
            identity_subject=f"iso-{tag}-{name}",
            email=f"{name}-{tag}@example.invalid",
            display_name=name,
            organization_role=enums.OrganizationRole.MEMBER,
        )

    def _job(org: uuid.UUID, user: uuid.UUID, asset: uuid.UUID) -> ScanJob:
        return ScanJob(
            organization_id=org,
            triggered_by_user_id=user,
            source=enums.ScanSource.MANUAL,
            asset_id=asset,
            modules=[enums.ScanModule.WEB],
            status=enums.ScanJobStatus.QUEUED,
        )

    def _task(job: ScanJob) -> ScanTask:
        return ScanTask(
            organization_id=job.organization_id,
            scan_job_id=job.id,
            module=enums.ScanModule.WEB,
            test_key="web.noop",
            test_version="0",
            classification=enums.ScanClassification.NON_INTRUSIVE,
            target_domain="example.invalid",
            status=enums.ScanTaskStatus.QUEUED,
        )

    def _result(task: ScanTask) -> ScanResult:
        return ScanResult(
            organization_id=task.organization_id,
            scan_task_id=task.id,
            schema_version="1",
            raw_output={},
            completed_at=now,
        )

    with make() as unit:
        org_a = Organization(name=f"iso-org-a-{tag}")
        org_b = Organization(name=f"iso-org-b-{tag}")
        unit.add_all([org_a, org_b])
        unit.flush()
        user_x, user_y = _user(org_a.id, "x"), _user(org_a.id, "y")
        user_b = _user(org_b.id, "b")
        unit.add_all([user_x, user_y, user_b])
        unit.flush()
        asset_a = Asset(
            organization_id=org_a.id,
            asset_type=enums.AssetType.DOMAIN,
            value=f"a-{tag}.example.invalid",
            origin=enums.AssetOrigin.ADDED,
        )
        asset_b = Asset(
            organization_id=org_b.id,
            asset_type=enums.AssetType.DOMAIN,
            value=f"b-{tag}.example.invalid",
            origin=enums.AssetOrigin.ADDED,
        )
        unit.add_all([asset_a, asset_b])
        unit.flush()
        job_a = _job(org_a.id, user_x.id, asset_a.id)
        job_b = _job(org_b.id, user_b.id, asset_b.id)
        guest_job = ScanJob(
            source=enums.ScanSource.GUEST,
            target_domain=f"guest-{tag}.example.invalid",
            modules=[enums.ScanModule.WEB],
            status=enums.ScanJobStatus.QUEUED,
            claim_token_hash=f"{tag:0>64}",
            purge_at=now + timedelta(hours=24),
        )
        unit.add_all([job_a, job_b, guest_job])
        unit.flush()
        task_a, guest_task = _task(job_a), _task(guest_job)
        unit.add_all([task_a, guest_task])
        unit.flush()
        result_a, guest_result = _result(task_a), _result(guest_task)
        unit.add_all([result_a, guest_result])
        unit.flush()
        finding_a = Finding(
            organization_id=org_a.id,
            scan_result_id=result_a.id,
            check_id="iso.check",
            severity=enums.FindingSeverity.INFO,
            status=enums.FindingStatus.NEW,
            title="isolation seed",
            description="seeded by tests/test_org_isolation.py",
        )
        key_x = ApiKey(
            organization_id=org_a.id,
            owner_user_id=user_x.id,
            created_by_user_id=user_x.id,
            name="iso-key-x",
            scope=enums.ApiKeyScope.READ_ONLY,
            key_prefix=f"iso{tag}x",
            secret_hash="not-a-real-hash",
        )
        key_y = ApiKey(
            organization_id=org_a.id,
            owner_user_id=user_y.id,
            created_by_user_id=user_y.id,
            name="iso-key-y",
            scope=enums.ApiKeyScope.READ_ONLY,
            key_prefix=f"iso{tag}y",
            secret_hash="not-a-real-hash",
        )
        notif_x = Notification(user_id=user_x.id, type="iso.test", schema_version="1")
        notif_y = Notification(user_id=user_y.id, type="iso.test", schema_version="1")
        unit.add_all([finding_a, key_x, key_y, notif_x, notif_y])
        unit.commit()
        ids = Seed(
            org_a=org_a.id,
            org_b=org_b.id,
            user_x=user_x.id,
            user_y=user_y.id,
            asset_a=asset_a.id,
            asset_b=asset_b.id,
            job_a=job_a.id,
            task_a=task_a.id,
            result_a=result_a.id,
            finding_a=finding_a.id,
            job_b=job_b.id,
            guest_job=guest_job.id,
            guest_task=guest_task.id,
            guest_result=guest_result.id,
            key_x=key_x.id,
            key_y=key_y.id,
            notif_x=notif_x.id,
            notif_y=notif_y.id,
        )
    yield ids
    with make() as unit:
        for model, column, values in (
            (Finding, Finding.scan_result_id, (ids.result_a, ids.guest_result)),
            (ScanResult, ScanResult.id, (ids.result_a, ids.guest_result)),
            (ScanTask, ScanTask.scan_job_id, (ids.job_a, ids.job_b, ids.guest_job)),
            (ScanJob, ScanJob.id, (ids.job_a, ids.job_b, ids.guest_job)),
            (ApiKey, ApiKey.id, (ids.key_x, ids.key_y)),
            (Notification, Notification.id, (ids.notif_x, ids.notif_y)),
            (Asset, Asset.id, (ids.asset_a, ids.asset_b)),
            (AppUser, AppUser.organization_id, (ids.org_a, ids.org_b)),
            (Organization, Organization.id, (ids.org_a, ids.org_b)),
        ):
            unit.execute(sa.delete(model).where(column.in_(values)))
        unit.commit()


@pytest.fixture
def app_session(app_engine: sa.Engine) -> Iterator[Session]:
    """A fresh nc3_app unit of work, rolled back after the test."""
    with Session(app_engine) as unit:
        yield unit
        unit.rollback()


@pytest.fixture
def platform_session(platform_engine: sa.Engine) -> Iterator[Session]:
    """A fresh app_platform unit of work, rolled back after the test."""
    with Session(platform_engine) as unit:
        yield unit
        unit.rollback()


# --- org ↔ org -------------------------------------------------------------


def test_cross_org_reads_are_empty(app_session: Session, seed: Seed) -> None:
    """Org A sees its own rows and nothing of org B's — silently."""
    rls.set_org_context(app_session, seed.org_a)
    assert app_session.get(Asset, seed.asset_a) is not None
    assert app_session.get(ScanJob, seed.job_a) is not None
    assert app_session.get(Asset, seed.asset_b) is None
    assert app_session.get(ScanJob, seed.job_b) is None
    assert app_session.get(Organization, seed.org_b) is None


def test_cross_org_update_and_delete_touch_zero_rows(
    app_session: Session, seed: Seed
) -> None:
    """Writes across the boundary affect nothing rather than erroring."""
    rls.set_org_context(app_session, seed.org_a)
    updated = app_session.execute(
        sa.update(Asset).where(Asset.id == seed.asset_b).values(value="stolen")
    )
    deleted = app_session.execute(sa.delete(Asset).where(Asset.id == seed.asset_b))
    assert _rowcount(updated) == 0
    assert _rowcount(deleted) == 0


def test_cross_org_insert_is_rejected_by_with_check(
    app_session: Session, seed: Seed
) -> None:
    """Creating a row for another org violates WITH CHECK loudly."""
    rls.set_org_context(app_session, seed.org_a)
    app_session.add(
        Asset(
            organization_id=seed.org_b,
            asset_type=enums.AssetType.DOMAIN,
            value="planted.example.invalid",
            origin=enums.AssetOrigin.ADDED,
        )
    )
    with pytest.raises(ProgrammingError, match="row-level security"):
        app_session.flush()


def test_missing_context_denies_with_empty_results(
    app_session: Session, seed: Seed
) -> None:
    """No GUCs set: every tenant row is unreachable, without an error."""
    assert app_session.get(Asset, seed.asset_a) is None
    assert app_session.get(ScanJob, seed.job_a) is None
    assert app_session.get(Organization, seed.org_a) is None


# --- user ↔ user -----------------------------------------------------------


def test_user_private_rows_are_invisible_to_colleagues(
    app_session: Session, seed: Seed
) -> None:
    """Same-org colleague X cannot read Y's notifications or API keys."""
    rls.set_user_context(app_session, seed.user_x)
    assert app_session.get(Notification, seed.notif_x) is not None
    assert app_session.get(ApiKey, seed.key_x) is not None
    assert app_session.get(Notification, seed.notif_y) is None
    assert app_session.get(ApiKey, seed.key_y) is None


def test_org_context_never_opens_a_colleagues_api_key(
    app_session: Session, seed: Seed
) -> None:
    """api_key has no org arm (IDR-012): org membership grants nothing."""
    rls.set_org_context(app_session, seed.org_a, user_id=seed.user_x)
    assert app_session.get(ApiKey, seed.key_x) is not None
    assert app_session.get(ApiKey, seed.key_y) is None
    # Member rows, by contrast, are org-visible (member management).
    assert app_session.get(AppUser, seed.user_y) is not None


# --- the guest arm ---------------------------------------------------------


def test_guest_rows_are_invisible_to_every_tenant_context(
    app_session: Session, seed: Seed
) -> None:
    """No context and org context both miss the guest job entirely."""
    assert app_session.get(ScanJob, seed.guest_job) is None
    rls.set_org_context(app_session, seed.org_a)
    assert app_session.get(ScanJob, seed.guest_job) is None
    assert app_session.get(ScanTask, seed.guest_task) is None
    assert app_session.get(ScanResult, seed.guest_result) is None


def test_guest_arm_reaches_exactly_its_own_job(
    app_session: Session, seed: Seed
) -> None:
    """The job arm opens the guest chain — and nothing of any org's."""
    rls.set_guest_job_context(app_session, seed.guest_job)
    assert app_session.get(ScanJob, seed.guest_job) is not None
    assert app_session.get(ScanTask, seed.guest_task) is not None
    assert app_session.get(ScanResult, seed.guest_result) is not None
    assert app_session.get(ScanJob, seed.job_a) is None
    assert app_session.get(Asset, seed.asset_a) is None


def test_claim_transition_works_through_the_guest_arm(
    app_session: Session, seed: Seed
) -> None:
    """Claiming sets ownership under the guest arm — no NULL→org policy.

    WITH CHECK still passes after the UPDATE because the arm keys on the
    immutable ``scan_job.id`` (IDR-012's claim-transition design). Rolled
    back by the fixture, so the seed stays a guest job.
    """
    rls.set_guest_job_context(app_session, seed.guest_job)
    claimed = app_session.execute(
        sa.update(ScanJob)
        .where(ScanJob.id == seed.guest_job)
        .values(
            organization_id=seed.org_a,
            claimed_by_user_id=seed.user_x,
            claimed_at=datetime.now(UTC),
            claim_token_hash=None,
            # §7.1: a claimed, non-terminal job carries no purge deadline —
            # it is recomputed at terminal completion.
            purge_at=None,
        )
    )
    assert _rowcount(claimed) == 1


# --- the worker path (hint-then-verify) -------------------------------------


def test_a_forged_worker_hint_loads_zero_rows(
    app_session: Session, seed: Seed
) -> None:
    """run_module's claim under a wrong org context finds no task row."""
    rls.set_org_context(app_session, seed.org_b)
    claimed = app_session.execute(
        sa.select(ScanTask).where(ScanTask.id == seed.task_a).with_for_update()
    ).scalar_one_or_none()
    assert claimed is None


def test_a_forged_hint_cannot_write_a_result(
    app_session: Session, seed: Seed
) -> None:
    """A result spoofing another org's attribution violates WITH CHECK.

    (A row *labeled* for the forger's own org referencing a foreign task id
    is stopped upstream: the worker's claim under policy loads zero rows, so
    persist is never reached — and §13.1's same-org FK rule stays with task
    creation, which runs under app_platform from committed job rows.)
    """
    rls.set_org_context(app_session, seed.org_b)
    app_session.add(
        ScanResult(
            organization_id=seed.org_a,  # spoofed attribution
            scan_task_id=seed.task_a,
            schema_version="1",
            raw_output={},
            completed_at=datetime.now(UTC),
        )
    )
    with pytest.raises(ProgrammingError, match="row-level security"):
        app_session.flush()


# --- pooled-connection hygiene ----------------------------------------------


def test_context_dies_with_its_transaction(
    app_engine: sa.Engine, seed: Seed
) -> None:
    """SET LOCAL context never leaks across commits or pool checkouts.

    The engine is pinned to one DBAPI connection (pool_size=1), so the second
    transaction and the second session both reuse the very connection that
    carried the org A context.
    """
    with Session(app_engine) as unit:
        rls.set_org_context(unit, seed.org_a)
        assert unit.get(Asset, seed.asset_a) is not None
        unit.commit()
        # Same session, next transaction: context is gone, access denied.
        assert unit.get(Asset, seed.asset_a) is None
    with Session(app_engine) as unit:
        # Fresh checkout of the same pooled connection: still nothing.
        assert unit.get(Asset, seed.asset_a) is None


# --- grant matrix and platform duties ----------------------------------------


def test_append_only_tables_refuse_updates_at_the_grant_layer(
    app_engine: sa.Engine,
) -> None:
    """statement_response/audit_event: UPDATE and DELETE are not granted."""
    for statement in (
        "UPDATE statement_response SET context_type = context_type",
        "DELETE FROM audit_event",
    ):
        with (
            Session(app_engine) as unit,
            pytest.raises(ProgrammingError, match="permission denied"),
        ):
            unit.execute(sa.text(statement))


def test_platform_role_reads_and_updates_any_job(
    platform_session: Session, seed: Seed
) -> None:
    """The reaper/heartbeat/dispatch duties reach every org's scan rows."""
    assert platform_session.get(ScanJob, seed.job_a) is not None
    assert platform_session.get(ScanJob, seed.job_b) is not None
    assert platform_session.get(ScanJob, seed.guest_job) is not None
    touched = platform_session.execute(
        sa.update(ScanTask)
        .where(ScanTask.id == seed.task_a)
        .values(status=enums.ScanTaskStatus.QUEUED)
    )
    assert _rowcount(touched) == 1


def test_platform_role_is_confined_to_its_duty_allowlist(
    platform_engine: sa.Engine, seed: Seed
) -> None:
    """Beyond scan_job/scan_task/audit-append, app_platform has nothing."""
    denied = (
        f"SELECT * FROM api_key WHERE id = '{seed.key_x}'",
        f"SELECT * FROM organization WHERE id = '{seed.org_a}'",
        f"DELETE FROM scan_job WHERE id = '{seed.job_b}'",
        "SELECT * FROM audit_event",
    )
    for statement in denied:
        with (
            Session(platform_engine) as unit,
            pytest.raises(ProgrammingError, match="permission denied"),
        ):
            unit.execute(sa.text(statement))


def test_both_runtime_roles_may_append_audit_events(
    app_engine: sa.Engine, platform_engine: sa.Engine
) -> None:
    """audit_append accepts rows carrying org, user, or neither.

    Raw INSERT without RETURNING: audit_event deliberately has no SELECT
    policy, and PostgreSQL applies SELECT policies to RETURNING rows — the
    future audit writer must not use RETURNING either.
    """
    insert = sa.text(
        """
        INSERT INTO audit_event
            (id, chain_id, sequence_number, event_type, detail, occurred_at,
             entry_hash, retention_until)
        VALUES
            (:id, :chain, 1, 'iso.test', '{"kind": "iso-test"}'::jsonb, now(),
             'iso-test-hash', now() + interval '1 day')
        """
    )
    for engine in (app_engine, platform_engine):
        with Session(engine) as unit:
            unit.execute(insert, {"id": str(uuid.uuid4()), "chain": uuid.uuid4().hex})
            unit.rollback()  # append-only table: leave nothing behind
