"""The orchestration decision core: matrix, transitions, outcome derivation.

No database: the models' CHECK constraints are pinned structurally in
tests/test_models.py and behaviorally by the compose smoke; here the pure
functions and ORM-instance transitions are exercised directly, which is where
every branch of the state diagram lives. The roster is built from the real
`noop` and `dnssec` module objects rather than entry-point discovery, so the
tests cannot drift from real descriptors.
"""

from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from sqlalchemy.orm import Session
from uuid6 import uuid7

from nc3_testing_platform.core.enums import (
    FindingSeverity,
    FindingStatus,
    ScanClassification,
    ScanJobStatus,
    ScanModule,
    ScanSource,
    ScanTaskStatus,
)
from nc3_testing_platform.domains.findings.models import Finding
from nc3_testing_platform.domains.scans.models import ScanJob, ScanResult, ScanTask
from nc3_testing_platform.modules.contract import (
    ModuleResult,
    NormalizedFinding,
    ProgressEmitter,
)
from nc3_testing_platform.modules.dnssec import MODULE as DNSSEC_MODULE
from nc3_testing_platform.modules.execution import run_engine
from nc3_testing_platform.modules.noop import MODULE as NOOP_MODULE
from nc3_testing_platform.modules.registry import LoadedModule, Roster
from nc3_testing_platform.worker import orchestration

NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC)

ROSTER = Roster(
    entries=(
        LoadedModule(entry_point="noop", implementation=NOOP_MODULE),
        LoadedModule(entry_point="dnssec", implementation=DNSSEC_MODULE),
    )
)


class RecordingSession:
    """A `Session.add`/`flush` recorder standing in for a unit of work."""

    def __init__(self) -> None:
        self.added: list[object] = []
        self.flushes: list[int] = []

    def add(self, obj: object) -> None:
        """Record one pending row."""
        self.added.append(obj)

    def flush(self) -> None:
        """Record how many rows were pending when the flush happened."""
        self.flushes.append(len(self.added))


def _job(**overrides: object) -> ScanJob:
    """A guest job instance with valid defaults, no database involved."""
    values: dict[str, object] = {
        "id": uuid7(),
        "organization_id": None,
        "source": ScanSource.GUEST,
        "target_domain": "example.lu",
        "modules": [ScanModule.DNSSEC],
        "module_configuration": {},
        "status": ScanJobStatus.QUEUED,
        "claim_token_hash": "seed",
        "purge_at": NOW + timedelta(hours=24),
    }
    values.update(overrides)
    return ScanJob(**values)


def _task(**overrides: object) -> ScanTask:
    """A queued task instance with valid defaults, no database involved."""
    values: dict[str, object] = {
        "id": uuid7(),
        "organization_id": None,
        "scan_job_id": uuid7(),
        "module": ScanModule.DNSSEC,
        "test_key": "dnssec.chainvalidator",
        "test_version": "1.0.0",
        "classification": ScanClassification.NON_INTRUSIVE,
        "target_domain": "example.lu",
        "configuration": {},
        "status": ScanTaskStatus.QUEUED,
    }
    values.update(overrides)
    return ScanTask(**values)


# --- plan_task_matrix -------------------------------------------------------


def test_installed_module_plans_from_its_declaration() -> None:
    """An installed module's spec carries the declared version and queue."""
    specs = orchestration.plan_task_matrix([ScanModule.DNSSEC], ROSTER)
    assert len(specs) == 1
    spec = specs[0]
    assert spec.test_key == "dnssec.chainvalidator"
    assert spec.queue == "non-intrusive-scan"
    assert spec.blocked_reason is None
    declared = DNSSEC_MODULE.descriptor.tests[0]
    assert spec.test_version == declared.test_version


def test_uninstalled_module_plans_blocked_specs() -> None:
    """Catalog tests without an installed module become visible blocked tasks.

    The web module's roster entry (`web.noop`) is deliberately not in the
    catalog, so every real web test is unavailable until B1 provisions it —
    and the reference module never leaks into the matrix.
    """
    specs = orchestration.plan_task_matrix([ScanModule.WEB], ROSTER)
    assert [spec.test_key for spec in specs] == [
        "web.headers",
        "web.tls",
        "web.subdomain_enumeration",
    ]
    for spec in specs:
        assert spec.queue is None
        assert spec.blocked_reason == orchestration.REASON_MODULE_UNAVAILABLE
        assert spec.test_version == orchestration.UNAVAILABLE_TEST_VERSION


def test_matrix_preserves_launch_order() -> None:
    """Specs follow `scan_job.modules` order, catalog order within a module."""
    specs = orchestration.plan_task_matrix(
        [ScanModule.EMAIL, ScanModule.DNSSEC], ROSTER
    )
    assert [spec.test_key for spec in specs] == [
        "email.mailvalidator",
        "dnssec.chainvalidator",
    ]


# --- create_tasks -----------------------------------------------------------


def test_create_tasks_propagates_the_domain_target() -> None:
    """Non-file tasks inherit the job's guest domain (one_task_target)."""
    session = RecordingSession()
    job = _job(module_configuration={"dnssec": {"budget": 5}})
    specs = orchestration.plan_task_matrix([ScanModule.DNSSEC], ROSTER)
    tasks = orchestration.create_tasks(cast(Session, session), job, specs, now=NOW)
    assert session.added == tasks
    task = tasks[0]
    assert task.target_domain == "example.lu"
    assert task.target_asset_id is None and task.file_upload_id is None
    assert task.status is ScanTaskStatus.QUEUED
    assert task.finished_at is None
    assert task.configuration == {"budget": 5}
    assert task.id is not None  # assigned application-side, usable for enqueue


def test_create_tasks_marks_unavailable_modules_blocked_and_finished() -> None:
    """Blocked-at-creation tasks are terminal rows (terminal_state_has_finish)."""
    session = RecordingSession()
    job = _job(modules=[ScanModule.WEB])
    specs = orchestration.plan_task_matrix([ScanModule.WEB], ROSTER)
    tasks = orchestration.create_tasks(cast(Session, session), job, specs, now=NOW)
    for task in tasks:
        assert task.status is ScanTaskStatus.BLOCKED
        assert task.status_reason == orchestration.REASON_MODULE_UNAVAILABLE
        assert task.finished_at == NOW


def test_create_tasks_targets_the_upload_for_file_tests() -> None:
    """File tests target the job's upload, never the domain (§14)."""
    session = RecordingSession()
    upload_id = uuid7()
    job = _job(
        target_domain=None,
        file_upload_id=upload_id,
        modules=[ScanModule.FILE],
    )
    specs = orchestration.plan_task_matrix([ScanModule.FILE], ROSTER)
    tasks = orchestration.create_tasks(cast(Session, session), job, specs, now=NOW)
    assert tasks, "the file module has catalog entries"
    for task in tasks:
        assert task.file_upload_id == upload_id
        assert task.target_domain is None and task.target_asset_id is None


# --- transitions ------------------------------------------------------------


def test_mark_job_running_is_idempotent() -> None:
    """A re-delivered job keeps its original start (stranded republish)."""
    job = _job()
    orchestration.mark_job_running(job, now=NOW)
    assert job.status is ScanJobStatus.RUNNING and job.started_at == NOW
    later = NOW + timedelta(seconds=30)
    orchestration.mark_job_running(job, now=later)
    assert job.started_at == NOW


def test_mark_task_running_refuses_duplicates() -> None:
    """A second delivery of a running task must not rewind it."""
    task = _task()
    orchestration.mark_task_running(task, now=NOW)
    with pytest.raises(ValueError, match="not queued"):
        orchestration.mark_task_running(task, now=NOW)


def test_mark_task_terminal_sets_the_finish_and_refuses_overwrites() -> None:
    """Terminal is once: a late success cannot overwrite a canceled task (§7.2)."""
    task = _task()
    orchestration.mark_task_terminal(
        task,
        ScanTaskStatus.CANCELED,
        reason=orchestration.REASON_TASK_CANCELED,
        now=NOW,
    )
    assert task.finished_at == NOW
    with pytest.raises(ValueError, match="already terminal"):
        orchestration.mark_task_terminal(
            task, ScanTaskStatus.COMPLETED, reason=None, now=NOW
        )


def test_mark_task_terminal_guards_the_vocabulary() -> None:
    """Non-terminal targets and reasonless blocks are refused loudly."""
    with pytest.raises(ValueError, match="not a terminal"):
        orchestration.mark_task_terminal(
            _task(), ScanTaskStatus.RUNNING, reason=None, now=NOW
        )
    with pytest.raises(ValueError, match="blocked_says_why"):
        orchestration.mark_task_terminal(
            _task(), ScanTaskStatus.BLOCKED, reason=None, now=NOW
        )


# --- outcome derivation -----------------------------------------------------


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([], None),
        ([ScanTaskStatus.RUNNING, ScanTaskStatus.COMPLETED], None),
        ([ScanTaskStatus.QUEUED], None),
        (
            [ScanTaskStatus.COMPLETED, ScanTaskStatus.COMPLETED],
            (ScanJobStatus.COMPLETED, None),
        ),
        (
            [ScanTaskStatus.COMPLETED, ScanTaskStatus.FAILED],
            (ScanJobStatus.PARTIAL, orchestration.REASON_TASKS_INCOMPLETE),
        ),
        (
            [ScanTaskStatus.COMPLETED, ScanTaskStatus.CANCELED],
            (ScanJobStatus.PARTIAL, orchestration.REASON_TASKS_INCOMPLETE),
        ),
        (
            [ScanTaskStatus.FAILED, ScanTaskStatus.BLOCKED],
            (ScanJobStatus.FAILED, orchestration.REASON_NO_USABLE_RESULTS),
        ),
        (
            [ScanTaskStatus.CANCELED, ScanTaskStatus.FAILED],
            (ScanJobStatus.CANCELED, orchestration.REASON_JOB_CANCELED),
        ),
        (
            [ScanTaskStatus.SKIPPED, ScanTaskStatus.BLOCKED],
            (ScanJobStatus.FAILED, orchestration.REASON_NO_USABLE_RESULTS),
        ),
    ],
)
def test_derive_job_outcome(
    statuses: list[ScanTaskStatus],
    expected: tuple[ScanJobStatus, str | None] | None,
) -> None:
    """Every arrow of the scan-job state diagram's counting rule."""
    assert orchestration.derive_job_outcome(statuses) == expected


def test_job_timeout_reason_overrides_and_resolves_by_usable_results() -> None:
    """A job timeout is `partial` with results, `failed` without (api-design)."""
    with_results = orchestration.derive_job_outcome(
        [ScanTaskStatus.COMPLETED, ScanTaskStatus.FAILED],
        reason_override=orchestration.REASON_JOB_TIMEOUT,
    )
    assert with_results == (ScanJobStatus.PARTIAL, orchestration.REASON_JOB_TIMEOUT)
    without = orchestration.derive_job_outcome(
        [ScanTaskStatus.FAILED],
        reason_override=orchestration.REASON_JOB_TIMEOUT,
    )
    assert without == (ScanJobStatus.FAILED, orchestration.REASON_JOB_TIMEOUT)


# --- failure classification -------------------------------------------------


def test_classify_failure_maps_the_contract_exceptions() -> None:
    """ValueError is bad input; an unrecognized error is the engine failing."""
    assert (
        orchestration.classify_failure(ValueError("no domain"))
        == orchestration.REASON_INVALID_INPUT
    )
    assert (
        orchestration.classify_failure(RuntimeError("engine exploded"))
        == orchestration.REASON_ENGINE_ERROR
    )
    assert (
        orchestration.classify_failure(TypeError("boom"))
        == orchestration.REASON_ENGINE_ERROR
    )


def test_budget_kill_classifies_as_timeout_end_to_end() -> None:
    """The drift test pinning `TIMEOUT_MARKER` to `run_engine`'s wording.

    A real child overruns a tiny budget; the outcome's error must classify as
    the task timeout, or a rewording in `modules/execution.py` has silently
    turned every timeout into a generic engine error.
    """
    outcome = run_engine(
        "nc3_testing_platform.modules.noop.engine:assess",
        args=("example.lu",),
        kwargs={"timeout": 1.0, "delay": 30.0},
        budget=0.05,
        grace=0.5,
        progress=ProgressEmitter(test_key="web.noop"),
    )
    assert outcome.timed_out
    with pytest.raises(RuntimeError) as excinfo:
        outcome.unwrap()
    assert (
        orchestration.classify_failure(excinfo.value)
        == orchestration.REASON_TASK_TIMEOUT
    )


# --- persistence ------------------------------------------------------------


def _result() -> ModuleResult:
    """A two-finding module result shaped like the noop's."""
    return ModuleResult(
        schema_version="noop/1.0",
        raw_output={"verdict": "ok"},
        summary={"findings": 2},
        findings=(
            NormalizedFinding(
                check_id="web.noop.ran",
                severity=FindingSeverity.INFO,
                title="ran",
                description="d",
            ),
            NormalizedFinding(
                check_id="web.noop.slow",
                severity=FindingSeverity.LOW,
                title="slow",
                description="d",
            ),
        ),
    )


def test_persist_result_writes_result_then_findings() -> None:
    """Two-step write: findings hang off the result's application-side id."""
    session = RecordingSession()
    task = _task(organization_id=None)
    record = orchestration.persist_result(
        cast(Session, session), task, _result(), completed_at=NOW
    )
    results = [obj for obj in session.added if isinstance(obj, ScanResult)]
    findings = [obj for obj in session.added if isinstance(obj, Finding)]
    assert results == [record]
    # The result row is flushed before any finding is added: the ORM has no
    # relationship() to order the inserts, so the flush is the ordering.
    assert session.flushes == [1]
    assert record.scan_task_id == task.id
    assert record.completed_at == NOW
    assert record.grade is None
    assert record.severity_counts == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 1,
    }
    assert len(findings) == 2
    for finding in findings:
        assert finding.scan_result_id == record.id
        # The B12a / US #87 seam: history-derived statuses replace this.
        assert finding.status is FindingStatus.NEW


def test_derive_finding_status_is_the_b12a_seam() -> None:
    """Every finding is `new` until B12a derives statuses from history."""
    assert orchestration.derive_finding_status() is FindingStatus.NEW


def test_reason_codes_are_namespaced_text() -> None:
    """`status_reason` codes follow the namespaced-text shape (§7.1/§7.2)."""
    reasons = [
        value
        for name, value in vars(orchestration).items()
        if name.startswith("REASON_")
    ]
    assert reasons, "the reason vocabulary must exist"
    for reason in reasons:
        prefix, _, rest = reason.partition(".")
        assert prefix in {"task", "job"} and rest, reason
