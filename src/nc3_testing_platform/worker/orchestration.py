"""The scan-job state machine: matrix build, transitions, completion counting.

Orchestration is DB-coordinated (Runtime & lifecycle views): the parent
`scan_job` row fans out into one `scan_task` per catalog test of each
requested module, children write their own state to PostgreSQL, and the job's
terminal state is derived by counting terminal children against the expected
matrix — no Celery chord and no result-backend coordination. Every function
here either is pure over plain values and ORM instances (the testable
decision core) or takes the `Session` explicitly (the thin IO shell around
it); nothing reads a clock — `now` is always caller-supplied.

Timeout is a *reason*, never a status (state diagram; api-design): a killed
engine lands its task in `failed` with `REASON_TASK_TIMEOUT`, and the job
resolves to `partial` when sibling results survive, otherwise `failed`.
"""

import uuid
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

import sqlalchemy as sa
from dateutil.relativedelta import relativedelta
from sqlalchemy.orm import Session
from uuid6 import uuid7

from nc3_testing_platform.core.enums import (
    FindingStatus,
    ScanClassification,
    ScanJobStatus,
    ScanModule,
    ScanTaskStatus,
)
from nc3_testing_platform.domains.findings.models import Finding
from nc3_testing_platform.domains.scans.models import ScanJob, ScanResult, ScanTask
from nc3_testing_platform.modules import catalog
from nc3_testing_platform.modules.contract import ModuleResult
from nc3_testing_platform.modules.normalization import rows
from nc3_testing_platform.modules.registry import ModuleRegistryError, Roster

# `status_reason` vocabulary: stable namespaced codes (data-model §7.1/§7.2),
# shaped like `test_key` — labels and localization are presentation-owned.
REASON_TASK_TIMEOUT = "task.timeout"
REASON_ENGINE_ERROR = "task.engine_error"
REASON_INVALID_INPUT = "task.invalid_input"
REASON_MODULE_UNAVAILABLE = "task.module_unavailable"
REASON_MISROUTED = "task.misrouted"
REASON_TASK_CANCELED = "task.canceled"
REASON_JOB_TIMEOUT = "job.timeout"
REASON_JOB_CANCELED = "job.canceled"
REASON_NO_USABLE_RESULTS = "job.no_usable_results"
REASON_TASKS_INCOMPLETE = "job.tasks_incomplete"

TERMINAL_TASK_STATUSES = frozenset(
    {
        ScanTaskStatus.COMPLETED,
        ScanTaskStatus.FAILED,
        ScanTaskStatus.SKIPPED,
        ScanTaskStatus.BLOCKED,
        ScanTaskStatus.CANCELED,
    }
)
TERMINAL_JOB_STATUSES = frozenset(
    {
        ScanJobStatus.COMPLETED,
        ScanJobStatus.PARTIAL,
        ScanJobStatus.FAILED,
        ScanJobStatus.CANCELED,
    }
)

# How `run_engine` words a budget kill (modules/execution.py); the only
# signal that survives `EngineOutcome.unwrap()`'s RuntimeError. Pinned by a
# drift test so a rewording there cannot silently turn timeouts into
# generic engine errors here.
TIMEOUT_MARKER = "overran its"

# The version recorded on a task whose module is not installed (B1 provisions
# engines): the platform cannot know a version the roster does not declare.
UNAVAILABLE_TEST_VERSION = "unknown"


def classify_failure(exc: BaseException) -> str:
    """The `status_reason` code for one exception out of a module run.

    Mirrors the module contract: `ValueError` is input the module cannot
    accept; a `RuntimeError` wording a budget kill is the timeout; anything
    else is the engine failing.
    """
    if isinstance(exc, ValueError):
        return REASON_INVALID_INPUT
    if isinstance(exc, RuntimeError) and TIMEOUT_MARKER in str(exc):
        return REASON_TASK_TIMEOUT
    return REASON_ENGINE_ERROR


@dataclass(frozen=True)
class TaskSpec:
    """One planned `scan_task` row: a catalog test resolved against the roster.

    `queue` is ``None`` exactly when no installed module implements the test;
    such a task is created `blocked` with `blocked_reason`, so a requested
    module the image cannot serve is visible in the task list instead of
    silently absent (api-design: "a requested module whose task was blocked
    or skipped produced nothing").
    """

    test_key: str
    test_version: str
    module: ScanModule
    classification: ScanClassification
    queue: str | None
    blocked_reason: str | None


def plan_task_matrix(
    modules_requested: Sequence[ScanModule], roster: Roster
) -> tuple[TaskSpec, ...]:
    """The v4.0 matrix: one spec per catalog test of each requested module.

    v4.0 jobs carry a single target, so the module × asset matrix of the
    all-in-one flow degenerates to module × 1; discovery-driven children
    (`parent_task_id` lineage) arrive with the subdomain-enumeration module.

    :param modules_requested: `scan_job.modules`, in launch order.
    :param roster: The validated plug-in population.
    :return: Specs in catalog order per module, launch order across modules.
    """
    specs: list[TaskSpec] = []
    for module in modules_requested:
        for entry in catalog.tests_for_module(module):
            try:
                loaded = roster.by_test_key(entry.test_key)
            except ModuleRegistryError:
                specs.append(
                    TaskSpec(
                        test_key=entry.test_key,
                        test_version=UNAVAILABLE_TEST_VERSION,
                        module=entry.module,
                        classification=entry.classification,
                        queue=None,
                        blocked_reason=REASON_MODULE_UNAVAILABLE,
                    )
                )
                continue
            declared = next(
                test
                for test in loaded.implementation.descriptor.tests
                if test.test_key == entry.test_key
            )
            specs.append(
                TaskSpec(
                    test_key=entry.test_key,
                    test_version=declared.test_version,
                    module=entry.module,
                    classification=entry.classification,
                    queue=loaded.implementation.descriptor.queue,
                    blocked_reason=None,
                )
            )
    return tuple(specs)


def create_tasks(
    session: Session, job: ScanJob, specs: Sequence[TaskSpec], *, now: datetime
) -> list[ScanTask]:
    """Materialize the matrix as `scan_task` rows on `job`, added to `session`.

    Target propagation follows `one_task_target`: a File test targets the
    job's upload, everything else inherits the job's asset or guest domain.
    Blocked specs are terminal at creation (`finished_at = now`, CHECK
    `terminal_state_has_finish`); the rest start `queued`.

    :param session: The unit of work; the caller flushes/commits.
    :param job: The committed parent row.
    :param specs: The planned matrix from :func:`plan_task_matrix`.
    :param now: The creation instant, caller-supplied.
    :return: The new rows, in spec order, ids already assigned (UUIDv7,
        application-side) so the caller can enqueue by `scan_task.id`.
    """
    tasks: list[ScanTask] = []
    for spec in specs:
        is_file = spec.module is ScanModule.FILE
        blocked = spec.blocked_reason is not None
        task = ScanTask(
            id=uuid7(),
            organization_id=job.organization_id,
            scan_job_id=job.id,
            module=spec.module,
            test_key=spec.test_key,
            test_version=spec.test_version,
            classification=spec.classification,
            target_asset_id=None if is_file else job.asset_id,
            target_domain=None if is_file else job.target_domain,
            file_upload_id=job.file_upload_id if is_file else None,
            configuration=dict(job.module_configuration.get(spec.module.value, {})),
            status=ScanTaskStatus.BLOCKED if blocked else ScanTaskStatus.QUEUED,
            status_reason=spec.blocked_reason,
            finished_at=now if blocked else None,
        )
        session.add(task)
        tasks.append(task)
    return tasks


def mark_job_running(job: ScanJob, *, now: datetime) -> None:
    """`queued` → `running` on delivery (state diagram), idempotently.

    A re-published stranded job may be delivered twice; the second delivery
    finds it already running and must not rewind `started_at`.
    """
    if job.status is not ScanJobStatus.QUEUED:
        return
    job.status = ScanJobStatus.RUNNING
    job.started_at = now


def mark_task_running(task: ScanTask, *, now: datetime) -> None:
    """`queued` → `running`; anything else is a duplicate delivery and raises."""
    if task.status is not ScanTaskStatus.QUEUED:
        raise ValueError(
            f"task {task.id} is {task.status.value}, not queued; refusing to run."
        )
    task.status = ScanTaskStatus.RUNNING
    task.started_at = now


def mark_task_terminal(
    task: ScanTask,
    status: ScanTaskStatus,
    *,
    reason: str | None,
    now: datetime,
) -> None:
    """Move one task into a terminal state, once.

    :raises ValueError: For a non-terminal target status, a missing reason on
        `blocked` (CHECK `blocked_says_why`), or a task already terminal — a
        canceled task must never be overwritten by a late success (§7.2).
    """
    if status not in TERMINAL_TASK_STATUSES:
        raise ValueError(f"{status.value} is not a terminal task status.")
    if status is ScanTaskStatus.BLOCKED and reason is None:
        raise ValueError("a blocked task must say why (blocked_says_why).")
    if task.status in TERMINAL_TASK_STATUSES:
        raise ValueError(
            f"task {task.id} is already terminal ({task.status.value}); "
            f"refusing to overwrite with {status.value}."
        )
    task.status = status
    task.status_reason = reason
    task.finished_at = now


def derive_finding_status() -> FindingStatus:
    """The `finding.status` seam: B12a / US #87 derives it from history.

    Until that story lands, every finding is recorded as `new` — the correct
    value for a target's first scan and the only value derivable without the
    historical comparison B12a owns. This function exists so B12a replaces
    one seam instead of hunting write sites.
    """
    return FindingStatus.NEW


def persist_result(
    session: Session,
    task: ScanTask,
    result: ModuleResult,
    *,
    completed_at: datetime,
) -> ScanResult:
    """Write one result and its findings via the pure row mappers (IDR-018).

    Two steps with a flush in between: the id is application-side UUIDv7, but
    the models carry no `relationship()`, so the ORM flush would otherwise
    order the two inserts arbitrarily and the findings' foreign key can fire
    before its result row exists.

    :param session: The unit of work; the caller commits.
    :param task: The task this result belongs to (at most one result each).
    :param result: What the module returned.
    :param completed_at: When the task finished — the same instant the task's
        terminal transition records, platform-owned.
    :return: The new `scan_result` row, id assigned.
    """
    record = ScanResult(
        id=uuid7(),
        **rows.scan_result_row(
            result,
            scan_task_id=task.id,
            completed_at=completed_at,
            organization_id=task.organization_id,
        ),
    )
    session.add(record)
    session.flush()
    for finding_row in rows.finding_rows(
        result, scan_result_id=record.id, organization_id=task.organization_id
    ):
        session.add(Finding(id=uuid7(), status=derive_finding_status(), **finding_row))
    return record


def derive_job_outcome(
    statuses: Collection[ScanTaskStatus],
    *,
    reason_override: str | None = None,
) -> tuple[ScanJobStatus, str | None] | None:
    """The job's terminal state from its children, or ``None`` while any runs.

    The counting rule of the state diagram: all children completed →
    `completed`; any usable result alongside failures → `partial`; nothing
    usable → `canceled` when cancellation stopped the work, else `failed`.
    `reason_override` carries a job-level cause (the reaper's job timeout)
    into whatever state the count resolves to.

    :param statuses: Every child task's current status. Empty means the
        matrix does not exist yet, which is not terminal.
    """
    if not statuses or any(s not in TERMINAL_TASK_STATUSES for s in statuses):
        return None
    completed = sum(1 for s in statuses if s is ScanTaskStatus.COMPLETED)
    if completed == len(statuses):
        return ScanJobStatus.COMPLETED, reason_override
    if completed:
        return ScanJobStatus.PARTIAL, reason_override or REASON_TASKS_INCOMPLETE
    if any(s is ScanTaskStatus.CANCELED for s in statuses):
        return ScanJobStatus.CANCELED, reason_override or REASON_JOB_CANCELED
    return ScanJobStatus.FAILED, reason_override or REASON_NO_USABLE_RESULTS


def finalize_job_if_done(
    session: Session,
    job_id: uuid.UUID,
    *,
    now: datetime,
    reason_override: str | None = None,
) -> tuple[ScanJobStatus, str | None] | None:
    """Close the job iff every child is terminal. Serialized, at-most-once.

    ``SELECT … FOR UPDATE`` on the job row makes concurrent finishers take
    turns: the one that sees the full count closes the job, every other one
    re-reads a terminal row and leaves. The caller commits, then publishes
    (Datastore-split ADR: terminal state reaches PostgreSQL before Redis).

    On terminal completion `purge_at` is set to `finished_at` + 12 months +
    30 days (§7.1) unless a deadline already stands — an unclaimed guest job
    keeps its 24-hour one from creation.

    :return: The `(status, reason)` this call committed, or ``None`` when the
        job is not done yet or was already closed.
    """
    job = session.execute(
        sa.select(ScanJob).where(ScanJob.id == job_id).with_for_update()
    ).scalar_one_or_none()
    if job is None or job.status in TERMINAL_JOB_STATUSES:
        return None
    statuses = (
        session.execute(
            sa.select(ScanTask.status).where(ScanTask.scan_job_id == job_id)
        )
        .scalars()
        .all()
    )
    outcome = derive_job_outcome(statuses, reason_override=reason_override)
    if outcome is None:
        return None
    job.status, job.status_reason = outcome
    job.finished_at = now
    if job.purge_at is None:
        job.purge_at = now + relativedelta(months=12) + timedelta(days=30)
    return outcome
