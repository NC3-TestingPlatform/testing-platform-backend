"""The scan pipeline: dispatch fans out, modules run, results persist.

Replaces the compose round-trip mock (issue #3) with the real, DB-coordinated
pipeline of B8 / US #84: `scan.dispatch` materializes the task matrix from a
committed `scan_job` row and publishes one `scan.run_module` per task to the
queue its module declares; each task runs its module through the registry's
worker-side gate and the killable child runner, persists via the pure row
mappers, and the job closes by counting terminal children — no chord, no
result-backend coordination (Runtime & lifecycle views).

Ordering rule on every path (Datastore-split ADR): the PostgreSQL commit
happens first, the Redis publish after — an event never advertises state a
rollback can undo. And no session stays open across an engine run: a module
can lawfully run for minutes, which would otherwise pin a pooled connection
per in-flight scan.

`scan.reap` and `scan.heartbeat` are the beat-driven closers of the state
diagram's two holes: a job committed but never delivered (stranded publish)
is re-published, and a job stuck `running` past its wall-clock budget is
failed with the job-timeout reason — resolving to `partial` when usable
results survived, which is the acceptance criterion made mechanical.
"""

import uuid
from datetime import UTC, datetime, timedelta
from logging import getLogger

import sqlalchemy as sa

from nc3_testing_platform.core.enums import ScanJobStatus, ScanTaskStatus
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.domains.assets.models import Asset
from nc3_testing_platform.domains.scans.models import FileUpload, ScanJob, ScanTask
from nc3_testing_platform.modules.contract import (
    ModuleResult,
    ProgressEmitter,
    ScanInput,
)
from nc3_testing_platform.modules.registry import (
    ModuleRegistryError,
    Roster,
    discover,
)
from nc3_testing_platform.worker import events, orchestration
from nc3_testing_platform.worker.app import app
from nc3_testing_platform.worker.db import session

logger = getLogger(__name__)

_roster: Roster | None = None


def get_roster() -> Roster:
    """The validated module roster, discovered once per worker process."""
    global _roster
    if _roster is None:
        _roster = discover()
    return _roster


def _now() -> datetime:
    """The platform clock: timezone-aware UTC, like every stored timestamp."""
    return datetime.now(UTC)


def _finalize_and_publish(
    job_id: uuid.UUID, *, reason_override: str | None = None
) -> None:
    """Close the job if all children are terminal; publish only what committed."""
    now = _now()
    with session() as unit:
        outcome = orchestration.finalize_job_if_done(
            unit, job_id, now=now, reason_override=reason_override
        )
        unit.commit()
    if outcome is not None:
        status, reason = outcome
        events.publish_job_event(
            job_id, status=status, status_reason=reason, occurred_at=now
        )


@app.task(name="scan.dispatch")
def dispatch(job_id: str) -> int:
    """Fan one committed job out: create the task matrix, publish the children.

    Idempotent by design, because the reaper re-publishes stranded jobs: an
    existing matrix is never recreated, only its still-queued tasks are
    re-sent, and a job already running keeps its `started_at`.

    :param job_id: The `scan_job.id`, committed by the launch before this
        task was published (the launch-story seam).
    :return: How many child tasks were published.
    """
    now = _now()
    job_uuid = uuid.UUID(job_id)
    announce_running = False
    to_publish: list[tuple[uuid.UUID, str]] = []
    with session() as unit:
        job = unit.get(ScanJob, job_uuid)
        if job is None:
            logger.warning("scan.dispatch: job %s does not exist; dropping.", job_id)
            return 0
        if job.status in orchestration.TERMINAL_JOB_STATUSES:
            return 0
        tasks = (
            unit.execute(sa.select(ScanTask).where(ScanTask.scan_job_id == job.id))
            .scalars()
            .all()
        )
        if not tasks:
            specs = orchestration.plan_task_matrix(list(job.modules), get_roster())
            tasks = orchestration.create_tasks(unit, job, specs, now=now)
        announce_running = job.status is ScanJobStatus.QUEUED
        orchestration.mark_job_running(job, now=now)
        for task in tasks:
            if (
                task.status is not ScanTaskStatus.QUEUED
                or task.cancellation_requested_at is not None
            ):
                continue
            try:
                queue = get_roster().queue_for(task.test_key)
            except ModuleRegistryError:
                # The module vanished between task creation and (re)dispatch.
                orchestration.mark_task_terminal(
                    task,
                    ScanTaskStatus.BLOCKED,
                    reason=orchestration.REASON_MODULE_UNAVAILABLE,
                    now=now,
                )
                continue
            to_publish.append((task.id, queue))
        unit.commit()
    if announce_running:
        events.publish_job_event(
            job_uuid,
            status=ScanJobStatus.RUNNING,
            status_reason=None,
            occurred_at=now,
        )
    for task_id, queue in to_publish:
        # scan_task.id doubles as the queue task id (§7.2): cancellation
        # revokes by it, and no second identifier is stored anywhere.
        app.send_task(
            "scan.run_module",
            args=(str(task_id),),
            queue=queue,
            task_id=str(task_id),
        )
    # An all-blocked matrix is terminal at creation; close the job now
    # rather than wait for a child that will never report.
    _finalize_and_publish(job_uuid)
    return len(to_publish)


@app.task(name="scan.run_module")
def run_module(task_id: str) -> str:
    """Execute one scan task end to end on this worker's egress queue.

    Claim the row, gate it against the roster and this worker's queue, run
    the module (engine in a killable child, per-engine budget — IDR-004
    amendment), then record exactly one outcome. Cancellation intent is
    honored at the two safe points: before the run starts and before the
    result is written — a canceled task never gains a result (§7.2).

    :param task_id: The `scan_task.id`, which is also this delivery's queue
        task id.
    :return: The task's final status value, for the worker log.
    """
    now = _now()
    task_uuid = uuid.UUID(task_id)

    # Phase 1 — claim the task and resolve its input; no engine work yet.
    with session() as unit:
        task = unit.get(ScanTask, task_uuid)
        if task is None:
            logger.warning("scan.run_module: task %s does not exist.", task_id)
            return "missing"
        job_id = task.scan_job_id
        if task.status is not ScanTaskStatus.QUEUED:
            logger.info(
                "scan.run_module: duplicate delivery of %s (%s); ignoring.",
                task_id,
                task.status.value,
            )
            return task.status.value
        if task.cancellation_requested_at is not None:
            orchestration.mark_task_terminal(
                task,
                ScanTaskStatus.CANCELED,
                reason=orchestration.REASON_TASK_CANCELED,
                now=now,
            )
            unit.commit()
            events.publish_task_event(
                job_id,
                task_id=task_uuid,
                status=ScanTaskStatus.CANCELED,
                status_reason=orchestration.REASON_TASK_CANCELED,
                occurred_at=now,
            )
            _finalize_and_publish(job_id)
            return ScanTaskStatus.CANCELED.value
        refusal: str | None = None
        entry = None
        try:
            entry = get_roster().by_test_key(task.test_key)
        except ModuleRegistryError:
            refusal = orchestration.REASON_MODULE_UNAVAILABLE
        if entry is not None:
            declared = entry.implementation.descriptor.queue
            if declared != settings.worker_queue:
                # The egress gate: a task on the wrong queue must not run
                # with the wrong network profile (egress ADR).
                refusal = orchestration.REASON_MISROUTED
        if refusal is not None:
            orchestration.mark_task_terminal(
                task, ScanTaskStatus.BLOCKED, reason=refusal, now=now
            )
            unit.commit()
            events.publish_task_event(
                job_id,
                task_id=task_uuid,
                status=ScanTaskStatus.BLOCKED,
                status_reason=refusal,
                occurred_at=now,
            )
            _finalize_and_publish(job_id)
            return ScanTaskStatus.BLOCKED.value
        target_domain = task.target_domain
        if task.target_asset_id is not None:
            asset = unit.get(Asset, task.target_asset_id)
            target_domain = asset.value if asset is not None else None
        file_path: str | None = None
        if task.file_upload_id is not None:
            upload = unit.get(FileUpload, task.file_upload_id)
            file_path = upload.storage_key if upload is not None else None
        configuration = dict(task.configuration)
        test_key = task.test_key
        orchestration.mark_task_running(task, now=now)
        unit.commit()
    events.publish_task_event(
        job_id,
        task_id=task_uuid,
        status=ScanTaskStatus.RUNNING,
        status_reason=None,
        occurred_at=now,
    )

    # Phase 2 — run the module with no session held: engines run for minutes.
    assert entry is not None  # the refusal path returned above
    module = entry.implementation
    result: ModuleResult | None = None
    failure_reason: str | None = None
    try:
        scan_input = ScanInput(
            target_domain=target_domain,
            file_path=file_path,
            options=configuration,
        )
        result = module.run(scan_input, progress=ProgressEmitter(test_key=test_key))
    except Exception as exc:
        failure_reason = orchestration.classify_failure(exc)
        logger.warning("task %s failed (%s): %s", task_id, failure_reason, exc)

    # Phase 3 — record exactly one outcome, then close the job if done.
    finished = _now()
    with session() as unit:
        task = unit.get(ScanTask, task_uuid)
        if task is None:
            logger.warning("scan.run_module: task %s vanished mid-run.", task_id)
            return "missing"
        if task.status in orchestration.TERMINAL_TASK_STATUSES:
            # The reaper or a cancel closed it while the engine ran; a late
            # success is rejected, not recorded (§7.2).
            logger.info(
                "scan.run_module: task %s closed mid-run (%s); result dropped.",
                task_id,
                task.status.value,
            )
            return task.status.value
        if task.cancellation_requested_at is not None:
            final = (ScanTaskStatus.CANCELED, orchestration.REASON_TASK_CANCELED)
        elif failure_reason is not None or result is None:
            final = (
                ScanTaskStatus.FAILED,
                failure_reason or orchestration.REASON_ENGINE_ERROR,
            )
        else:
            orchestration.persist_result(unit, task, result, completed_at=finished)
            final = (ScanTaskStatus.COMPLETED, None)
        orchestration.mark_task_terminal(task, final[0], reason=final[1], now=finished)
        unit.commit()
    events.publish_task_event(
        job_id,
        task_id=task_uuid,
        status=final[0],
        status_reason=final[1],
        occurred_at=finished,
    )
    _finalize_and_publish(job_id)
    return final[0].value


@app.task(name="scan.reap")
def reap() -> dict[str, int]:
    """The sweep behind the state diagram's reaper arrows.

    Stranded jobs (`queued` older than ``scan_stale_after_seconds``) are
    re-published to `scan.dispatch`, which is idempotent. Stuck jobs
    (`running` past ``scan_job_timeout_seconds``) get their live tasks failed
    with the job-timeout reason and the job closed — `partial` when earlier
    results survive, `failed` otherwise (api-design §7.1).

    :return: Counts per sweep, for the beat log.
    """
    now = _now()
    stale_before = now - timedelta(seconds=settings.scan_stale_after_seconds)
    timeout_before = now - timedelta(seconds=settings.scan_job_timeout_seconds)
    with session() as unit:
        stranded = (
            unit.execute(
                sa.select(ScanJob.id).where(
                    ScanJob.status == ScanJobStatus.QUEUED,
                    ScanJob.created_at < stale_before,
                )
            )
            .scalars()
            .all()
        )
        stuck = (
            unit.execute(
                sa.select(ScanJob.id).where(
                    ScanJob.status == ScanJobStatus.RUNNING,
                    ScanJob.started_at < timeout_before,
                )
            )
            .scalars()
            .all()
        )
    for job_id in stranded:
        app.send_task("scan.dispatch", args=(str(job_id),), queue="platform")
    for job_id in stuck:
        swept = _now()
        failed_tasks: list[uuid.UUID] = []
        with session() as unit:
            live_tasks = (
                unit.execute(
                    sa.select(ScanTask).where(
                        ScanTask.scan_job_id == job_id,
                        ScanTask.status.not_in(orchestration.TERMINAL_TASK_STATUSES),
                    )
                )
                .scalars()
                .all()
            )
            for task in live_tasks:
                orchestration.mark_task_terminal(
                    task,
                    ScanTaskStatus.FAILED,
                    reason=orchestration.REASON_JOB_TIMEOUT,
                    now=swept,
                )
                failed_tasks.append(task.id)
            unit.commit()
        for failed_id in failed_tasks:
            # Best effort: pull an undelivered child off its queue. A child
            # already executing keeps running until its own budget kill; its
            # late result is rejected by the terminal-row guard.
            try:
                app.control.revoke(str(failed_id))
            except Exception:
                logger.exception("revoke of task %s failed", failed_id)
            events.publish_task_event(
                job_id,
                task_id=failed_id,
                status=ScanTaskStatus.FAILED,
                status_reason=orchestration.REASON_JOB_TIMEOUT,
                occurred_at=swept,
            )
        _finalize_and_publish(job_id, reason_override=orchestration.REASON_JOB_TIMEOUT)
    return {"republished": len(stranded), "timed_out": len(stuck)}


@app.task(name="scan.heartbeat")
def heartbeat() -> int:
    """Publish one heartbeat per running job.

    Lets B13's streams tell a long scan from a dead connection (SSE
    ``heartbeat`` events, api-design §7).

    :return: How many jobs were signalled.
    """
    now = _now()
    with session() as unit:
        running = (
            unit.execute(
                sa.select(ScanJob.id).where(ScanJob.status == ScanJobStatus.RUNNING)
            )
            .scalars()
            .all()
        )
    for job_id in running:
        events.publish_heartbeat(job_id, occurred_at=now)
    return len(running)
