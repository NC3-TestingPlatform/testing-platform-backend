"""Database queries for scan execution.

Every function takes the session as its first argument and returns models or plain
values.
Nothing here opens a transaction, commits, or raises HTTP errors; those belong to
`service.py` and `router.py` respectively.

Task creation is worker-side: `scan.dispatch` builds the module × asset matrix
after the job row is committed and published (Runtime & lifecycle views — the
all-in-one activity flow), so the launch inserts only the `scan_job` row.
"""

import uuid

from sqlalchemy.orm import Session

from nc3_testing_platform.domains.scans.models import ScanJob, ScanTask


def get_job(session: Session, scan_id: uuid.UUID) -> ScanJob | None:
    """The job row, or ``None`` when it does not exist (or is purged)."""
    return session.get(ScanJob, scan_id)


def get_task(session: Session, task_id: uuid.UUID) -> ScanTask | None:
    """The task row, or ``None`` when it does not exist (or is purged)."""
    return session.get(ScanTask, task_id)


# TODO: list_jobs(session, ...) with cursor pagination, ordered stably.
# TODO: claim_job(session, scan_id, token_hash) as a single conditional update:
#   unclaimed guest job, matching hash, deadline not passed.
# TODO: list_results(session, scan_id) and the finding filters in api-design §6.
# TODO: mark_cancellation_requested(session, task_id).
