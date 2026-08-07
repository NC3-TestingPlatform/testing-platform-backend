"""Database queries for scan execution.

Every function takes the session as its first argument and returns models or plain
values.
Nothing here opens a transaction, commits, or raises HTTP errors; those belong to
`service.py` and `router.py` respectively.

Nothing here is implemented yet.
"""

# TODO: get_job(session, scan_id) and get_task(session, task_id).
# TODO: list_jobs(session, ...) with cursor pagination, ordered stably.
# TODO: insert_job_with_tasks(session, ...) creating both in one flush.
# TODO: claim_job(session, scan_id, token_hash) as a single conditional update:
#   unclaimed guest job, matching hash, deadline not passed.
# TODO: list_results(session, scan_id) and the finding filters in api-design §6.
# TODO: mark_cancellation_requested(session, task_id).
