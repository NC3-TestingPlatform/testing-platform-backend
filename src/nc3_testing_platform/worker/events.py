"""Worker-side scan progress publishing to Redis. Advisory, always after commit.

The worker publishes state changes to one pub/sub channel per job; B13's SSE
endpoint subscribes and relays. Payloads are the SSE schemas the contract
already declares (`domains.scans.schemas`), wrapped as
``{"event": <sse event name>, "data": <schema dump>}`` so the relay maps one
message to one ``event:``/``data:`` pair without re-shaping anything.

Two rules from the Datastore-split ADR and the state diagram:

* **Publish after the commit it describes.** Database state is authoritative;
  an event for an uncommitted transition would advertise state a rollback can
  undo. Callers commit first, then publish.
* **Advisory on every path.** A Redis outage must not fail a scan that
  PostgreSQL accepted, so a failed publish is logged and swallowed — the same
  rule `ProgressEmitter.emit` applies to progress sinks.

Sync client, deliberately: `core.redis_utils` is the *application's* asyncio
boundary; Celery tasks are synchronous and must not run an event loop per
publish. Same laziness rationale as `worker.db`.
"""

import json
import uuid
from datetime import datetime
from logging import getLogger

from redis import Redis

from nc3_testing_platform.core.enums import ScanJobStatus, ScanTaskStatus
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.domains.scans.schemas import (
    ScanEndEvent,
    ScanHeartbeatEvent,
    ScanJobEvent,
    ScanTaskEvent,
)

logger = getLogger(__name__)

_client: Redis | None = None


def get_client() -> Redis:
    """The process-wide sync client, created lazily from ``settings.redis_url``.

    Socket timeouts are what make the advisory rule real: without them a
    half-open connection blocks the publish — and the worker slot — until
    Celery's hard limit, so a Redis incident would degrade scan throughput
    instead of just costing events.
    """
    global _client
    if _client is None:
        _client = Redis.from_url(
            settings.redis_url,
            decode_responses=True,
            socket_connect_timeout=2.0,
            socket_timeout=2.0,
            health_check_interval=30,
        )
    return _client


def channel(job_id: uuid.UUID) -> str:
    """The pub/sub channel carrying one job's events (the B13 seam)."""
    return f"scan:events:{job_id}"


def _publish(
    job_id: uuid.UUID,
    event: str,
    data: ScanTaskEvent | ScanJobEvent | ScanHeartbeatEvent | ScanEndEvent,
    client: Redis | None = None,
) -> None:
    """Send one wrapped event; a failed publish is logged, never raised."""
    message = json.dumps({"event": event, "data": data.model_dump(mode="json")})
    try:
        con = client if client is not None else get_client()
        con.publish(channel(job_id), message)
    except Exception:
        logger.exception("publish of %s event for job %s failed", event, job_id)


def publish_task_event(
    job_id: uuid.UUID,
    *,
    task_id: uuid.UUID,
    status: ScanTaskStatus,
    status_reason: str | None,
    occurred_at: datetime,
    client: Redis | None = None,
) -> None:
    """One task changed state (SSE ``task``)."""
    _publish(
        job_id,
        "task",
        ScanTaskEvent(
            task_id=task_id,
            status=status,
            status_reason=status_reason,
            occurred_at=occurred_at,
        ),
        client,
    )


def publish_job_event(
    job_id: uuid.UUID,
    *,
    status: ScanJobStatus,
    status_reason: str | None,
    occurred_at: datetime,
    client: Redis | None = None,
) -> None:
    """The job changed state (SSE ``job``); a terminal state also ends the stream.

    The ``end`` event follows the terminal ``job`` event on the same channel,
    matching the stream contract: after ``end``, no further events.
    """
    _publish(
        job_id,
        "job",
        ScanJobEvent(
            status=status, status_reason=status_reason, occurred_at=occurred_at
        ),
        client,
    )
    if status in _TERMINAL_JOB_STATUSES:
        _publish(
            job_id,
            "end",
            ScanEndEvent(status=status, occurred_at=occurred_at),
            client,
        )


def publish_heartbeat(
    job_id: uuid.UUID,
    *,
    occurred_at: datetime,
    client: Redis | None = None,
) -> None:
    """The job is alive (SSE ``heartbeat``)."""
    _publish(job_id, "heartbeat", ScanHeartbeatEvent(occurred_at=occurred_at), client)


_TERMINAL_JOB_STATUSES = frozenset(
    {
        ScanJobStatus.COMPLETED,
        ScanJobStatus.PARTIAL,
        ScanJobStatus.FAILED,
        ScanJobStatus.CANCELED,
    }
)
