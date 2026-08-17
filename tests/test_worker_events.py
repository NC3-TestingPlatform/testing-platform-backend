"""The worker's Redis event publishing: payload shape and the advisory rule.

`fakeredis` stands in for Redis, so the pub/sub path is exercised for real:
what lands on the channel must parse back through the SSE schemas of
`domains/scans/schemas.py`, because B13's endpoint relays these messages to
browsers verbatim.
"""

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import fakeredis
import pytest
from uuid6 import uuid7

from nc3_testing_platform.core.enums import ScanJobStatus, ScanTaskStatus
from nc3_testing_platform.domains.scans.schemas import (
    ScanEndEvent,
    ScanHeartbeatEvent,
    ScanJobEvent,
    ScanTaskEvent,
)
from nc3_testing_platform.worker import events

NOW = datetime(2026, 8, 17, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def client() -> fakeredis.FakeRedis:
    """A fresh fake Redis per test."""
    return fakeredis.FakeRedis(decode_responses=True)


def _drain(client: fakeredis.FakeRedis, job_id: uuid.UUID) -> Any:
    """Subscribe to the job's channel and consume the subscribe confirmation."""
    pubsub = client.pubsub()
    pubsub.subscribe(events.channel(job_id))
    assert pubsub.get_message(timeout=1) is not None
    return pubsub


def _payloads(pubsub: Any) -> list[dict[str, Any]]:
    """Every published message, JSON-decoded."""
    out: list[dict[str, Any]] = []
    while True:
        message = pubsub.get_message(timeout=0.1)
        if message is None:
            return out
        if message["type"] == "message":
            out.append(json.loads(message["data"]))


def test_task_event_round_trips_the_sse_schema(client: fakeredis.FakeRedis) -> None:
    """One `task` message whose data validates as a ScanTaskEvent."""
    job_id, task_id = uuid7(), uuid7()
    pubsub = _drain(client, job_id)
    events.publish_task_event(
        job_id,
        task_id=task_id,
        status=ScanTaskStatus.FAILED,
        status_reason="task.timeout",
        occurred_at=NOW,
        client=client,
    )
    (message,) = _payloads(pubsub)
    assert message["event"] == "task"
    parsed = ScanTaskEvent.model_validate(message["data"])
    assert parsed.task_id == task_id
    assert parsed.status is ScanTaskStatus.FAILED
    assert parsed.status_reason == "task.timeout"


def test_running_job_event_does_not_end_the_stream(
    client: fakeredis.FakeRedis,
) -> None:
    """A non-terminal `job` event stands alone."""
    job_id = uuid7()
    pubsub = _drain(client, job_id)
    events.publish_job_event(
        job_id,
        status=ScanJobStatus.RUNNING,
        status_reason=None,
        occurred_at=NOW,
        client=client,
    )
    messages = _payloads(pubsub)
    assert [m["event"] for m in messages] == ["job"]
    ScanJobEvent.model_validate(messages[0]["data"])


def test_terminal_job_event_is_followed_by_end(client: fakeredis.FakeRedis) -> None:
    """A terminal `job` event ends the stream: `end` follows on the channel."""
    job_id = uuid7()
    pubsub = _drain(client, job_id)
    events.publish_job_event(
        job_id,
        status=ScanJobStatus.PARTIAL,
        status_reason="job.timeout",
        occurred_at=NOW,
        client=client,
    )
    messages = _payloads(pubsub)
    assert [m["event"] for m in messages] == ["job", "end"]
    end = ScanEndEvent.model_validate(messages[1]["data"])
    assert end.status is ScanJobStatus.PARTIAL


def test_heartbeat_round_trips(client: fakeredis.FakeRedis) -> None:
    """The interval signal parses as a ScanHeartbeatEvent."""
    job_id = uuid7()
    pubsub = _drain(client, job_id)
    events.publish_heartbeat(job_id, occurred_at=NOW, client=client)
    (message,) = _payloads(pubsub)
    assert message["event"] == "heartbeat"
    ScanHeartbeatEvent.model_validate(message["data"])


def test_a_failing_publish_is_swallowed() -> None:
    """Advisory on every path: a Redis outage must not fail the scan."""

    class ExplodingClient:
        """The unhappy path: every publish raises."""

        def publish(self, channel: str, message: str) -> None:
            """Refuse, loudly."""
            raise ConnectionError("redis is down")

    events.publish_task_event(
        uuid7(),
        task_id=uuid7(),
        status=ScanTaskStatus.COMPLETED,
        status_reason=None,
        occurred_at=NOW,
        client=ExplodingClient(),  # type: ignore[arg-type]
    )
