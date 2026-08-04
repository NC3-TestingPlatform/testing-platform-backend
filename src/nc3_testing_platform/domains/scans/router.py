"""Scan launch, lifecycle, live progress, retention, and deletion.

This domain exercises every cross-cutting pattern in the contract — media-type
request dispatch, optional authentication, the `202` async-job shape, cursor
pagination, an SSE channel, problem+json errors, rate-limit headers, and hard
deletion.

Handlers return fixed sample data. The gates listed in :func:`launch_scan` are
application logic.
"""

from collections.abc import Iterator
from typing import Any

from fastapi import APIRouter, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from nc3_testing_platform.core.enums import ScanJobStatus
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import (
    ANONYMOUS_ALTERNATIVE,
    Authenticated,
    rate_limited,
)
from nc3_testing_platform.domains.scans import examples
from nc3_testing_platform.domains.scans.dependencies import (
    JSON_MEDIA_TYPE,
    MULTIPART_MEDIA_TYPE,
    ScanAccessToken,
    ScanLaunchBody,
)
from nc3_testing_platform.domains.scans.schemas import (
    FileScanLaunch,
    ScanClaimRequest,
    ScanEndEvent,
    ScanHeartbeatEvent,
    ScanJob,
    ScanJobAccepted,
    ScanJobDetail,
    ScanJobEvent,
    ScanResult,
    ScanTaskEvent,
)

router = APIRouter(
    prefix="/scans",
    tags=["scans"],
)

# Handwritten because FastAPI generates one request schema per operation from
# type hints, and this operation has three. The variants are registered as
# components by :func:`app.core.openapi.register_component_schemas`, so these
# references resolve to named types in a generated client.
#
# The `oneOf` carries no discriminator on purpose: the selector is the caller's
# access state, not a field in the body, and OpenAPI cannot express that. The
# description states the rule the document cannot.
LAUNCH_REQUEST_BODY: dict[str, Any] = {
    "required": True,
    "description": (
        "The request schema is selected by media type, and within JSON by access "
        "state.\n\n"
        "- `application/json` + authenticated caller → `AssetScanLaunch` "
        "(`asset_id`, an Asset in the caller's organization).\n"
        "- `application/json` + anonymous caller → `GuestScanLaunch` (`target`, a "
        "canonical domain).\n"
        "- `multipart/form-data` → `FileScanLaunch` (one `file` part, no target).\n\n"
        "Supplying the field belonging to the other access state returns `422`. No "
        "schema contains an `asset_id | target | file` union, and no other media "
        "type is accepted."
    ),
    "content": {
        JSON_MEDIA_TYPE: {
            "schema": {
                "oneOf": [
                    {"$ref": "#/components/schemas/AssetScanLaunch"},
                    {"$ref": "#/components/schemas/GuestScanLaunch"},
                ]
            }
        },
        MULTIPART_MEDIA_TYPE: {
            "schema": {"$ref": "#/components/schemas/FileScanLaunch"}
        },
    },
}

# The payload shape is selected by SSE's own `event:` line, which sits outside the
# JSON, so OpenAPI cannot discriminate the `oneOf`. The description carries the
# mapping.
_EVENT_STREAM_RESPONSE: dict[int | str, dict] = {
    200: {
        "description": (
            "Advisory progress events until the job reaches a terminal state. The "
            "SSE `event:` line selects the payload:\n\n"
            "- `task` → `ScanTaskEvent`, one task changed state\n"
            "- `job` → `ScanJobEvent`, the job changed state\n"
            "- `heartbeat` → `ScanHeartbeatEvent`, sent on an interval\n"
            "- `end` → `ScanEndEvent`, terminal state reached, no further events\n\n"
            "Database state is authoritative. Refetch the snapshot after a reconnect "
            "or whenever an applied event leaves the client uncertain."
        ),
        "content": {
            "text/event-stream": {
                "schema": {
                    "oneOf": [
                        {"$ref": "#/components/schemas/ScanTaskEvent"},
                        {"$ref": "#/components/schemas/ScanJobEvent"},
                        {"$ref": "#/components/schemas/ScanHeartbeatEvent"},
                        {"$ref": "#/components/schemas/ScanEndEvent"},
                    ]
                }
            }
        },
    }
}


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Launch a scan",
    response_model=ScanJobAccepted,
    openapi_extra={
        "requestBody": LAUNCH_REQUEST_BODY,
        "security": ANONYMOUS_ALTERNATIVE,
    },
    responses={
        **problem_responses(403, 415, 422),
        **rate_limited(),
    },
)
async def launch_scan(launch: ScanLaunchBody) -> ScanJobAccepted:
    """Launch a domain or file scan.

    Returns `202` with the job resource. An unauthenticated launch also returns the
    one-time token needed to claim the scan after registering.

    The application performs the launch in a fixed order: allocate the job
    identifier, record any required declarations against it, evaluate the gates,
    create job and task state in one transaction, enqueue only once that state is
    durable, then respond. Gates — authorization, verification, current MFA
    assurance, rate, and cooldown — are evaluated from the request context and the
    selected tests. None of them is a field the caller sends.
    """
    return examples.queued_job_accepted(
        guest=not launch.authenticated,
        file_scan=isinstance(launch.body, FileScanLaunch),
    )


@router.get(
    "",
    summary="List scans",
    responses=problem_responses(401),
    dependencies=[Authenticated],
)
async def list_scans(page: CursorPage) -> Page[ScanJob]:
    """Scans in the caller's organization, newest first.

    Guest scans appear here once they are claimed.
    """
    return Page(
        items=[examples.sample_job(), examples.sample_file_job()], next_cursor=None
    )


@router.get(
    "/{scan_id}",
    summary="Get a scan with its task snapshot",
    responses=problem_responses(401, 404),
)
async def get_scan(
    scan_id: ResourceId, claim_token: ScanAccessToken = None
) -> ScanJobDetail:
    """The authoritative job and task state.

    Fetch this before subscribing to the event stream and again after reconnection
    or whenever an applied event leaves the client uncertain.
    """
    if scan_id == examples.FILE_JOB_ID:
        return examples.sample_file_job_detail()
    return examples.sample_job_detail()


@router.get(
    "/{scan_id}/results",
    summary="Get scan results",
    responses=problem_responses(401, 404),
)
async def get_scan_results(
    scan_id: ResourceId, claim_token: ScanAccessToken = None
) -> list[ScanResult]:
    """One result per completed task.

    Not paginated: the collection is bounded by the job's task count, which the
    executable-test catalog caps well below a page.
    """
    return examples.sample_results()


@router.get(
    "/{scan_id}/events",
    summary="Stream live scan progress",
    response_class=StreamingResponse,
    responses={**_EVENT_STREAM_RESPONSE, **problem_responses(401, 404)},
)
async def stream_scan_events(
    scan_id: ResourceId, claim_token: ScanAccessToken = None
) -> StreamingResponse:
    """Advisory server-sent events for a running scan.

    Database state is authoritative; these events only reduce latency.
    The snapshot is the only recovery for missed events: refetch it after a reconnect.
    """

    def event_stream() -> Iterator[str]:
        for name, event in _sample_events():
            yield f"event: {name}\ndata: {event.model_dump_json()}\n\n"

    return StreamingResponse(event_stream(), media_type="text/event-stream")


def _sample_events() -> list[tuple[str, BaseModel]]:
    job = examples.sample_job()
    stream: list[tuple[str, BaseModel]] = [
        ("job", ScanJobEvent(status=ScanJobStatus.RUNNING, occurred_at=job.created_at))
    ]
    for task in examples.sample_tasks():
        stream.append(
            (
                "task",
                ScanTaskEvent(
                    task_id=task.id,
                    status=task.status,
                    status_reason=task.status_reason,
                    occurred_at=task.finished_at or task.created_at,
                ),
            )
        )
    ended = job.finished_at or job.created_at
    stream.append(("heartbeat", ScanHeartbeatEvent(occurred_at=ended)))
    stream.append(("job", ScanJobEvent(status=job.status, occurred_at=ended)))
    stream.append(("end", ScanEndEvent(status=job.status, occurred_at=ended)))
    return stream


@router.post(
    "/{scan_id}/cancel",
    summary="Cancel a running scan",
    responses=problem_responses(401, 404, 409),
    dependencies=[Authenticated],
)
async def cancel_scan(scan_id: ResourceId) -> ScanJob:
    """Record durable cancellation intent.

    Scan history is preserved: canceling is not deletion, and `DELETE` is never
    used to stop execution. Workers check the intent before starting a task and at
    safe interruption points; a canceled task cannot later produce an accepted
    successful result.
    """
    return examples.sample_job()


@router.post(
    "/{scan_id}/claim",
    summary="Claim a guest scan",
    responses=problem_responses(401, 404),
    dependencies=[Authenticated],
)
async def claim_scan(scan_id: ResourceId, body: ScanClaimRequest) -> ScanJob:
    """Attach a guest scan to the authenticated caller's organization.

    One atomic compare-and-set: the job must be an unclaimed guest job whose stored
    hash matches the supplied token and whose retention has not lapsed. Success
    records the claiming user and organization and discards the stored hash, so the
    token cannot be spent twice. For a file scan it also restores organization
    scoping on the upload metadata.

    Every failure answers `404` — wrong token, already claimed, and lapsed are
    indistinguishable from outside. Anything more specific would let a caller
    holding no token confirm that a scan exists and learn its state.
    """
    return examples.sample_job()


@router.post(
    "/{scan_id}/retention/extend",
    summary="Extend the retention deadline",
    responses=problem_responses(401, 403, 404, 409),
    dependencies=[Authenticated],
)
async def extend_retention(scan_id: ResourceId) -> ScanJob:
    """Move `purge_at` further out and record an audit event.

    No request body: the interval is policy, not contract.
    Read the new deadline from the response.
    """
    return examples.sample_job(extended=True)


@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Hard-delete a scan",
    responses=problem_responses(401, 403, 404),
    dependencies=[Authenticated],
)
async def delete_scan(scan_id: ResourceId) -> Response:
    """Delete the scan and its data immediately.

    Distinct from cancellation, which stops execution and keeps the history.
    """
    return Response(status_code=status.HTTP_204_NO_CONTENT)
