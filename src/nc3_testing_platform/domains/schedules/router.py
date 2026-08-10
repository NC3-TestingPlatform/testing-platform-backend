"""Recurring scan management."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Response, status

from nc3_testing_platform.core.enums import ScanModule
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import CredentialRequired
from nc3_testing_platform.domains.scans.examples import (
    ASSET_ID,
    ORGANIZATION_ID,
    USER_ID,
)
from nc3_testing_platform.domains.schedules.schemas import (
    Schedule,
    ScheduleCreate,
    ScheduleUpdate,
)

router = APIRouter(
    prefix="/schedules",
    tags=["schedules"],
)

_SCHEDULE_ID = UUID("019ee1a4-0011-7a22-8b33-4c44d5e66f77")


def _sample_schedule() -> Schedule:
    return Schedule(
        id=_SCHEDULE_ID,
        organization_id=ORGANIZATION_ID,
        asset_id=ASSET_ID,
        created_by_user_id=USER_ID,
        modules=[ScanModule.EMAIL, ScanModule.WEB, ScanModule.DNSSEC],
        recurrence_rule="FREQ=WEEKLY;BYDAY=MO;BYHOUR=2;BYMINUTE=0",
        timezone="Europe/Luxembourg",
        next_run_at=datetime(2026, 8, 3, 0, 0, tzinfo=UTC),
        created_at=datetime(2026, 6, 1, 8, 30, tzinfo=UTC),
        updated_at=datetime(2026, 7, 31, 9, 1, 12, tzinfo=UTC),
    )


@router.get(
    "",
    summary="List schedules",
    responses=problem_responses(401),
    dependencies=[CredentialRequired],
)
async def list_schedules(page: CursorPage) -> Page[Schedule]:
    """Schedules owned by the caller's organization."""
    return Page(items=[_sample_schedule()], next_cursor=None)


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create a schedule",
    responses=problem_responses(401, 403, 404, 422),
    dependencies=[CredentialRequired],
)
async def create_schedule(body: ScheduleCreate) -> Schedule:
    """Create a recurring scan against a currently eligible asset."""
    return _sample_schedule()


@router.get(
    "/{schedule_id}",
    summary="Get a schedule",
    responses=problem_responses(401, 404),
    dependencies=[CredentialRequired],
)
async def get_schedule(schedule_id: ResourceId) -> Schedule:
    """One schedule, including its next fire time."""
    return _sample_schedule()


@router.patch(
    "/{schedule_id}",
    summary="Update a schedule",
    responses=problem_responses(401, 404, 422),
    dependencies=[CredentialRequired],
)
async def update_schedule(schedule_id: ResourceId, body: ScheduleUpdate) -> Schedule:
    """Change recurrence, modules, or enablement."""
    return _sample_schedule()


@router.delete(
    "/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a schedule",
    responses=problem_responses(401, 404),
    dependencies=[CredentialRequired],
)
async def delete_schedule(schedule_id: ResourceId) -> Response:
    """Remove a schedule. Scans it already produced are unaffected."""
    return Response(status_code=status.HTTP_204_NO_CONTENT)
