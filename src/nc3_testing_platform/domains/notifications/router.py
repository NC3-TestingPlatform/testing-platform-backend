"""Inbox, account preference, and organization webhook operations."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Response, status
from pydantic import AnyHttpUrl

from nc3_testing_platform.core.enums import OrganizationRole
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import Authenticated
from nc3_testing_platform.domains.notifications.schemas import (
    Account,
    AccountUpdate,
    Notification,
    OrganizationWebhook,
    OrganizationWebhookUpsert,
)
from nc3_testing_platform.domains.scans.examples import JOB_ID, ORGANIZATION_ID, USER_ID

router = APIRouter(prefix="/notifications", tags=["notifications"])

# `PATCH /account` is grouped with notifications because the only preference it
# carries is the email opt-in; `GET /account` reads the same projection.
account_router = APIRouter(prefix="/account", tags=["account"])

_NOTIFICATION_ID = UUID("019ee1a6-0011-7a22-8b33-4c44d5e66f77")
_WEBHOOK_ID = UUID("019ee1a6-1122-7b33-9c44-5d55e6f77a88")
_T = datetime(2026, 7, 31, 9, 2, tzinfo=UTC)


def _sample_notification() -> Notification:
    return Notification(
        id=_NOTIFICATION_ID,
        type="scan.completed",
        schema_version="1.0",
        data={"scan_job_id": str(JOB_ID), "status": "partial"},
        created_at=_T,
    )


@router.get(
    "",
    summary="List notifications",
    responses=problem_responses(401),
    dependencies=[Authenticated],
)
async def list_notifications(page: CursorPage) -> Page[Notification]:
    """The caller's inbox, newest first."""
    return Page(items=[_sample_notification()], next_cursor=None)


@router.post(
    "/read-all",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Mark all as read",
    responses=problem_responses(401),
    dependencies=[Authenticated],
)
async def mark_all_read() -> Response:
    """Mark every unread notification belonging to the caller.

    Returns no body: the caller already knows the outcome, and re-sending the
    inbox here would duplicate `GET /notifications`.
    """
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/{notification_id}/read",
    summary="Mark one as read",
    responses=problem_responses(401, 404),
    dependencies=[Authenticated],
)
async def mark_read(notification_id: ResourceId) -> Notification:
    """Set `read_at` on one of the caller's notifications."""
    notification = _sample_notification()
    notification.read_at = _T
    return notification


@router.get(
    "/webhook",
    summary="Get the organization webhook",
    responses=problem_responses(401, 403, 404),
    dependencies=[Authenticated],
)
async def get_webhook() -> OrganizationWebhook:
    """The organization's SIEM endpoint. `404` when none is configured."""
    return _sample_webhook()


@router.put(
    "/webhook",
    summary="Create or replace the organization webhook",
    responses=problem_responses(401, 403, 422),
    dependencies=[Authenticated],
)
async def upsert_webhook(body: OrganizationWebhookUpsert) -> OrganizationWebhook:
    """Set the single webhook configuration for the organization."""
    return _sample_webhook()


@router.delete(
    "/webhook",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Disable the organization webhook",
    responses=problem_responses(401, 403, 404),
    dependencies=[Authenticated],
)
async def delete_webhook() -> Response:
    """Delete the configuration, which disables the integration.

    A `DELETE` rather than a revoke: nothing about the configuration needs to
    stay visible after it is switched off.
    """
    return Response(status_code=status.HTTP_204_NO_CONTENT)


def _sample_webhook() -> OrganizationWebhook:
    return OrganizationWebhook(
        id=_WEBHOOK_ID,
        organization_id=ORGANIZATION_ID,
        endpoint_url=AnyHttpUrl("https://siem.example.lu/ingest/nc3"),
        created_by_user_id=USER_ID,
        created_at=_T,
        updated_at=_T,
    )


@router.delete(
    "/{notification_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Dismiss a notification",
    responses=problem_responses(401, 404),
    dependencies=[Authenticated],
)
async def dismiss_notification(notification_id: ResourceId) -> Response:
    """Permanently remove the caller's row.

    Dismissal is deletion in v4.0 — there is no archived state, and no other user
    is affected because the row was never shared.
    """
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@account_router.get(
    "",
    summary="Get the current account",
    responses=problem_responses(401),
    dependencies=[Authenticated],
)
async def get_account() -> Account:
    """The caller's `app_user` projection: identity, organization, role, preference."""
    return Account(
        id=USER_ID,
        email="analyst@example.lu",
        display_name="A. Analyst",
        organization_id=ORGANIZATION_ID,
        organization_role=OrganizationRole.ORGANIZATION_ADMIN,
        email_notifications_enabled=True,
    )


@account_router.patch(
    "",
    summary="Update account preferences",
    responses=problem_responses(401, 422),
    dependencies=[Authenticated],
)
async def update_account(body: AccountUpdate) -> Account:
    """Change the email-notification opt-in.

    Profile fields are not editable here. They live in the identity provider and reach this
    projection through claim updates.
    """
    account = await get_account()
    account.email_notifications_enabled = body.email_notifications_enabled
    return account
