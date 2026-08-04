"""Organization members and invitations.

Two routers: administrative operations under `/org`, and the invitee-facing pair
under `/invitations/{token}`, which is reached by someone who may not be a member
of anything yet.
"""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status

from nc3_testing_platform.core.enums import OrganizationRole
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import Authenticated
from nc3_testing_platform.domains.org.schemas import (
    Invitation,
    InvitationCreate,
    InvitationPreview,
    Member,
    MemberRoleUpdate,
)
from nc3_testing_platform.domains.scans.examples import ORGANIZATION_ID, USER_ID

router = APIRouter(prefix="/org", tags=["organization"])

# Invitee-facing. The preview is readable by anyone holding the link; acceptance
# still requires an authenticated caller whose verified email matches.
invitation_router = APIRouter(prefix="/invitations", tags=["organization"])

_INVITATION_ID = UUID("019ee1a7-0011-7a22-8b33-4c44d5e66f77")
_T = datetime(2026, 7, 28, 10, 0, tzinfo=UTC)
_EXPIRES = datetime(2026, 8, 11, 10, 0, tzinfo=UTC)


def _sample_member(disabled: bool = False) -> Member:
    return Member(
        user_id=USER_ID,
        email="analyst@example.lu",
        display_name="A. Analyst",
        organization_role=OrganizationRole.ORGANIZATION_ADMIN,
        disabled_at=_T if disabled else None,
        created_at=_T,
    )


def _sample_invitation() -> Invitation:
    return Invitation(
        id=_INVITATION_ID,
        organization_id=ORGANIZATION_ID,
        email="newcomer@example.lu",
        organization_role=OrganizationRole.MEMBER,
        invited_by_user_id=USER_ID,
        expires_at=_EXPIRES,
        created_at=_T,
    )


@router.get(
    "/members",
    summary="List members",
    responses=problem_responses(401, 403),
    dependencies=[Authenticated],
)
async def list_members(page: CursorPage) -> Page[Member]:
    """Members of the caller's organization."""
    return Page(items=[_sample_member()], next_cursor=None)


@router.patch(
    "/members/{user_id}",
    summary="Change a member's role",
    responses=problem_responses(401, 403, 404, 409, 422),
    dependencies=[Authenticated],
)
async def update_member_role(user_id: ResourceId, body: MemberRoleUpdate) -> Member:
    """Promote or demote a member.

    Answers `409` when the change would leave no enabled administrator.
    """
    return _sample_member()


@router.post(
    "/members/{user_id}/disable",
    summary="Disable a member",
    responses=problem_responses(401, 403, 404, 409),
    dependencies=[Authenticated],
)
async def disable_member(user_id: ResourceId) -> Member:
    """Revoke a member's access without removing them or their attribution.

    There is no removal operation: disabling ends access, and erasure — a separate
    workflow — removes the person.
    """
    return _sample_member(disabled=True)


@router.post(
    "/members/{user_id}/enable",
    summary="Re-enable a member",
    responses=problem_responses(401, 403, 404),
    dependencies=[Authenticated],
)
async def enable_member(user_id: ResourceId) -> Member:
    """Restore access to a disabled member."""
    return _sample_member()


@router.get(
    "/invitations",
    summary="List invitations",
    responses=problem_responses(401, 403),
    dependencies=[Authenticated],
)
async def list_invitations(page: CursorPage) -> Page[Invitation]:
    """Invitations issued by this organization, including spent and revoked ones."""
    return Page(items=[_sample_invitation()], next_cursor=None)


@router.post(
    "/invitations",
    status_code=status.HTTP_201_CREATED,
    summary="Invite someone to the organization",
    responses=problem_responses(401, 403, 409, 422),
    dependencies=[Authenticated],
)
async def create_invitation(body: InvitationCreate) -> Invitation:
    """Issue an invitation and email the link.

    Answers `409` when a live invitation already exists for the same address. There
    is no resend: revoke the outstanding one and issue another, so every link ever
    sent has its own auditable row.
    """
    return _sample_invitation()


@router.delete(
    "/invitations/{invitation_id}",
    summary="Revoke an invitation",
    responses=problem_responses(401, 403, 404, 409),
    dependencies=[Authenticated],
)
async def revoke_invitation(invitation_id: ResourceId) -> Invitation:
    """Invalidate the outstanding link.

    The row survives with `revoked_at` set, which is why this returns the invitation
    rather than `204` — revocation changes state, it does not erase it.
    """
    invitation = _sample_invitation()
    invitation.revoked_at = _T
    return invitation


@invitation_router.get(
    "/{token}",
    summary="Preview an invitation",
    responses=problem_responses(404, 410),
)
async def preview_invitation(token: str) -> InvitationPreview:
    """What the invitee sees before deciding.

    Unauthenticated, because the recipient may have no account yet. Answers `410`
    for a spent, revoked, or expired token so the UI can say which.
    """
    return InvitationPreview(
        organization_name="Example Luxembourg S.A.",
        organization_role=OrganizationRole.MEMBER,
        email="newcomer@example.lu",
        expires_at=_EXPIRES,
    )


@invitation_router.post(
    "/{token}/acceptance",
    status_code=status.HTTP_201_CREATED,
    summary="Accept an invitation",
    responses=problem_responses(401, 403, 404, 409, 410),
    dependencies=[Authenticated],
)
async def accept_invitation(token: str) -> Member:
    """Join the organization.

    Atomic, and gated on three things at once: the token is live, the caller's
    verified email matches the invited address, and the caller does not already
    belong to another organization. Failing any of them changes nothing.
    """
    return _sample_member()
