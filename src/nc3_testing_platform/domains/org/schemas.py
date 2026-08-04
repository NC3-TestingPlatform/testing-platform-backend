"""Organization membership and invitations.

Membership is created by exactly one route: accepting an invitation. There is no
operation that adds a member directly, so the email-match check on acceptance
cannot be bypassed.

Only the invitation token's hash is stored. The plaintext exists in the emailed
link and nowhere else, so a database read cannot yield a usable invitation.

A registered user belongs to exactly one organization, so leaving is not modeled.
A member who should lose access is disabled; a member who should be forgotten is
erased, which is a separate workflow with its own thirty-day guarantee.
"""

from pydantic import BaseModel, EmailStr, Field

from nc3_testing_platform.core.enums import OrganizationRole
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp


class Member(BaseSchema):
    """One user's membership of the organization."""

    user_id: ResourceId
    email: EmailStr
    display_name: str | None = None
    organization_role: OrganizationRole
    disabled_at: Timestamp | None = Field(
        default=None,
        description="Set while the member is disabled. A disabled user cannot authenticate.",
    )
    created_at: Timestamp


class MemberRoleUpdate(BaseModel):
    """Change a member's role.

    Rejected when it would remove the last enabled administrator — an organization
    that cannot administer itself has no route back without operator intervention.
    """

    organization_role: OrganizationRole


class InvitationCreate(BaseModel):
    """Invite one email address to join at one role."""

    email: EmailStr
    organization_role: OrganizationRole = OrganizationRole.MEMBER


class Invitation(BaseSchema):
    """An invitation's lifecycle, as the inviting organization sees it.

    The token never appears here in any form.
    """

    id: ResourceId
    organization_id: ResourceId
    email: EmailStr
    organization_role: OrganizationRole
    invited_by_user_id: ResourceId | None = None
    expires_at: Timestamp
    accepted_by_user_id: ResourceId | None = None
    accepted_at: Timestamp | None = None
    revoked_at: Timestamp | None = Field(
        default=None,
        description="Set on revocation. The row is kept, so the attempt stays visible.",
    )
    created_at: Timestamp


class InvitationPreview(BaseSchema):
    """What an invitee can see before accepting.

    Deliberately thin. Anyone holding the link can read this, so it carries the
    organization's name and nothing that would leak its membership or activity.
    """

    organization_name: str
    organization_role: OrganizationRole
    email: EmailStr = Field(
        description="The invited address. Acceptance requires a verified match."
    )
    expires_at: Timestamp
