"""Request and response shapes of the auth operations (B3 / US #79).

Passwords travel as `SecretStr` so they can never leak through a repr, a log
line, or a validation error echo. The registration body carries the statement
answers inline — consent versioning is part of the registration act
(Non-functional v0.11), not a follow-up call — reusing the exact submission
shape of `POST /statement-responses` so both paths record identical receipts.
"""

from pydantic import BaseModel, EmailStr, Field, SecretStr

from nc3_testing_platform.core.enums import OrganizationRole
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp
from nc3_testing_platform.domains.statements.schemas import (
    StatementResponseSubmission,
)

# Bounds shared by every password field: 12 as the local-account floor
# (password is the only factor until B4 lands MFA), 128 well under argon2's
# practical limits while still refusing megabyte bodies.
_PASSWORD_FIELD = Field(min_length=12, max_length=128)


class RegistrationSubmission(BaseModel):
    """Lean registration: email, password, optional display name, consent."""

    email: EmailStr
    password: SecretStr = _PASSWORD_FIELD
    display_name: str | None = Field(default=None, max_length=200)
    statement_responses: list[StatementResponseSubmission] = Field(
        description=(
            "Answers to every active account-level acceptance statement "
            "(`GET /statements`), each named by key and exact version. "
            "Registration is refused while any is missing."
        ),
    )


class RegisteredUser(BaseSchema):
    """The provisioned account: the registrant administers a workspace org.

    Per IDR-016 the workspace organization is created at registration with
    the registrant as `organization_admin`; the first successful DNS
    verification later promotes and names it.
    """

    user_id: ResourceId
    organization_id: ResourceId
    email: EmailStr
    display_name: str | None = None
    organization_role: OrganizationRole


class LoginSubmission(BaseModel):
    """Password login for a platform-local account."""

    email: EmailStr
    password: SecretStr = _PASSWORD_FIELD


class SessionInfo(BaseSchema):
    """The authenticated session and its server-side expiry horizon.

    `idle_expires_at` moves with activity; `absolute_expires_at` never does.
    Whichever passes first ends the session (Non-functional v0.11).
    """

    user_id: ResourceId
    organization_id: ResourceId
    email: EmailStr
    display_name: str | None = None
    organization_role: OrganizationRole
    session_created_at: Timestamp
    last_seen_at: Timestamp
    idle_expires_at: Timestamp
    absolute_expires_at: Timestamp


class PasswordChangeSubmission(BaseModel):
    """Authenticated password change; requires the current password."""

    current_password: SecretStr = _PASSWORD_FIELD
    new_password: SecretStr = _PASSWORD_FIELD
