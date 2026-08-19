"""Request and response shapes of the auth operations (B3 / US #79).

Passwords travel as `SecretStr` so they can never leak through a repr, a log
line, or a validation error echo. The registration body carries the statement
answers inline — consent versioning is part of the registration act
(Non-functional v0.11), not a follow-up call — reusing the exact submission
shape of `POST /statement-responses` so both paths record identical receipts.
"""

from pydantic import BaseModel, EmailStr, Field, SecretStr, model_validator

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

    While `mfa_required` is true the session is pending its second factor:
    only `POST /auth/mfa/verify`, `POST /auth/logout`, and this view accept
    it, and the profile fields (`display_name`, `organization_role`) are
    withheld — a correct password alone reveals nothing it did not prove.
    """

    user_id: ResourceId
    organization_id: ResourceId
    email: EmailStr
    display_name: str | None = None
    organization_role: OrganizationRole | None = None
    session_created_at: Timestamp
    last_seen_at: Timestamp
    idle_expires_at: Timestamp
    absolute_expires_at: Timestamp
    mfa_enrolled: bool = False
    mfa_required: bool = False
    mfa_verified_at: Timestamp | None = None
    mfa_assurance_expires_at: Timestamp | None = None
    recovery_codes_remaining: int | None = None


class PasswordChangeSubmission(BaseModel):
    """Authenticated password change; requires the current password."""

    current_password: SecretStr = _PASSWORD_FIELD
    new_password: SecretStr = _PASSWORD_FIELD


# Six decimal digits (RFC 6238); recovery codes are 16 base32 characters,
# with separators and case forgiven at the boundary (`totp.py`).
_TOTP_CODE_PATTERN = r"^[0-9]{6}$"


class MfaEnrollSubmission(BaseModel):
    """Start TOTP enrollment; re-authenticates with the current password.

    The password gate keeps a stolen session cookie from planting an
    attacker-controlled factor (US #80 plan rev 2).
    """

    password: SecretStr = _PASSWORD_FIELD


class MfaEnrollment(BaseSchema):
    """The TOTP provisioning material, shown exactly once."""

    secret_base32: str = Field(
        description="The seed for manual authenticator entry (base32)."
    )
    otpauth_uri: str = Field(
        description="The `otpauth://totp/...` URI behind the QR code."
    )


class MfaConfirmSubmission(BaseModel):
    """Prove possession of the enrolled authenticator."""

    totp_code: str = Field(pattern=_TOTP_CODE_PATTERN)


class RecoveryCodes(BaseSchema):
    """The full active recovery-code set, shown exactly once."""

    recovery_codes: list[str]


class MfaVerifySubmission(BaseModel):
    """Exactly one of the two second-factor code forms."""

    totp_code: str | None = Field(default=None, pattern=_TOTP_CODE_PATTERN)
    recovery_code: SecretStr | None = Field(
        default=None, min_length=16, max_length=24
    )

    @model_validator(mode="after")
    def _exactly_one_code(self) -> "MfaVerifySubmission":
        if (self.totp_code is None) == (self.recovery_code is None):
            raise ValueError(
                "Provide exactly one of totp_code or recovery_code."
            )
        return self


class MfaDisableSubmission(MfaVerifySubmission):
    """Disable MFA: the current password plus one valid code."""

    password: SecretStr = _PASSWORD_FIELD


class RecoveryCodesRegenerateSubmission(BaseModel):
    """Replace the recovery-code set; re-authenticates with the password."""

    password: SecretStr = _PASSWORD_FIELD
