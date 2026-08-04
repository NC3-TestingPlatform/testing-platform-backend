"""User inbox, account preferences, and the organization webhook.

Notifications are deliberately minimal: one row per user per event, owned by that
user alone. No organization scope, no shared read state, no parent event resource,
no per-type preferences. Two people in the same organization each get their own
row, and one reading it does not mark it read for the other.

In-app delivery has no opt-out. Email delivery has exactly one switch, on the
account, which is why there is no notification-settings resource to configure.
"""

from typing import Any

from pydantic import AnyHttpUrl, BaseModel, EmailStr, Field

from nc3_testing_platform.core.enums import OrganizationRole
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp


class Notification(BaseSchema):
    """One inbox item belonging to one user."""

    id: ResourceId
    type: str = Field(
        description=(
            "Namespaced notification type. v4.0 covers verification completion, "
            "regressions, scan completion and failure, retention warnings, and "
            "token expiry. The vocabulary is code-owned and extends freely."
        ),
        examples=["scan.completed"],
    )
    schema_version: str = Field(
        description="Version of this type's `data` shape.",
        examples=["1.0"],
    )
    # `data` has no fixed schema; contents are per-type and code-owned.
    data: dict[str, Any] = Field(
        default_factory=dict, description="Type-specific payload."
    )
    read_at: Timestamp | None = Field(
        default=None, description="Null while unread. There is no separate flag."
    )
    created_at: Timestamp


class Account(BaseSchema):
    """The caller's `app_user` projection.

    Read-only. Identity, credentials, display name, and email are owned by the identity provider
    and edited there; they arrive here through claim updates. The one field this
    platform owns is the email-notification preference.
    """

    id: ResourceId
    email: EmailStr
    display_name: str | None = None
    organization_id: ResourceId
    organization_role: OrganizationRole = Field(
        description=(
            "Role within the organization. Platform-administrator status is a "
            "separate identity-provider claim and never appears here."
        )
    )
    email_notifications_enabled: bool


class AccountUpdate(BaseModel):
    """The only account field this API can change."""

    email_notifications_enabled: bool


class OrganizationWebhook(BaseSchema):
    """The organization's single SIEM integration endpoint.

    The signing secret is never returned. It is set once on write and thereafter
    only ever used to sign outgoing payloads.
    """

    id: ResourceId
    organization_id: ResourceId
    endpoint_url: AnyHttpUrl
    created_by_user_id: ResourceId | None = None
    created_at: Timestamp
    updated_at: Timestamp


class OrganizationWebhookUpsert(BaseModel):
    """Create or replace the webhook configuration.

    A `PUT` rather than a `POST`, because an organization has zero or one of these
    """

    endpoint_url: AnyHttpUrl
    signing_secret: str = Field(
        min_length=32,
        description=(
            "Shared secret used to sign delivered payloads. Stored encrypted and "
            "never returned. The payload's own `schema_version` belongs to the "
            "signed contract, not to this configuration."
        ),
    )
