"""SQLAlchemy models for notifications and the organization webhook (§11)."""

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core.db import Base, uuid_pk


class Notification(Base):
    """User-owned in-app inbox item (§11.1).

    Dismissing one hard-deletes the row; the whole inbox dies with its user.
    The type vocabulary and recipient selection are code-owned.
    """

    __tablename__ = "notification"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="CASCADE"), index=True
    )
    # Stable namespaced notification type.
    type: Mapped[str]
    # Version of this type's `data` shape.
    schema_version: Mapped[str]
    data: Mapped[dict[str, Any]] = mapped_column(server_default=sa.text("'{}'::jsonb"))
    read_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())


class OrganizationWebhook(Base):
    """Zero-or-one integration endpoint per organization (§11.2).

    Endpoint and secret are stored encrypted under a DEK wrapped by the
    organization-scope KEK (§3.3); deleting the organization's `key_envelope`
    crypto-shreds both. The crypto itself is application-owned, not modeled.
    """

    __tablename__ = "organization_webhook"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id"), unique=True
    )
    endpoint_url_encrypted: Mapped[bytes]
    signing_secret_encrypted: Mapped[bytes]
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )
