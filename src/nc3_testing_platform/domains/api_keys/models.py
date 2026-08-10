"""SQLAlchemy model for API keys (§9.2)."""

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import API_KEY_SCOPE, Base, uuid_pk


class ApiKey(Base):
    """A hashed API credential, user-owned or organization-owned (§9.2).

    The plaintext key is never stored. A null `owner_user_id` marks an
    organization key; user-owned keys die with their owner (erasure revokes and
    deletes them, the audit event keeps the record).
    """

    __tablename__ = "api_key"
    __table_args__ = (
        # §14: a reason can exist only on a revoked key. The reverse is not
        # required — a revocation may omit its reason.
        sa.CheckConstraint(
            "revocation_reason IS NULL OR revoked_at IS NOT NULL",
            name="reason_implies_revocation",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="CASCADE"), index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    name: Mapped[str]
    scope: Mapped[enums.ApiKeyScope] = mapped_column(API_KEY_SCOPE)
    key_prefix: Mapped[str] = mapped_column(unique=True)
    secret_hash: Mapped[str]
    expires_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    revocation_reason: Mapped[str | None]
    last_used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
