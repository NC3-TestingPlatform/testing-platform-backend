"""SQLAlchemy models for assets, domain verification, and feeds (§4, §10.2).

Ownership proof is held in two independent tables: `domain_verification` is a
proof that exists, `domain_verification_challenge` a challenge in progress — so
a domain keeps proven coverage while it re-proves or widens it.

Every foreign key pointing at `asset` restricts (§4.1): an asset referenced by
scan history or discovered children answers 409, never a cascade.
"""

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import (
    ASSET_ORIGIN,
    ASSET_TYPE,
    DNS_RECORD_TYPE,
    FEED_FORMAT,
    VERIFICATION_SCOPE,
    Base,
    uuid_pk,
)


class Asset(Base):
    """Organization-owned monitored target; v4.0 assets are domains (§4.1)."""

    __tablename__ = "asset"
    __table_args__ = (
        sa.UniqueConstraint("organization_id", "asset_type", "value"),
        # §14: only discovery produces child assets.
        sa.CheckConstraint(
            "parent_asset_id IS NULL OR origin = 'discovered'",
            name="child_implies_discovered",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id")
    )
    asset_type: Mapped[enums.AssetType] = mapped_column(ASSET_TYPE)
    # Lowercase IDNA A-label domain without a trailing dot, canonicalized at the
    # API boundary.
    value: Mapped[str]
    origin: Mapped[enums.AssetOrigin] = mapped_column(ASSET_ORIGIN)
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT")
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL")
    )
    regression_alerts_enabled: Mapped[bool] = mapped_column(server_default=sa.false())
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )


class DomainVerification(Base):
    """The current ownership proof; presence is the status (§4.2).

    The asset_type = domain rule is cross-table and stays application-enforced
    (§14 closing note).
    """

    __tablename__ = "domain_verification"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id")
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), unique=True
    )
    verified_scope: Mapped[enums.VerificationScope] = mapped_column(
        VERIFICATION_SCOPE
    )
    verified_at: Mapped[datetime]


class DomainVerificationChallenge(Base):
    """A challenge in progress; at most one per asset (§4.3)."""

    __tablename__ = "domain_verification_challenge"
    __table_args__ = (
        # §14: a failure code always follows a recorded check.
        sa.CheckConstraint(
            "failure_code IS NULL OR last_recheck_at IS NOT NULL",
            name="failure_follows_recheck",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id")
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), unique=True
    )
    requested_scope: Mapped[enums.VerificationScope] = mapped_column(
        VERIFICATION_SCOPE
    )
    record_type: Mapped[enums.DnsRecordType] = mapped_column(DNS_RECORD_TYPE)
    record_name: Mapped[str]
    verification_token: Mapped[str]
    token_expires_at: Mapped[datetime]
    requested_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL")
    )
    requested_at: Mapped[datetime]
    last_recheck_at: Mapped[datetime | None]
    failure_code: Mapped[str | None]


class AssetFeed(Base):
    """Per-asset RSS or Atom feed configuration with a revocable token (§10.2)."""

    __tablename__ = "asset_feed"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id")
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT")
    )
    format: Mapped[enums.FeedFormat] = mapped_column(FEED_FORMAT)
    token_hash: Mapped[str]
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL")
    )
    revoked_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
