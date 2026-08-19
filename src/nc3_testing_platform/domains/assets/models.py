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
from sqlalchemy.dialects import postgresql
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
        # The target of `domain_verification`'s composite foreign key. It exists
        # so a proof's denormalised `value` cannot drift from the asset it was
        # proven for: the database refuses the pair rather than trusting the
        # application to keep two copies in step.
        sa.UniqueConstraint("id", "value", name="uq_asset_id_value"),
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
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
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

    `value` is denormalised from the asset so the claim can be unique **platform
    wide**: a domain names at most one organization (IDR-016), and that is
    enforced by `uq_domain_verification_value` rather than by application checks,
    which could not see the conflicting row in the first place. PostgreSQL exempts
    unique-index and referential-integrity checks from row security, which is the
    only reason a global constraint works at all under FORCE RLS — see the
    migration for the consequence.
    """

    __tablename__ = "domain_verification"
    __table_args__ = (
        # Global, not per-organization: this *is* the claim adjudication.
        sa.UniqueConstraint("value", name="uq_domain_verification_value"),
        # Named explicitly, and it has to be. The convention in `core/db.py`
        # renders `fk_domain_verification_asset_id_asset` for any foreign key
        # whose first column is `asset_id` and whose target is `asset` — which is
        # already taken by the single-column key from the initial schema, and
        # `pg_constraint` is unique on (conrelid, conname), so the migration would
        # abort.
        sa.ForeignKeyConstraint(
            ["asset_id", "value"],
            ["asset.id", "asset.value"],
            name="fk_domain_verification_asset_value",
            ondelete="RESTRICT",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), unique=True
    )
    verified_scope: Mapped[enums.VerificationScope] = mapped_column(
        VERIFICATION_SCOPE
    )
    # The canonical domain the proof covers, denormalised from the asset and
    # pinned to it by the composite foreign key above.
    value: Mapped[str]
    verified_at: Mapped[datetime]
    # Who proved it. Attribution for a dispute, so it survives the user leaving.
    verified_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    # How the proof was established, for a dispute later. Written here and read by
    # nothing in v4.0: the v4.1 intrusive gate is the consumer (IDR-019).
    #
    # `dnssec_validated` is true only when the answer carrying the token was
    # DNSSEC-validated. It is never derived from the AD bit alone, because a
    # signed zone with no record returns AD over an authenticated *denial*.
    dnssec_validated: Mapped[bool] = mapped_column(server_default=sa.false())
    # Which resolvers answered, and how many of them carried the token. A dispute
    # needs to show how the proof was established, not just that it was.
    resolvers: Mapped[list[str]] = mapped_column(
        postgresql.ARRAY(sa.Text), server_default=sa.text("'{}'::text[]")
    )
    corroborating_answers: Mapped[int] = mapped_column(server_default=sa.text("0"))
    # Stamped by a later re-check. Nothing writes it in v4.0; it exists so v4.1's
    # staleness rule for the intrusive gate needs no second migration.
    last_reverified_at: Mapped[datetime | None]


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
        sa.ForeignKey("organization.id"), index=True
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
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    requested_at: Mapped[datetime]
    last_recheck_at: Mapped[datetime | None]
    failure_code: Mapped[str | None]


class AssetFeed(Base):
    """Per-asset RSS or Atom feed configuration with a revocable token (§10.2)."""

    __tablename__ = "asset_feed"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), index=True
    )
    format: Mapped[enums.FeedFormat] = mapped_column(FEED_FORMAT)
    # A feed request presents only the token, so this is the lookup column.
    token_hash: Mapped[str] = mapped_column(index=True)
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    revoked_at: Mapped[datetime | None]
    last_used_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
