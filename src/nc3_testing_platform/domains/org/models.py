"""SQLAlchemy models for organizations and users (data-model §3).

`key_envelope` holds the wrapped scope KEKs of the three-scope encryption
design (IDR-011/IDR-017). Only the table is modeled here: key wrapping and
crypto-shredding are application-owned and arrive in a later phase.
"""

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import KEY_SCOPE, ORGANIZATION_ROLE, Base, uuid_pk


class Organization(Base):
    """Tenant boundary (§3.1)."""

    __tablename__ = "organization"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str]
    settings: Mapped[dict[str, Any]] = mapped_column(
        server_default=sa.text("'{}'::jsonb")
    )
    white_label_config: Mapped[dict[str, Any]] = mapped_column(
        server_default=sa.text("'{}'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )


class AppUser(Base):
    """The single local user entity (§3.2).

    Since B3 (US #79) the platform is the identity provider: this row is the
    identity projection (`identity_subject` keys issuer + subject; local
    accounts use `local:<user id>`), while credentials and sessions live in
    the user-private tables of `domains/auth` — never here, because this row
    is visible org-wide for member management (IDR-012).
    """

    __tablename__ = "app_user"
    __table_args__ = (
        # B3: one account per email, case-insensitive. The application
        # lowercases at the boundary; the expression index enforces it at
        # the root and backs the `auth_login_lookup` definer function.
        sa.Index("uq_app_user_email_lower", sa.text("lower(email)"), unique=True),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    identity_subject: Mapped[str] = mapped_column(unique=True)
    email: Mapped[str]
    display_name: Mapped[str | None]
    email_notifications_enabled: Mapped[bool] = mapped_column(
        server_default=sa.false()
    )
    organization_role: Mapped[enums.OrganizationRole] = mapped_column(
        ORGANIZATION_ROLE
    )
    disabled_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )


class KeyEnvelope(Base):
    """One wrapped KEK per organization, per user, and per guest scan job (§3.3).

    Deleting a row crypto-shreds everything retained under its scope, so erasure
    is a delete here plus application logic — never an update to wrapped data.
    """

    __tablename__ = "key_envelope"
    __table_args__ = (
        # §14: the owner reference exists exactly on the scope that names it,
        # and organization context exists on all but guest-job envelopes.
        sa.CheckConstraint(
            "(scope = 'user') = (user_id IS NOT NULL)", name="user_scope_has_user"
        ),
        sa.CheckConstraint(
            "(scope = 'scan_job') = (scan_job_id IS NOT NULL)",
            name="scan_job_scope_has_job",
        ),
        sa.CheckConstraint(
            "(scope = 'scan_job') = (organization_id IS NULL)",
            name="guest_scope_lacks_org",
        ),
        # §14: one organization envelope per organization; the user and scan-job
        # columns carry plain unique constraints instead.
        sa.Index(
            "uq_key_envelope_organization_scope",
            "organization_id",
            unique=True,
            postgresql_where=sa.text("scope = 'organization'"),
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    scope: Mapped[enums.KeyScope] = mapped_column(KEY_SCOPE)
    # The partial unique index covers only organization-scope rows; cascade
    # maintenance and user-envelope lookups by organization need the full index.
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id", ondelete="CASCADE"), index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="CASCADE"), unique=True
    )
    scan_job_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("scan_job.id", ondelete="CASCADE"), unique=True
    )
    wrapped_kek: Mapped[bytes]
    wrapping_nonce: Mapped[bytes]
    wrapping_algorithm: Mapped[str]
    master_key_version: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )


class OrganizationInvitation(Base):
    """Pending invitation to join one organization with one role (§3.4)."""

    __tablename__ = "organization_invitation"
    __table_args__ = (
        # §14: an acceptance actor implies an acceptance time; erasure may later
        # null the actor, so the implication is one-way.
        sa.CheckConstraint(
            "accepted_by_user_id IS NULL OR accepted_at IS NOT NULL",
            name="acceptance_actor_implies_time",
        ),
        # §14: one live invitation per organization and normalized address.
        # Expiry cannot sit in an index predicate, so replacing an expired
        # invitation first sets revoked_at.
        sa.Index(
            "uq_organization_invitation_live_email",
            "organization_id",
            sa.text("lower(email)"),
            unique=True,
            postgresql_where=sa.text("accepted_at IS NULL AND revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    email: Mapped[str]
    organization_role: Mapped[enums.OrganizationRole] = mapped_column(
        ORGANIZATION_ROLE
    )
    token_hash: Mapped[str] = mapped_column(unique=True)
    invited_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    expires_at: Mapped[datetime]
    accepted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    accepted_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
