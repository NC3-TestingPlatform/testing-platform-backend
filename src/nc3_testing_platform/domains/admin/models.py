"""SQLAlchemy model for the audit log (§12).

Rows are append-only; revoking application UPDATE/DELETE permission is part of
the migration work (issue #6). User identity lives only inside
`payload_encrypted`, keyed through the opaque `envelope_id` — no foreign key,
so deleting the user-scope `key_envelope` blinds the payload without touching
the row. The 24-month `retention_until` default is derived from `occurred_at`
by the application at write time; PostgreSQL column defaults cannot reference
another column.
"""

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core.db import Base, uuid_pk


class AuditEvent(Base):
    """One hash-chained audit event (§12.1)."""

    __tablename__ = "audit_event"
    __table_args__ = (
        sa.UniqueConstraint("chain_id", "sequence_number"),
        # §14: the encrypted-payload column group is all-or-none.
        sa.CheckConstraint(
            "num_nonnulls(payload_encrypted, wrapped_dek, envelope_id, "
            "encryption_metadata) IN (0, 4)",
            name="payload_group_all_or_none",
        ),
        # §14: an event carries detail, an encrypted payload, or both.
        sa.CheckConstraint(
            "detail IS NOT NULL OR payload_encrypted IS NOT NULL",
            name="detail_or_payload",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    # Organization or platform chain identifier, never a user chain.
    chain_id: Mapped[str]
    sequence_number: Mapped[int] = mapped_column(sa.BigInteger)
    event_type: Mapped[str]
    # Must not identify an AppUser; a non-user model entity only.
    subject_type: Mapped[str | None]
    subject_id: Mapped[uuid.UUID | None]
    # Structured operational detail containing no PII.
    detail: Mapped[dict[str, Any] | None]
    payload_encrypted: Mapped[bytes | None]
    wrapped_dek: Mapped[bytes | None]
    # Copied from the user-scope key_envelope.id at write time; opaque, no FK.
    envelope_id: Mapped[uuid.UUID | None]
    encryption_metadata: Mapped[dict[str, Any] | None]
    occurred_at: Mapped[datetime]
    previous_hash: Mapped[str | None]
    entry_hash: Mapped[str]
    # Indexed for the retention sweep.
    retention_until: Mapped[datetime] = mapped_column(index=True)
