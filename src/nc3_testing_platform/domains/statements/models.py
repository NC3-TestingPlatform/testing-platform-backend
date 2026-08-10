"""SQLAlchemy models for statements and their responses (§5).

`statement_response` rows are immutable receipts: correction means a new
Statement version and a new response. Revoking application UPDATE/DELETE
permission on the table is part of the migration work (issue #6), not the
model. `envelope_id` is copied from the user-scope `key_envelope.id` at write
time and deliberately carries no foreign key (§3.5): erasure must sever the
link without touching the receipt.
"""

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import STATEMENT_RESPONSE_KIND, Base, uuid_pk


class Statement(Base):
    """Versioned text requiring an explicit acceptance or attestation (§5.1)."""

    __tablename__ = "statement"
    __table_args__ = (sa.UniqueConstraint("statement_key", "version"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    statement_key: Mapped[str]
    version: Mapped[str]
    response_kind: Mapped[enums.StatementResponseKind] = mapped_column(
        STATEMENT_RESPONSE_KIND
    )
    # Null for account-level responses; `scan_job` for per-launch responses.
    required_context_type: Mapped[str | None]
    content_hash: Mapped[str]
    content_uri: Mapped[str | None]
    effective_at: Mapped[datetime]
    retired_at: Mapped[datetime | None]


class StatementResponse(Base):
    """Immutable response receipt, optionally bound to a model context (§5.2)."""

    __tablename__ = "statement_response"
    __table_args__ = (
        # §14: a context is named and bound together.
        sa.CheckConstraint(
            "(context_type IS NULL) = (context_id IS NULL)",
            name="context_named_and_bound",
        ),
        # §14: the two response-uniqueness rules of §5.2 — one account-level
        # response per statement and envelope, one contextual response per
        # statement and context.
        sa.Index(
            "uq_statement_response_account_level",
            "statement_id",
            "envelope_id",
            unique=True,
            postgresql_where=sa.text("context_type IS NULL"),
        ),
        sa.Index(
            "uq_statement_response_contextual",
            "statement_id",
            "context_type",
            "context_id",
            unique=True,
            postgresql_where=sa.text("context_type IS NOT NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id")
    )
    statement_id: Mapped[uuid.UUID] = mapped_column(sa.ForeignKey("statement.id"))
    # Opaque; never encodes a user identifier, and no foreign key is retained.
    envelope_id: Mapped[uuid.UUID]
    context_type: Mapped[str | None]
    context_id: Mapped[uuid.UUID | None]
    responded_at: Mapped[datetime]
    # Encrypted actor identity, IP address, user agent, and response evidence.
    # Encryption itself is application-owned and out of scope here.
    response_evidence_encrypted: Mapped[bytes]
    # Per-response DEK wrapped by the user-scope KEK.
    wrapped_dek: Mapped[bytes]
    encryption_metadata: Mapped[dict[str, Any]]
