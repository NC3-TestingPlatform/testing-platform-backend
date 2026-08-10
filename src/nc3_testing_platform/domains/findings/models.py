"""SQLAlchemy model for findings (§8.2)."""

import uuid
from typing import Any

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import FINDING_SEVERITY, FINDING_STATUS, Base, uuid_pk


class Finding(Base):
    """One diagnostic outcome on one scan result (§8.2).

    `status` persists the derived historical comparison with the result
    projection; regression matching uses the stable `check_id` and, where one
    rule yields several findings, the normalized `affected_resource`.
    """

    __tablename__ = "finding"
    __table_args__ = (sa.Index("ix_finding_result_check", "scan_result_id", "check_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    scan_result_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("scan_result.id", ondelete="CASCADE")
    )
    # Stable diagnostic-rule identifier; changing one is a breaking result-schema change.
    check_id: Mapped[str]
    severity: Mapped[enums.FindingSeverity] = mapped_column(FINDING_SEVERITY)
    status: Mapped[enums.FindingStatus] = mapped_column(FINDING_STATUS)
    title: Mapped[str]
    description: Mapped[str]
    affected_resource: Mapped[str | None]
    remediation: Mapped[str | None]
    evidence: Mapped[dict[str, Any] | None]
    external_references: Mapped[list[Any]] = mapped_column(
        server_default=sa.text("'[]'::jsonb")
    )
