"""SQLAlchemy model for reports (§10.1)."""

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import (
    REPORT_FORMAT,
    REPORT_LANGUAGE,
    REPORT_TIER,
    TECHNICAL_REPORT_VIEW,
    Base,
    uuid_pk,
)


class Report(Base):
    """Generation metadata for one rendered report (§10.1).

    The source columns are provenance identifiers, deliberately without foreign
    keys: they outlive the purged scan data they point at. The rendered artifact
    itself is generated on demand and never stored.
    """

    __tablename__ = "report"
    __table_args__ = (
        # §14: exactly one source, and view depth on technical reports alone.
        sa.CheckConstraint(
            "num_nonnulls(source_scan_job_id, source_scan_task_id) = 1",
            name="one_source",
        ),
        sa.CheckConstraint(
            "tier = 'technical' OR technical_view IS NULL",
            name="view_is_technical_only",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id")
    )
    tier: Mapped[enums.ReportTier] = mapped_column(REPORT_TIER)
    technical_view: Mapped[enums.TechnicalReportView | None] = mapped_column(
        TECHNICAL_REPORT_VIEW
    )
    format: Mapped[enums.ReportFormat] = mapped_column(REPORT_FORMAT)
    language: Mapped[enums.ReportLanguage] = mapped_column(REPORT_LANGUAGE)
    source_scan_job_id: Mapped[uuid.UUID | None]
    source_scan_task_id: Mapped[uuid.UUID | None]
    generated_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL")
    )
    generated_at: Mapped[datetime]
