"""SQLAlchemy model for schedules (§9.1)."""

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import SCAN_MODULE, Base, uuid_pk


class Schedule(Base):
    """Recurring scan configuration for one asset (§9.1).

    A Schedule creates ScanJob rows; it stores no results. The RRULE and the
    IANA timezone are validated at the API boundary (schemas.py) and stored
    separately, never merged into one string.
    """

    __tablename__ = "schedule"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), index=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    modules: Mapped[list[enums.ScanModule]] = mapped_column(ARRAY(SCAN_MODULE))
    module_configuration: Mapped[dict[str, Any]] = mapped_column(
        server_default=sa.text("'{}'::jsonb")
    )
    # RFC 5545 RRULE.
    recurrence_rule: Mapped[str]
    # IANA timezone name.
    timezone: Mapped[str]
    enabled: Mapped[bool] = mapped_column(server_default=sa.true())
    # Indexed for the scheduler's due-run poll.
    next_run_at: Mapped[datetime | None] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )
