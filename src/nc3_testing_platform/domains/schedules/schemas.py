"""Recurring scans, shared across an organization.

Recurrence is an RFC 5545 rule plus an IANA timezone, not a frequency enum with a
weekday and day-of-month. This handles patterns an enum cannot express (last
weekday of a month, every second Tuesday) and preserves local run times across DST
boundaries — a 02:00, a run stays at 02:00 local time.

A schedule creates ScanJob rows and stores no results of its own.
"""

from typing import Any

from pydantic import BaseModel, Field

from nc3_testing_platform.core.enums import ScanModule
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp

_RECURRENCE_DESCRIPTION = (
    "RFC 5545 RRULE, without the `RRULE:` prefix, e.g. "
    "`FREQ=WEEKLY;BYDAY=MO;BYHOUR=2;BYMINUTE=0`."
)
_TIMEZONE_DESCRIPTION = (
    "IANA timezone the rule is evaluated in, e.g. `Europe/Luxembourg`. Stored "
    "separately from the rule so local run times survive daylight-saving changes."
)


class Schedule(BaseSchema):
    """A recurring scan of one asset."""

    id: ResourceId
    organization_id: ResourceId
    asset_id: ResourceId
    created_by_user_id: ResourceId | None = Field(
        default=None,
        description="Attribution only. The schedule is organization-owned.",
    )
    modules: list[ScanModule]
    module_configuration: dict[str, Any] = Field(default_factory=dict)
    recurrence_rule: str = Field(description=_RECURRENCE_DESCRIPTION)
    timezone: str = Field(description=_TIMEZONE_DESCRIPTION)
    enabled: bool = True
    next_run_at: Timestamp | None = Field(
        default=None,
        description="Next fire time. Null while disabled or once the rule is exhausted.",
    )
    created_at: Timestamp
    updated_at: Timestamp


class ScheduleCreate(BaseModel):
    """Create a recurring scan.

    The asset must already be eligible under the verification rules. Eligibility is
    rechecked at every execution rather than trusted from creation time, so a
    verification that lapses stops producing scans instead of quietly continuing.
    """

    asset_id: ResourceId
    modules: list[ScanModule] = Field(min_length=1)
    module_configuration: dict[str, Any] = Field(default_factory=dict)
    recurrence_rule: str = Field(description=_RECURRENCE_DESCRIPTION)
    timezone: str = Field(description=_TIMEZONE_DESCRIPTION)
    enabled: bool = True


class ScheduleUpdate(BaseModel):
    """Partial update. Omitted fields are left alone.

    `asset_id` is absent: repointing a schedule at another asset would attribute one
    asset's recurring history to a different one.
    """

    modules: list[ScanModule] | None = Field(default=None, min_length=1)
    module_configuration: dict[str, Any] | None = None
    recurrence_rule: str | None = Field(
        default=None, description=_RECURRENCE_DESCRIPTION
    )
    timezone: str | None = Field(default=None, description=_TIMEZONE_DESCRIPTION)
    enabled: bool | None = None
