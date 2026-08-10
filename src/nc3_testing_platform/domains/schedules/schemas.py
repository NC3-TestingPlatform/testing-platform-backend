"""Recurring scans, shared across an organization.

Recurrence is an RFC 5545 rule plus an IANA timezone, not a frequency enum with a
weekday and day-of-month. This handles patterns an enum cannot express (last
weekday of a month, every second Tuesday) and preserves local run times across DST
boundaries — a 02:00, a run stays at 02:00 local time.

A schedule creates ScanJob rows and stores no results of its own.
"""

from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil.rrule import rrulestr
from pydantic import BaseModel, Field, field_validator

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


def _valid_recurrence_rule(value: str | None) -> str | None:
    """Reject anything the RFC 5545 grammar cannot parse, at the boundary.

    Accepting free text here would store rules the scheduler discovers to be
    garbage only when it tries to compute the next run.
    """
    if value is None:
        return None
    try:
        rrulestr(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"Not a valid RFC 5545 recurrence rule: {exc}") from exc
    return value


def _valid_timezone(value: str | None) -> str | None:
    """Reject timezone names absent from the IANA database."""
    if value is None:
        return None
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ValueError(f"Not an IANA timezone identifier: {value!r}") from exc
    return value


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

    _rrule_parses = field_validator("recurrence_rule")(_valid_recurrence_rule)
    _timezone_exists = field_validator("timezone")(_valid_timezone)


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

    _rrule_parses = field_validator("recurrence_rule")(_valid_recurrence_rule)
    _timezone_exists = field_validator("timezone")(_valid_timezone)
