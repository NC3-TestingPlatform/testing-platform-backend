"""Shared base model and value objects used by more than one domain.

Wire field names match the database column names exactly (`organization_id`, not `org_id`), so the database, the
contract, and generated clients share one vocabulary.
"""

from datetime import UTC, datetime
from typing import Annotated

from pydantic import (
    UUID7,
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
)

# Wire values are UUIDv7, which is time-sortable.
ResourceId = UUID7


# Every timestamp in the contract is a UTC instant serialized as ISO-8601.
def _normalize_to_utc(value: datetime) -> datetime:
    return value.astimezone(UTC)

Timestamp = Annotated[
    AwareDatetime,
    AfterValidator(_normalize_to_utc),
]


class BaseSchema(BaseModel):
    """Base for response models."""

    model_config = ConfigDict(from_attributes=True)


class SeverityCounts(BaseModel):
    """Findings counted by severity band.

    Stored as untyped JSONB in `scan_result.severity_counts`, but the key set is fully determined by `finding_severity`, so the contract types it.
    Non-graded tests summarize outcomes through these counts instead of a letter grade; graded tests carry both.
    """

    critical: int = Field(default=0, ge=0, description="Findings in the critical band.")
    high: int = Field(default=0, ge=0, description="Findings in the high band.")
    medium: int = Field(default=0, ge=0, description="Findings in the medium band.")
    low: int = Field(default=0, ge=0, description="Findings in the low band.")
    info: int = Field(default=0, ge=0, description="Findings in the informational band.")
