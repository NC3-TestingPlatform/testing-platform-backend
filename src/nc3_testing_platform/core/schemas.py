"""Shared base model and value objects used by more than one domain.

Wire field names match the database column names exactly (`organization_id`, not `org_id`), so the database, the
contract, and generated clients share one vocabulary.
"""

from datetime import UTC, datetime
from typing import Annotated

import idna
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


def _parse_domain_name(value: str) -> str:
    """Canonicalizes a domain to lowercase IDNA A-label form without a trailing dot.

    Accepts Unicode or ASCII input.
    Raises `ValueError` for anything that does not parse as a domain.
    """
    try:
        canonical = idna.encode(value, uts46=True).decode("ascii").removesuffix(".")
    except idna.IDNAError as error:
        raise ValueError(f"Not a valid domain name: {error}") from error
    if "." not in canonical:
        raise ValueError("A domain name needs at least two labels.")
    if len(canonical) > 253:
        raise ValueError("A domain name is at most 253 characters in A-label form.")
    return canonical


# A domain in canonical form: lowercase IDNA A-labels, no trailing dot. Parsing
# happens at the boundary, so `asset.value` and the `target_domain` columns never
# hold a non-canonical spelling that would defeat their uniqueness rules.
DomainName = Annotated[str, AfterValidator(_parse_domain_name)]


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
