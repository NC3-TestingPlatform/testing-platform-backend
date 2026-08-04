"""Organization-wide finding reads.

Read-only. `new`, `regression`, `persistent`, and `resolved` are derived by
comparing a result against the asset's history, so there is no operation to set
one: a manual override would corrupt the next comparison.

The `Finding` model itself lives in the scans domain, because a finding belongs to
a scan result. This domain only adds the cross-asset views.
"""

from typing import Annotated

from fastapi import APIRouter, Query

from nc3_testing_platform.core.enums import FindingSeverity, FindingStatus
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import Authenticated
from nc3_testing_platform.domains.scans import examples
from nc3_testing_platform.domains.scans.schemas import Finding

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
)


@router.get(
    "",
    summary="List findings",
    responses=problem_responses(401),
    dependencies=[Authenticated],
)
async def list_findings(
    page: CursorPage,
    severity: Annotated[
        FindingSeverity | None, Query(description="Filter by severity band.")
    ] = None,
    status: Annotated[
        FindingStatus | None,
        Query(description="Filter by historical-comparison classification."),
    ] = None,
    asset_id: Annotated[
        ResourceId | None,
        Query(description="Restrict to findings raised against one asset."),
    ] = None,
    scan_job_id: Annotated[
        ResourceId | None,
        Query(description="Restrict to findings from one scan."),
    ] = None,
) -> Page[Finding]:
    """Findings across the caller's organization."""
    return Page(items=examples.sample_findings(), next_cursor=None)


@router.get(
    "/{finding_id}",
    summary="Get a finding",
    responses=problem_responses(401, 404),
    dependencies=[Authenticated],
)
async def get_finding(finding_id: ResourceId) -> Finding:
    """One finding in full, including its evidence."""
    return examples.sample_findings()[0]
