"""Report generation and provenance listing."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Response, status

from nc3_testing_platform.core.enums import (
    ReportFormat,
    ReportLanguage,
    ReportTier,
    TechnicalReportView,
)
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.security import CredentialRequired
from nc3_testing_platform.domains.reports.schemas import Report, ReportRequest
from nc3_testing_platform.domains.scans.examples import JOB_ID, ORGANIZATION_ID, USER_ID

router = APIRouter(
    prefix="/reports",
    tags=["reports"],
)

_REPORT_ID = UUID("019ee1a5-0011-7a22-8b33-4c44d5e66f77")

# The rendered document comes back in the response body, so the operation answers
# with whichever media type the requested `format` names.
_ARTIFACT_MEDIA_TYPES = {
    ReportFormat.PDF: "application/pdf",
    ReportFormat.DOCX: (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ),
    ReportFormat.JSON: "application/json",
}

# Smallest body that is recognizable as the declared media type. A client sniffing
# the response, or a mock consumer asserting on it, must not be handed PDF bytes
# labelled as DOCX.
#
# The report's actual content is deferred to v4.1: it is assembled from scan
# results, whose shapes belong to the scan modules and do not exist yet
# (`[RFD 1, gap 2]`). Only the format-to-media-type mapping is in v4.0 scope.
_ARTIFACT_STUBS = {
    ReportFormat.PDF: b"%PDF-1.7\n%%EOF\n",
    # DOCX is an OPC package, so a DOCX body begins with the ZIP local-file header.
    ReportFormat.DOCX: b"PK\x03\x04",
    ReportFormat.JSON: b'{"report": "Content is deferred to v4.1."}\n',
}


def _sample_report() -> Report:
    return Report(
        id=_REPORT_ID,
        organization_id=ORGANIZATION_ID,
        tier=ReportTier.TECHNICAL,
        technical_view=TechnicalReportView.FULL,
        format=ReportFormat.PDF,
        language=ReportLanguage.EN,
        source_scan_job_id=JOB_ID,
        generated_by_user_id=USER_ID,
        generated_at=datetime(2026, 7, 31, 9, 5, tzinfo=UTC),
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Generate a report",
    response_class=Response,
    responses={
        201: {
            "description": (
                "The rendered document, in the requested format."
                "To obtain it again, submit another request while the source scan "
                "is still retained."
            ),
            "content": {
                media_type: {"schema": {"type": "string", "format": "binary"}}
                if media_type != "application/json"
                else {"schema": {"type": "object"}}
                for media_type in _ARTIFACT_MEDIA_TYPES.values()
            },
        },
        **problem_responses(401, 404, 409, 422),
    },
    dependencies=[CredentialRequired],
)
async def generate_report(body: ReportRequest) -> Response:
    """Render a report synchronously from one retained scan source.

    Answers `409` once the source has been purged: the provenance row may still
    exist, but the data it was drawn from no longer does.

    The body is a placeholder of the right type, not a real report. Report content
    is assembled from scan results, and those shapes are owned by the scan modules,
    which do not exist yet.
    """
    return Response(
        content=_ARTIFACT_STUBS[body.format],
        media_type=_ARTIFACT_MEDIA_TYPES[body.format],
        status_code=status.HTTP_201_CREATED,
    )


@router.get(
    "",
    summary="List generated reports",
    responses=problem_responses(401),
    dependencies=[CredentialRequired],
)
async def list_reports(page: CursorPage) -> Page[Report]:
    """Provenance metadata for reports this organization has generated.

    Metadata only. No entry here can be turned back into a document; that requires
    generating a new one from a source that is still retained.
    """
    return Page(items=[_sample_report()], next_cursor=None)
