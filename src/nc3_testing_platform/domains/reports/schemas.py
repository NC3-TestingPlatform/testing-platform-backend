"""Report generation from a retained scan.

Only metadata persists. `POST /reports` renders synchronously and hands
back the document; the metadata records who generated what, from which
source, in which language.

The way to get the document again is to ask for it again, and that only
works while the source scan is still retained. Once `purge_at` passes, the
metadata row survives as evidence that a report once existed, and no further
copy can be produced from it.
"""

from pydantic import BaseModel, Field, model_validator

from nc3_testing_platform.core.enums import (
    ReportFormat,
    ReportLanguage,
    ReportTier,
    TechnicalReportView,
)
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp


class ReportRequest(BaseModel):
    """Generate one report from exactly one source."""

    tier: ReportTier
    technical_view: TechnicalReportView | None = Field(
        default=None,
        description="Depth of a technical report. Meaningless for the executive tier.",
    )
    format: ReportFormat
    language: ReportLanguage = ReportLanguage.EN
    source_scan_job_id: ResourceId | None = Field(
        default=None, description="Report on a whole scan. Mutually exclusive."
    )
    source_scan_task_id: ResourceId | None = Field(
        default=None, description="Report on one test's result. Mutually exclusive."
    )

    @model_validator(mode="after")
    def _exactly_one_source(self) -> "ReportRequest":
        if bool(self.source_scan_job_id) == bool(self.source_scan_task_id):
            raise ValueError(
                "Supply exactly one of `source_scan_job_id` or `source_scan_task_id`."
            )
        return self

    @model_validator(mode="after")
    def _technical_view_requires_technical_tier(self) -> "ReportRequest":
        if self.technical_view is not None and self.tier is not ReportTier.TECHNICAL:
            raise ValueError("`technical_view` applies only to the technical tier.")
        return self


class Report(BaseSchema):
    """Provenance metadata for one generated report.

    The source identifiers deliberately carry no foreign key.
    """

    id: ResourceId
    organization_id: ResourceId
    tier: ReportTier
    technical_view: TechnicalReportView | None = None
    format: ReportFormat
    language: ReportLanguage
    source_scan_job_id: ResourceId | None = None
    source_scan_task_id: ResourceId | None = None
    generated_by_user_id: ResourceId | None = Field(
        default=None, description="Attribution only. Null once the user is erased."
    )
    generated_at: Timestamp
