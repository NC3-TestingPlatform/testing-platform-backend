"""Deterministic sample data for the mock backend.

Every identifier and timestamp is fixed. The generated document is byte-stable
across runs, and a spec diff shows real contract changes rather than churn.
"""

from datetime import UTC, datetime
from uuid import UUID

from nc3_testing_platform.core.config import RETENTION_EXTENSION
from nc3_testing_platform.core.enums import (
    FindingSeverity,
    FindingStatus,
    ScanClassification,
    ScanGrade,
    ScanJobStatus,
    ScanModule,
    ScanSource,
    ScanTaskStatus,
    TrendDirection,
)
from nc3_testing_platform.core.schemas import SeverityCounts
from nc3_testing_platform.domains.scans.schemas import (
    Finding,
    ResultTrend,
    ScanJob,
    ScanJobAccepted,
    ScanJobDetail,
    ScanResult,
    ScanTask,
)

_T0 = datetime(2026, 7, 31, 9, 0, tzinfo=UTC)
# Guest retention deadline: creation plus 24 hours. The interval is platform
# configuration rather than contract, so only the resulting timestamp is shown.
_GUEST_PURGE_AT = datetime(2026, 8, 1, 9, 0, tzinfo=UTC)
_T1 = datetime(2026, 7, 31, 9, 0, 4, tzinfo=UTC)
_T2 = datetime(2026, 7, 31, 9, 1, 12, tzinfo=UTC)
# finished_at + 12 months + 30 days
_PURGE_AT = datetime(2027, 8, 30, 9, 1, 12, tzinfo=UTC)

ORGANIZATION_ID = UUID("019ed068-b8f8-7e25-8902-35e3ed567f57")
USER_ID = UUID("019ed068-f263-7683-bcce-ef76973414db")
ASSET_ID = UUID("019ee1a0-1c44-7a10-9d2e-4b7c8f0a1e33")
JOB_ID = UUID("019ee1a0-3b91-7c05-8f41-6d2a90bb17c4")
UPLOAD_ID = UUID("019ee1a0-2a78-7b93-8c1d-3f5e6a7b8c9d")

_TASK_HEADERS = UUID("019ee1a0-4d02-7e18-b3a7-8c15ffd2a091")
_TASK_TLS = UUID("019ee1a0-5e13-7f29-a4b8-9d26aae3b1a2")
_TASK_SUBDOMAINS = UUID("019ee1a0-6f24-7a3a-b5c9-ae37bbf4c2b3")
_TASK_EMAIL = UUID("019ee1a0-7035-7b4b-86da-bf48ccf5d3c4")
_TASK_PQC = UUID("019ee1a0-8146-7c5c-87eb-c059ddf6e4d5")
_TASK_DNSSEC = UUID("019ee1a0-9257-7d6d-88fc-d16aeef7f5e6")

_RESULT_HEADERS = UUID("019ee1a1-0368-7e7e-890d-e27bfff806f7")
_RESULT_EMAIL = UUID("019ee1a1-1479-7f8f-8a1e-f38c001917a8")
_PRIOR_RESULT_EMAIL = UUID("019ec3b2-58a1-7c40-9e12-7ab34cd56e89")

_FINDING_HSTS = UUID("019ee1a1-258a-7a90-8b2f-049d112a28b9")
_FINDING_DMARC = UUID("019ee1a1-369b-7ba1-8c30-15ae223b39ca")
_FINDING_SPF = UUID("019ee1a1-47ac-7cb2-8d41-26bf334c4adb")

FILE_JOB_ID = UUID("019ee1a2-4c60-7d81-9e23-5ab41cd67f90")
_FILE_TASK_HASHLOOKUP = UUID("019ee1a2-5d71-7e92-af34-6bc52de78a01")
_FILE_TASK_PANDORA = UUID("019ee1a2-6e82-7fa3-b045-7cd63ef89b12")
_FILE_TASK_METADATA = UUID("019ee1a2-7f93-7ab4-8156-8de74fa9ac23")
_FILE_TASK_MIME = UUID("019ee1a2-80a4-7bc5-8267-9ef85fabbd34")


def _task(
    task_id: UUID,
    module: ScanModule,
    test_key: str,
    status: ScanTaskStatus = ScanTaskStatus.COMPLETED,
    status_reason: str | None = None,
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_job_id=JOB_ID,
        module=module,
        test_key=test_key,
        test_version="1.4.0",
        classification=ScanClassification.NON_INTRUSIVE,
        target_asset_id=ASSET_ID,
        status=status,
        status_reason=status_reason,
        created_at=_T0,
        started_at=_T1,
        finished_at=_T2 if status != ScanTaskStatus.RUNNING else None,
    )


def sample_tasks() -> list[ScanTask]:
    """The six tasks an all-in-one domain scan fans out into.

    One is `blocked` on purpose: `status_reason` is mandatory in that state, and the
    UI has to be able to tell the user why a check did not run.
    """
    return [
        _task(_TASK_EMAIL, ScanModule.EMAIL, "email.mailvalidator"),
        _task(_TASK_HEADERS, ScanModule.WEB, "web.headers"),
        _task(_TASK_TLS, ScanModule.WEB, "web.tls"),
        _task(_TASK_SUBDOMAINS, ScanModule.WEB, "web.subdomain_enumeration"),
        _task(_TASK_PQC, ScanModule.PQC, "pqc.quantumvalidator"),
        _task(
            _TASK_DNSSEC,
            ScanModule.DNSSEC,
            "dnssec.chainvalidator",
            status=ScanTaskStatus.BLOCKED,
            status_reason="dnssec.resolver_unavailable",
        ),
    ]


def sample_file_tasks() -> list[ScanTask]:
    """The four tasks a File scan fans out into.

    Every one is `not_applicable`: a File test analyzes an upload, so there is no
    external target for the intrusive classification to apply to. They carry
    `file_upload_id` where a domain task carries `target_asset_id`.
    """
    return [
        ScanTask(
            id=task_id,
            scan_job_id=FILE_JOB_ID,
            module=ScanModule.FILE,
            test_key=test_key,
            test_version="1.2.0",
            classification=ScanClassification.NOT_APPLICABLE,
            file_upload_id=UPLOAD_ID,
            status=ScanTaskStatus.COMPLETED,
            created_at=_T0,
            started_at=_T1,
            finished_at=_T2,
        )
        for task_id, test_key in (
            (_FILE_TASK_HASHLOOKUP, "file.hashlookup"),
            (_FILE_TASK_PANDORA, "file.pandora"),
            (_FILE_TASK_METADATA, "file.metadata"),
            (_FILE_TASK_MIME, "file.mime_check"),
        )
    ]


def sample_file_job() -> ScanJob:
    """A completed File scan.

    Carries `file_upload_id` where a domain scan carries `asset_id`, and no grade
    anywhere: no File test produces one.
    """
    return ScanJob(
        id=FILE_JOB_ID,
        organization_id=ORGANIZATION_ID,
        source=ScanSource.MANUAL,
        triggered_by_user_id=USER_ID,
        file_upload_id=UPLOAD_ID,
        modules=[ScanModule.FILE],
        status=ScanJobStatus.COMPLETED,
        purge_at=_PURGE_AT,
        created_at=_T0,
        started_at=_T1,
        finished_at=_T2,
    )


def sample_file_job_detail() -> ScanJobDetail:
    """The File scan with its four tasks."""
    return ScanJobDetail(**sample_file_job().model_dump(), tasks=sample_file_tasks())


def sample_job(
    status: ScanJobStatus = ScanJobStatus.PARTIAL,
    source: ScanSource = ScanSource.MANUAL,
    extended: bool = False,
) -> ScanJob:
    """A completed all-in-one scan of an owned asset.

    `partial` rather than `completed`: one task is blocked, so usable results exist
    alongside a failure. That combination is the one clients most often get wrong.
    """
    return ScanJob(
        id=JOB_ID,
        organization_id=ORGANIZATION_ID,
        source=source,
        triggered_by_user_id=USER_ID,
        asset_id=ASSET_ID,
        modules=[
            ScanModule.EMAIL,
            ScanModule.WEB,
            ScanModule.PQC,
            ScanModule.DNSSEC,
        ],
        status=status,
        status_reason="scan.partial_blocked_task",
        purge_at=_PURGE_AT + RETENTION_EXTENSION if extended else _PURGE_AT,
        created_at=_T0,
        started_at=_T1,
        finished_at=_T2,
    )


def sample_job_detail() -> ScanJobDetail:
    """The job/task snapshot a live-progress client fetches before subscribing."""
    return ScanJobDetail(**sample_job().model_dump(), tasks=sample_tasks())


def queued_job_accepted(
    guest: bool = False, file_scan: bool = False
) -> ScanJobAccepted:
    """The `202` body of a launch, before any task has started.

    Exactly one target field is set, and which one is decided by the request context
    rather than by the caller — a multipart launch carries an upload, an anonymous
    JSON launch a bare domain, an authenticated JSON launch an Asset. The guest
    branch is also the only one that returns a claim capability.
    """
    job = ScanJobAccepted(
        id=JOB_ID,
        organization_id=None if guest else ORGANIZATION_ID,
        source=ScanSource.GUEST if guest else ScanSource.MANUAL,
        triggered_by_user_id=None if guest else USER_ID,
        asset_id=None if (guest or file_scan) else ASSET_ID,
        target_domain="example.lu" if (guest and not file_scan) else None,
        file_upload_id=UPLOAD_ID if file_scan else None,
        modules=_requested_modules(guest=guest, file_scan=file_scan),
        status=ScanJobStatus.QUEUED,
        # An unclaimed guest job carries its deadline from creation; an owned job
        # has none until it finishes. The claim recomputes it under the normal rule.
        purge_at=_GUEST_PURGE_AT if guest else None,
        created_at=_T0,
    )
    if guest:
        # 256 bits, base64url, no padding — 43 characters.
        job.claim_token = "9xK2mQ7pL4vR8nT1jH5gF3dS6aW0zYbUcElOnAiKrXs"
    return job


def _requested_modules(*, guest: bool, file_scan: bool) -> list[ScanModule]:
    """A file launch is always the File module, and the multipart request carries no module field."""
    if file_scan:
        return [ScanModule.FILE]
    if guest:
        return [ScanModule.EMAIL]
    return [ScanModule.EMAIL, ScanModule.WEB, ScanModule.PQC, ScanModule.DNSSEC]


def sample_results() -> list[ScanResult]:
    """Results for the two graded tests in the sample job.

    `raw_output` is deliberately shallow. Its real shape belongs to the
    executable-test registry, and inventing a rich one here would put a shape into
    the frontend's mock that the registry has never agreed to.
    """
    return [
        ScanResult(
            id=_RESULT_EMAIL,
            scan_task_id=_TASK_EMAIL,
            schema_version="2026-05-01",
            raw_output={"spf": "pass", "dkim": "pass", "dmarc": "p=none"},
            summary={"policy_enforced": False},
            grade=ScanGrade.B,
            severity_counts=SeverityCounts(medium=1, info=1),
            trend=ResultTrend(
                previous_scan_result_id=_PRIOR_RESULT_EMAIL,
                direction=TrendDirection.IMPROVING,
                delta=1,
            ),
            completed_at=_T2,
        ),
        ScanResult(
            id=_RESULT_HEADERS,
            scan_task_id=_TASK_HEADERS,
            schema_version="2026-05-01",
            raw_output={
                "strict_transport_security": None,
                "content_security_policy": "present",
            },
            summary={"missing_headers": 1},
            grade=ScanGrade.C,
            severity_counts=SeverityCounts(medium=1),
            completed_at=_T2,
        ),
    ]


def sample_findings() -> list[Finding]:
    """Findings across both sample results, covering all three status kinds a client must render differently."""
    return [
        Finding(
            id=_FINDING_DMARC,
            scan_result_id=_RESULT_EMAIL,
            check_id="email.dmarc.policy_enforced",
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.PERSISTENT,
            title="DMARC policy is not enforced",
            description=(
                "The domain publishes a DMARC record with p=none, so receivers "
                "take no action on messages that fail authentication."
            ),
            affected_resource="_dmarc.example.lu",
            remediation="Move to p=quarantine, then to p=reject once reports are clean.",
            external_references=["RFC 7489"],
        ),
        Finding(
            id=_FINDING_SPF,
            scan_result_id=_RESULT_EMAIL,
            check_id="email.spf.present",
            severity=FindingSeverity.INFO,
            status=FindingStatus.RESOLVED,
            title="SPF record present",
            description="A syntactically valid SPF record was found.",
            affected_resource="example.lu",
        ),
        Finding(
            id=_FINDING_HSTS,
            scan_result_id=_RESULT_HEADERS,
            check_id="web.headers.hsts_missing",
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.REGRESSION,
            title="Strict-Transport-Security header missing",
            description=(
                "The response carries no HSTS header, so a client may be "
                "downgraded to plaintext on a first or stale connection."
            ),
            affected_resource="https://example.lu/",
            remediation="Send Strict-Transport-Security with a max-age of at least 31536000.",
            external_references=["RFC 6797"],
        ),
    ]
