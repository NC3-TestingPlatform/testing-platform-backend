"""Closed enumerations of the v4 contract.

Every enum mirrors a PostgreSQL enum type in the data model, with two exceptions.
`VerificationStatus` and `TrendDirection` are computed at read time from stored rows and have no column of their own.

Absent or deferred values:
- `report_format` has no Atom member. RSS and Atom belong to `feed_format`, which
  is a property of a per-asset feed, not of a generated report.
- `asset_type` has only `domain`. IP and CIDR assets carry a different attestation
model and are deferred to v4.1.

`test_key`, `check_id`, `status_reason`, and `notification.type` are namespaced
text, not enums: the application code owns their vocabulary.
"""

from enum import StrEnum


class OrganizationRole(StrEnum):
    """Role within one organization."""

    MEMBER = "member"
    ORGANIZATION_ADMIN = "organization_admin"


class AssetType(StrEnum):
    """v4.0 assets are currently domains."""

    DOMAIN = "domain"


class AssetOrigin(StrEnum):
    """Whether the asset was registered by a user or found by subdomain discovery."""

    ADDED = "added"
    DISCOVERED = "discovered"


class VerificationStatus(StrEnum):
    """Current state of a domain-ownership challenge."""

    PENDING = "pending"
    VERIFIED = "verified"
    EXPIRED = "expired"


class VerificationScope(StrEnum):
    """Verification coverage. Zone coverage is evaluated by DNS-label ancestry."""

    EXACT = "exact"
    ZONE = "zone"


class DnsRecordType(StrEnum):
    """DNS record a verification challenge is published as.

    TXT is the only v4.0 method.
    """

    TXT = "TXT"


class StatementResponseKind(StrEnum):
    """Acceptance and attestation share a receipt shape but are distinct acts."""

    ACCEPTANCE = "acceptance"
    ATTESTATION = "attestation"


class ScanSource(StrEnum):
    """What requested a scan job.

    Derived from the request context, never supplied by the caller.
    """

    GUEST = "guest"
    MANUAL = "manual"
    SCHEDULE = "schedule"
    API = "api"


class ScanJobStatus(StrEnum):
    """Job lifecycle. `partial` means usable results exist alongside failures."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"


class ScanModule(StrEnum):
    """The five v4.0 test modules."""

    EMAIL = "email"
    WEB = "web"
    FILE = "file"
    PQC = "pqc"
    DNSSEC = "dnssec"


class ScanClassification(StrEnum):
    """Intrusiveness of one executable test, copied onto the task at creation.

    `not_applicable` is used only by File tests.
    """

    NON_INTRUSIVE = "non_intrusive"
    INTRUSIVE = "intrusive"
    NOT_APPLICABLE = "not_applicable"


class ScanTaskStatus(StrEnum):
    """Task lifecycle.

    `blocked` always carries a `status_reason` explaining why,
    so the UI can tell the user what stopped a check.
    """

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"
    CANCELED = "canceled"


class ScanGrade(StrEnum):
    """Letter grade. Produced by the scan modules."""

    A_PLUS = "A+"
    A = "A"
    B = "B"
    C = "C"
    D = "D"
    F = "F"


class TrendDirection(StrEnum):
    """Movement of a score against the previous comparable measurement."""

    IMPROVING = "improving"
    UNCHANGED = "unchanged"
    DECLINING = "declining"


class FindingSeverity(StrEnum):
    """Severity values of one finding."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(StrEnum):
    """Historical-comparison classification, derived at result time and immutable."""

    NEW = "new"
    REGRESSION = "regression"
    PERSISTENT = "persistent"
    RESOLVED = "resolved"


class ApiKeyScope(StrEnum):
    """Capability granted by an API key."""

    READ_ONLY = "read_only"
    FULL_SCAN = "full_scan"


class ReportTier(StrEnum):
    """Audience of a generated report."""

    EXECUTIVE = "executive"
    TECHNICAL = "technical"


class TechnicalReportView(StrEnum):
    """Depth of a technical report. Meaningful only when the evidence tier is technical."""

    FULL = "full"
    SUMMARY = "summary"


class ReportFormat(StrEnum):
    """Rendered report document formats."""

    PDF = "pdf"
    DOCX = "docx"
    JSON = "json"


class ReportLanguage(StrEnum):
    """Report output language."""

    EN = "en"
    FR = "fr"
    DE = "de"


class FeedFormat(StrEnum):
    """Syndication format of a per-asset feed."""

    RSS = "rss"
    ATOM = "atom"
