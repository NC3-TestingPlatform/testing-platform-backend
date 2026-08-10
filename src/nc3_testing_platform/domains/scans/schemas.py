"""Scan launch, execution, results, and findings.

Shape:
    ScanJob  1─n  ScanTask  1─0..1  ScanResult  1─n  Finding

A ScanJob is one submitted request. It fans out into one ScanTask per executable
test and each task queues, fails, and is graded independently. A result belongs to
a task.

MVP: **Open payloads.** Several columns are JSONB whose element shapes belong to the
scan modules, which do not exist yet. Each module will own its result schema; once
a module is written and wired, its schema is imported and composed into the result
envelope here, and the generated contract gains typed results.
Until then those payloads are untyped.
Each such field is marked `TODO` naming its owner and what unblocks it.
"""

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

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
from nc3_testing_platform.core.schemas import (
    BaseSchema,
    DomainName,
    ResourceId,
    SeverityCounts,
    Timestamp,
)
from nc3_testing_platform.domains.statements.schemas import StatementResponseSubmission

# 256 bits of randomness, base64url without padding.
CLAIM_TOKEN_PATTERN = r"^[A-Za-z0-9_-]{43}$"

_STATEMENT_RESPONSES_DESCRIPTION = (
    "Answers to the statements this launch requires, each identified by key and "
    "version. Recorded as immutable receipts bound to the job before any gate is "
    "evaluated. Empty in practice for v4.0: a declaration is required only by an "
    "intrusive test, and the v4.0 catalog classifies none. A boolean "
    "`attestation` flag is not a substitute and is not part of this contract."
)

# The v4.0 executable tests. Not an enum: `test_key` is namespaced text whose
# vocabulary is owned by application code and extends without a migration. Listed
# here so the contract can document and exemplify the current catalog.
V4_TEST_KEYS = (
    "email.mailvalidator",
    "web.headers",
    "web.tls",
    "web.subdomain_enumeration",
    "file.hashlookup",
    "file.pandora",
    "file.metadata",
    "file.mime_check",
    "pqc.quantumvalidator",
    "dnssec.chainvalidator",
)

_TEST_KEY_DESCRIPTION = (
    "Stable identifier of the executable test. v4.0 catalog: "
    + ", ".join(f"`{key}`" for key in V4_TEST_KEYS)
    + ". The vocabulary is code-owned and extends without a schema change."
)


class Finding(BaseSchema):
    """One diagnostic-rule outcome recorded against a scan result.

    `check_id` is the stable identity anchor used to match a finding across scans.
    It is never derived from the title or from position in the output, and changing
    one is a breaking result-schema change.
    """

    id: ResourceId
    scan_result_id: ResourceId
    check_id: str = Field(
        description=(
            "Stable diagnostic-rule identifier. Regression matching keys on this "
            "and, where one rule yields several findings, on the normalized "
            "`affected_resource`."
        )
    )
    severity: FindingSeverity
    status: FindingStatus = Field(
        description=(
            "Historical-comparison classification, derived when the result is "
            "written and immutable thereafter. No operation mutates it."
        )
    )
    title: str
    description: str
    affected_resource: str | None = Field(
        default=None,
        description="The specific record, host, or header the finding concerns.",
    )
    remediation: str | None = None
    # TODO: typed evidence is owned by the check that raises the finding, and so by
    # the module that owns the check. Composed in with the module's result schema.
    evidence: dict[str, Any] | None = Field(
        default=None, description="Per-check evidence. Shape owned by the check."
    )
    external_references: list[Any] = Field(
        default_factory=list,
        description="External references for this rule. Element shape owned by the check.",
    )


class ResultTrend(BaseSchema):
    """Movement of a result's score against the previous result for the same test.

    Computed per request from the two results. `delta` uses the scale of whichever
    metric was compared, so it is comparable against other deltas for the same test.
    """

    previous_scan_result_id: ResourceId = Field(
        description="The result this one was compared against."
    )
    direction: TrendDirection
    delta: float = Field(
        description=(
            "Signed change, positive when improving. Grades move in whole steps "
            "along `A+ A B C D F`; severity counts move by finding count."
        )
    )


class ScanResult(BaseSchema):
    """The output of one completed ScanTask. At most one per task."""

    id: ResourceId
    scan_task_id: ResourceId
    schema_version: str = Field(
        description=(
            "Version of the result payload written by this test. Text, not a "
            "number: the registry versions each test's result schema independently."
        )
    )
    # TODO: owned by the scan module that produces the result.
    # One shape, or keyed shapes.
    raw_output: dict[str, Any] = Field(
        description="Full test output. Shape owned by the executable-test registry."
    )
    summary: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Condensed verdicts for display. Non-graded tests carry their per-step "
            "verdicts here. Shape owned by the executable-test registry."
        ),
    )
    grade: ScanGrade | None = Field(
        default=None,
        description=(
            "Letter grade. Present only for `email.mailvalidator`, `web.headers`, "
            "and `web.tls`. No cross-module composite score exists."
        ),
    )
    severity_counts: SeverityCounts | None = Field(
        default=None, description="Findings by severity. Used by non-graded tests."
    )
    trend: ResultTrend | None = Field(
        default=None,
        description=(
            "Movement against the previous result for this test, tracking `grade` "
            "where the test is graded and total findings where it is not. Null on "
            "the first result for a test, or once the predecessor has been purged."
        ),
    )
    completed_at: Timestamp


class ScanTask(BaseSchema):
    """One executable test run against one domain or one uploaded file.

    Exactly one of `target_asset_id`, `target_domain`, and `file_upload_id` is set.
    `id` doubles as the queue task identifier and as the public `task_id` carried by
    live-progress events.
    """

    id: ResourceId
    scan_job_id: ResourceId
    parent_task_id: ResourceId | None = Field(
        default=None,
        description=(
            "Discovery and fan-out lineage. A subdomain found by "
            "`web.subdomain_enumeration` becomes a child task of the discovering one."
        ),
    )
    module: ScanModule
    test_key: str = Field(description=_TEST_KEY_DESCRIPTION)
    test_version: str = Field(
        description="Version of the test definition, copied at task creation."
    )
    classification: ScanClassification
    target_asset_id: ResourceId | None = None
    target_domain: DomainName | None = Field(
        default=None,
        description="Set for a guest target or a discovered subdomain with no Asset row.",
    )
    file_upload_id: ResourceId | None = None
    # TODO: shape owned by the module, alongside its result schema.
    configuration: dict[str, Any] = Field(
        default_factory=dict,
        description="Resolved per-test configuration. Shape owned by the test registry.",
    )
    status: ScanTaskStatus
    status_reason: str | None = Field(
        default=None,
        description=(
            "Stable namespaced reason code for a failed, skipped, blocked, or "
            "canceled outcome. Always present when the status is `blocked`. "
            "A task timeout appears as `failed` plus the task-timeout reason: "
            "timeout is a reason, never a status. Labels and localization are "
            "code-owned."
        ),
    )
    cancellation_requested_at: Timestamp | None = Field(
        default=None,
        description=(
            "Durable cancellation intent. Workers check it before starting and at "
            "safe interruption points; a canceled task cannot later produce an "
            "accepted successful result."
        ),
    )
    created_at: Timestamp
    started_at: Timestamp | None = None
    finished_at: Timestamp | None = None

    @model_validator(mode="after")
    def _exactly_one_target(self) -> "ScanTask":
        """Rejects a task carrying zero or several targets."""
        targets = (self.target_asset_id, self.target_domain, self.file_upload_id)
        if sum(value is not None for value in targets) != 1:
            raise ValueError(
                "Exactly one of `target_asset_id`, `target_domain`, and "
                "`file_upload_id` is set."
            )
        return self


class ScanJob(BaseSchema):
    """One submitted scan request.

    Exactly one of `asset_id`, `target_domain`, and `file_upload_id` is set, chosen
    by the request context rather than by the caller: an authenticated JSON launch
    populates `asset_id`, an unauthenticated JSON launch populates `target_domain`,
    and a multipart launch populates `file_upload_id`.
    """

    id: ResourceId
    organization_id: ResourceId | None = Field(
        default=None,
        description=(
            "Owning organization, and the row-level-security key. Null for a guest "
            "job until it is claimed. Tasks, results, and findings inherit it, so "
            "it is not repeated on those resources."
        ),
    )
    source: ScanSource = Field(
        description=(
            "Derived server-side from the request context, never supplied by the "
            "caller. It selects which gates apply."
        )
    )
    schedule_id: ResourceId | None = Field(
        default=None, description="Present when `source` is `schedule`."
    )
    api_key_id: ResourceId | None = Field(
        default=None, description="Present when `source` is `api`."
    )
    triggered_by_user_id: ResourceId | None = Field(
        default=None,
        description="Attribution only. Becomes null if the user is erased.",
    )
    asset_id: ResourceId | None = None
    target_domain: DomainName | None = Field(
        default=None,
        description=(
            "Canonical domain that is not an Asset row. Populated only by an "
            "unauthenticated launch; a guest target never becomes an Asset."
        ),
    )
    file_upload_id: ResourceId | None = Field(
        default=None,
        description="The upload created by an accepted multipart launch. At most one per job.",
    )
    modules: list[ScanModule] = Field(
        description=(
            "What the launch asked for. Compare against the tasks to see what ran: a "
            "requested module whose task was blocked or skipped produced nothing."
        )
    )
    # TODO: launch options are owned by the module they configure
    module_configuration: dict[str, Any] = Field(default_factory=dict)
    status: ScanJobStatus
    status_reason: str | None = Field(
        default=None,
        description=(
            "Stable namespaced reason code for a job-wide exceptional or terminal "
            "outcome. A job timeout sets the job-timeout reason and resolves to "
            "`partial` when usable results exist, otherwise `failed`."
        ),
    )
    claimed_by_user_id: ResourceId | None = None
    claimed_at: Timestamp | None = None
    purge_at: Timestamp | None = Field(
        default=None,
        description=(
            "Read-only final hard-deletion timestamp, not the start of a grace "
            "period. Null until terminal completion, then `finished_at` plus twelve "
            "months plus thirty days by default, with thirty days' notice.\n\n"
            "An unclaimed guest job is the exception: it carries a deadline from "
            "creation, because ownerless data has nobody to notify and no reason to "
            "be kept. A successful claim recomputes this under the normal rule, and "
            "notice begins to apply only from that point. Purging at the deadline "
            "does not wait for the job to finish; unfinished work is terminated."
        ),
    )
    created_at: Timestamp
    started_at: Timestamp | None = None
    finished_at: Timestamp | None = None

    @model_validator(mode="after")
    def _exactly_one_target(self) -> "ScanJob":
        """Rejects a job carrying zero or several targets."""
        targets = (self.asset_id, self.target_domain, self.file_upload_id)
        if sum(value is not None for value in targets) != 1:
            raise ValueError(
                "Exactly one of `asset_id`, `target_domain`, and `file_upload_id` "
                "is set."
            )
        return self


class ScanJobAccepted(ScanJob):
    """The `202` body of a launch.

    Identical to a ScanJob except that an unauthenticated launch also returns the
    one-time token needed to claim the scan after registering.
    """

    claim_token: str | None = Field(
        default=None,
        pattern=CLAIM_TOKEN_PATTERN,
        description=(
            "One-time token that claims this scan for an organization once the "
            "guest registers. Present only on the response to an unauthenticated "
            "launch, and readable only here — the server keeps a hash, so a lost "
            "token cannot be recovered and the scan stays unclaimable."
        ),
        examples=["9xK2mQ7pL4vR8nT1jH5gF3dS6aW0zYbUcElOnAiKrXs"],
    )


class ScanJobDetail(ScanJob):
    """A job together with its task snapshot.

    This is the snapshot a live-progress client fetches before subscribing, and
    refetches after a reconnect. Results are a separate call because they are large.
    """

    tasks: list[ScanTask] = Field(default_factory=list)


class _DomainLaunch(BaseModel):
    """What the two JSON launch variants share.

    Only the target field differs between them, and that difference is the whole
    point of the access-state split — so everything else, including the rule that a
    domain launch cannot request the File module, belongs here once.

    Not a component in the generated document: nothing references it, so Pydantic
    inlines its fields into each variant.
    """

    modules: list[ScanModule] = Field(
        min_length=1,
        max_length=5,
        json_schema_extra={"uniqueItems": True},
        description="One or more distinct modules to run against the target.",
    )
    module_configuration: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Per-module launch options. Each module defines its own option shape; "
            "the web module's subdomain-discovery option is one example."
        ),
    )
    statement_responses: list[StatementResponseSubmission] = Field(
        default_factory=list,
        max_length=50,
        description=_STATEMENT_RESPONSES_DESCRIPTION,
    )

    @field_validator("modules")
    @classmethod
    def _reject_file_module(cls, modules: list[ScanModule]) -> list[ScanModule]:
        """The File module has no domain target to scan.

        It analyzes an upload, so it is reachable only through the multipart
        transport. Accepting it here would create a job whose tasks have nothing to
        run against.
        """
        if ScanModule.FILE in modules:
            raise ValueError(
                "The `file` module analyzes an upload, not a domain. Launch it with "
                "a `multipart/form-data` request instead."
            )
        if len(set(modules)) != len(modules):
            raise ValueError("Each module appears at most once.")
        return modules


class AssetScanLaunch(_DomainLaunch):
    """Authenticated domain launch.

    Selected by `application/json` plus an authenticated caller.
    """

    asset_id: ResourceId = Field(
        description="An Asset belonging to the caller's organization."
    )


class GuestScanLaunch(_DomainLaunch):
    """Unauthenticated domain launch.

    Selected by `application/json` plus an anonymous caller.

    Free target text exists in this context and nowhere else. The domain is stored
    on the job and never becomes an Asset row. Guest launches run non-intrusive
    tests only, which in v4.0 is every domain test.
    """

    target: DomainName = Field(
        description=(
            "Domain to scan. Unicode or ASCII input is accepted and canonicalized "
            "to lowercase IDNA (A-label) form without a trailing dot."
        ),
        examples=["example.lu"],
    )


class FileScanLaunch(BaseModel):
    """File launch. Selected by `multipart/form-data`.

    Carries no target field and no `modules` field.
    The resulting job is always the File module.
    """

    file: str = Field(
        json_schema_extra={"contentMediaType": "application/octet-stream"},
        description=(
            "The file to analyze. Maximum 50 MB by default. The MIME type is "
            "detected from the raw bytes; the declared `Content-Type` and the "
            "filename extension are not trusted."
        ),
    )
    module_configuration: dict[str, Any] = Field(default_factory=dict)


class ScanClaimRequest(BaseModel):
    """Claims a guest scan for the authenticated caller's organization.

    The token travels in the body rather than a header: it authorizes one operation
    on one resource, not the caller, and `Authorization` already carries the session
    that identifies who is claiming.
    """

    claim_token: str = Field(
        pattern=CLAIM_TOKEN_PATTERN,
        description="The one-time token returned by the unauthenticated launch.",
        examples=["9xK2mQ7pL4vR8nT1jH5gF3dS6aW0zYbUcElOnAiKrXs"],
    )


class ScanTaskEvent(BaseModel):
    """SSE `task`: one task changed state."""

    task_id: ResourceId
    status: ScanTaskStatus
    status_reason: str | None = Field(
        default=None, description="Present on a terminal status."
    )
    occurred_at: Timestamp


class ScanJobEvent(BaseModel):
    """SSE `job`: the job changed state."""

    status: ScanJobStatus
    status_reason: str | None = None
    occurred_at: Timestamp


class ScanHeartbeatEvent(BaseModel):
    """SSE `heartbeat`: the stream is alive.

    Sent on an interval so a client can tell a running scan from a dropped
    connection, and show when it last heard anything.
    """

    occurred_at: Timestamp


class ScanEndEvent(BaseModel):
    """SSE `end`: the job reached a terminal state and no further events follow."""

    status: ScanJobStatus
    occurred_at: Timestamp
