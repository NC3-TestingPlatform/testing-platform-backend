"""SQLAlchemy models for scan execution (§6.1, §7.1, §7.2, §8.1).

A purge hard-deletes the scan data (§7.1 retention), so containment cascades:
deleting a `scan_job` takes its tasks, deleting a task takes its result. Every
other reference follows the doc's stated `ON DELETE` behavior.

`test_key`, `test_version`, and `classification` are copied from the code-owned
executable-test catalog (§7.3) at task creation and are immutable thereafter —
an application rule; rows carry no updated_at to tempt otherwise.
"""

import uuid
from datetime import datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core import enums
from nc3_testing_platform.core.db import (
    SCAN_CLASSIFICATION,
    SCAN_GRADE,
    SCAN_JOB_STATUS,
    SCAN_MODULE,
    SCAN_SOURCE,
    SCAN_TASK_STATUS,
    Base,
    uuid_pk,
)


class FileUpload(Base):
    """Metadata for one uploaded file; the bytes are temporary (§6.1)."""

    __tablename__ = "file_upload"
    __table_args__ = (
        # §14: the storage reference exists exactly while the bytes do.
        sa.CheckConstraint(
            "(purged_at IS NULL) = (storage_key IS NOT NULL)",
            name="storage_key_while_bytes_exist",
        ),
        # §14: a known uploader implies a known organization.
        sa.CheckConstraint(
            "uploaded_by_user_id IS NULL OR organization_id IS NOT NULL",
            name="uploader_implies_org",
        ),
        # §14: the purge deadline is at most 24 hours after upload.
        sa.CheckConstraint(
            "purge_due_at <= uploaded_at + interval '24 hours'",
            name="purge_within_24_hours",
        ),
        # §14: the purge deadline never precedes the upload.
        sa.CheckConstraint(
            "purge_due_at >= uploaded_at",
            name="purge_not_before_upload",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    uploaded_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    original_filename: Mapped[str]
    declared_mime_type: Mapped[str | None]
    detected_mime_type: Mapped[str]
    size_bytes: Mapped[int] = mapped_column(sa.BigInteger)
    sha256: Mapped[str]
    # Never a browser-accessible path; null after purge.
    storage_key: Mapped[str | None]
    uploaded_at: Mapped[datetime]
    # Indexed for the purge sweep.
    purge_due_at: Mapped[datetime] = mapped_column(index=True)
    purged_at: Mapped[datetime | None]


class ScanJob(Base):
    """One submitted scan request (§7.1)."""

    __tablename__ = "scan_job"
    __table_args__ = (
        # §14, in the doc's order. Between two null tests, `=` reads "exactly when".
        sa.CheckConstraint(
            "num_nonnulls(asset_id, target_domain, file_upload_id) = 1",
            name="one_launch_target",
        ),
        # `cardinality`, not `array_length`: the latter is null on an empty
        # array, and a CHECK that evaluates to null passes.
        sa.CheckConstraint(
            "cardinality(modules) >= 1",
            name="modules_not_empty",
        ),
        sa.CheckConstraint(
            "(source = 'schedule') = (schedule_id IS NOT NULL)",
            name="schedule_provenance",
        ),
        sa.CheckConstraint(
            "(source = 'api') = (api_key_id IS NOT NULL)", name="api_key_provenance"
        ),
        sa.CheckConstraint(
            "target_domain IS NULL OR source = 'guest'", name="guest_only_target_text"
        ),
        sa.CheckConstraint(
            "claim_token_hash IS NULL OR source = 'guest'", name="guest_only_claimable"
        ),
        sa.CheckConstraint(
            "source <> 'guest' OR claimed_at IS NOT NULL "
            "OR claim_token_hash IS NOT NULL",
            name="unclaimed_guest_holds_hash",
        ),
        sa.CheckConstraint(
            "claimed_by_user_id IS NULL OR claimed_at IS NOT NULL",
            name="claim_actor_implies_time",
        ),
        sa.CheckConstraint(
            "claimed_at IS NULL OR organization_id IS NOT NULL",
            name="claimed_job_has_org",
        ),
        sa.CheckConstraint(
            "claimed_at IS NULL OR claim_token_hash IS NULL",
            name="claim_discards_hash",
        ),
        sa.CheckConstraint(
            "organization_id IS NOT NULL OR source = 'guest'",
            name="only_guest_lacks_org",
        ),
        sa.CheckConstraint(
            "(status IN ('completed', 'partial', 'failed', 'canceled')) "
            "= (finished_at IS NOT NULL)",
            name="terminal_state_has_finish",
        ),
        sa.CheckConstraint(
            "status <> 'running' OR started_at IS NOT NULL",
            name="running_has_start",
        ),
        sa.CheckConstraint(
            "(purge_at IS NOT NULL) = "
            "(status IN ('completed', 'partial', 'failed', 'canceled') "
            "OR (source = 'guest' AND claimed_at IS NULL))",
            name="purge_deadline_placement",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    triggered_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    source: Mapped[enums.ScanSource] = mapped_column(SCAN_SOURCE)
    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("schedule.id"), index=True
    )
    api_key_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("api_key.id"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), index=True
    )
    # Lowercase IDNA A-label domain not stored as an Asset; guest launches only.
    target_domain: Mapped[str | None]
    file_upload_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("file_upload.id"), unique=True
    )
    # What the launch asked for; compare against the tasks to see what ran.
    modules: Mapped[list[enums.ScanModule]] = mapped_column(ARRAY(SCAN_MODULE))
    module_configuration: Mapped[dict[str, Any]] = mapped_column(
        server_default=sa.text("'{}'::jsonb")
    )
    status: Mapped[enums.ScanJobStatus] = mapped_column(SCAN_JOB_STATUS)
    status_reason: Mapped[str | None]
    # Hash of the 256-bit one-time token returned by an unauthenticated launch;
    # the plaintext is never stored, and a successful claim nulls the hash.
    claim_token_hash: Mapped[str | None]
    claimed_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="SET NULL"), index=True
    )
    claimed_at: Mapped[datetime | None]
    # Final hard-deletion timestamp, not the start of a grace period (§7.1).
    # Indexed for the purge sweep.
    purge_at: Mapped[datetime | None] = mapped_column(index=True)
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class ScanTask(Base):
    """Persisted execution of one executable test (§7.2).

    `id` doubles as the queue task identifier; durable cancellation intent lives
    in `cancellation_requested_at`, and the queue task is revoked by this id.
    """

    __tablename__ = "scan_task"
    __table_args__ = (
        sa.CheckConstraint(
            "num_nonnulls(target_asset_id, target_domain, file_upload_id) = 1",
            name="one_task_target",
        ),
        sa.CheckConstraint(
            "status <> 'blocked' OR status_reason IS NOT NULL",
            name="blocked_says_why",
        ),
        sa.CheckConstraint(
            "(module = 'file') = (classification = 'not_applicable')",
            name="not_applicable_is_file_only",
        ),
        sa.CheckConstraint(
            "(file_upload_id IS NOT NULL) = (module = 'file')",
            name="file_task_targets_upload",
        ),
        sa.CheckConstraint(
            "(status IN ('completed', 'failed', 'skipped', 'blocked', 'canceled')) "
            "= (finished_at IS NOT NULL)",
            name="terminal_state_has_finish",
        ),
        sa.CheckConstraint(
            "status <> 'running' OR started_at IS NOT NULL",
            name="running_has_start",
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    scan_job_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("scan_job.id", ondelete="CASCADE"), index=True
    )
    # Discovery and fan-out lineage for all-in-one scans.
    parent_task_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("scan_task.id"), index=True
    )
    module: Mapped[enums.ScanModule] = mapped_column(SCAN_MODULE)
    test_key: Mapped[str]
    test_version: Mapped[str]
    classification: Mapped[enums.ScanClassification] = mapped_column(
        SCAN_CLASSIFICATION
    )
    target_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("asset.id", ondelete="RESTRICT"), index=True
    )
    target_domain: Mapped[str | None]
    file_upload_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("file_upload.id"), index=True
    )
    configuration: Mapped[dict[str, Any]] = mapped_column(
        server_default=sa.text("'{}'::jsonb")
    )
    status: Mapped[enums.ScanTaskStatus] = mapped_column(SCAN_TASK_STATUS)
    status_reason: Mapped[str | None]
    cancellation_requested_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]


class ScanResult(Base):
    """The stored output of one completed task; at most one per task (§8.1)."""

    __tablename__ = "scan_result"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID | None] = mapped_column(
        sa.ForeignKey("organization.id"), index=True
    )
    scan_task_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("scan_task.id", ondelete="CASCADE"), unique=True
    )
    schema_version: Mapped[str]
    raw_output: Mapped[dict[str, Any]]
    summary: Mapped[dict[str, Any]] = mapped_column(
        server_default=sa.text("'{}'::jsonb")
    )
    # Only Email, Web headers, and Web TLS tasks grade; presence per test is
    # catalog-owned and stays outside CHECK reach (§14 closing note).
    grade: Mapped[enums.ScanGrade | None] = mapped_column(SCAN_GRADE)
    severity_counts: Mapped[dict[str, Any] | None]
    completed_at: Mapped[datetime]
