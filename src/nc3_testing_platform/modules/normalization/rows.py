"""`ModuleResult` → `scan_result` / `finding` row dicts. Pure, no persistence.

The last step before the database, and deliberately not the database step.
These functions take plain data and return plain dicts shaped like the columns
of data-model §8.1 and §8.2; the caller — B8 / US #84 — opens the session,
resolves tenancy, and writes them.

**The boundary, restated because it is easy to erode.** Nothing here takes a
`Session`, resolves an `organization_id`, or reads a clock: `completed_at` and
`organization_id` are caller-supplied because the platform, not the module,
knows them. Nothing here emits `finding.status` either — new / regression /
persistent / resolved is derived by comparing against history, which is B12a /
US #87's job and needs the very rows this function is producing.

Two calls, not one, because `finding.scan_result_id` does not exist until the
result row is written: build and flush the result, then map the findings
against its id.
"""

import copy
import uuid
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from nc3_testing_platform.modules.contract import ModuleResult
from nc3_testing_platform.modules.normalization import findings as finding_rules


def _json_mapping(value: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """A nullable JSONB payload as an independent plain dict, preserving ``None``.

    Deep, for the same reason `contract._snapshot` is: a shallow ``dict()``
    shares every nested list and dict with the `ModuleResult`, so a caller
    editing a row — adding a redaction, stripping a key before write — would
    reach back and mutate the result it was derived from. B12a / US #87 holds
    both at once (it compares this run's findings against history), so that
    aliasing is a live hazard rather than a theoretical one.

    ``None`` and ``{}`` are different rows: the column is nullable, and a
    finding that carries no evidence is not the same as one that carries an
    empty object.
    """
    return None if value is None else copy.deepcopy(dict(value))


def scan_result_row(
    result: ModuleResult,
    *,
    scan_task_id: uuid.UUID,
    completed_at: datetime,
    organization_id: uuid.UUID | None,
) -> dict[str, Any]:
    """One `ModuleResult` as a `scan_result` row dict (§8.1).

    `severity_counts` is derived here rather than taken from the module — it is
    platform-owned (IDR-018) and always carries all five bands. `grade` passes
    through as the module set it: ``None`` for the tests that do not grade,
    which is most of them.

    :param result: The module's returned result.
    :param scan_task_id: The task this result belongs to. One result per task
        (`scan_result.scan_task_id` is unique).
    :param completed_at: When the task finished, supplied by the caller — a
        pure mapper does not read a clock, and the platform owns the timeline.
    :param organization_id: The owning organization, or ``None`` for a guest
        scan. Resolved by the caller; this function never looks tenancy up.
    :return: A dict keyed by `scan_result` column name, minus the
        database-assigned `id`.
    """
    return {
        "organization_id": organization_id,
        "scan_task_id": scan_task_id,
        "schema_version": result.schema_version,
        "raw_output": copy.deepcopy(dict(result.raw_output)),
        "summary": copy.deepcopy(dict(result.summary)),
        "grade": result.grade,
        "severity_counts": finding_rules.severity_counts(result.findings),
        "completed_at": completed_at,
    }


def finding_rows(
    result: ModuleResult,
    *,
    scan_result_id: uuid.UUID,
    organization_id: uuid.UUID | None,
) -> list[dict[str, Any]]:
    """One `ModuleResult`'s findings as `finding` row dicts, in stored order.

    Ordered through `findings.order_findings`, so an unchanged re-run produces
    the same rows in the same sequence and a diff between two results is a real
    change. `evidence` and `external_references` are copied out to plain
    JSON-shaped containers — a ``tuple`` does not survive the JSONB boundary.

    :param result: The module's returned result.
    :param scan_result_id: The already-written result row these findings hang
        off. Caller-supplied because the id exists only once that row is
        flushed.
    :param organization_id: The owning organization, or ``None`` for a guest
        scan. Resolved by the caller.
    :return: A list of dicts keyed by `finding` column name, minus the
        database-assigned `id` and minus `status`, which B12a / US #87 derives
        from history.
    """
    return [
        {
            "organization_id": organization_id,
            "scan_result_id": scan_result_id,
            "check_id": finding.check_id,
            "severity": finding.severity,
            "title": finding.title,
            "description": finding.description,
            "affected_resource": finding.affected_resource,
            "remediation": finding.remediation,
            "evidence": _json_mapping(finding.evidence),
            "external_references": list(finding.external_references),
        }
        for finding in finding_rules.order_findings(result.findings)
    ]
