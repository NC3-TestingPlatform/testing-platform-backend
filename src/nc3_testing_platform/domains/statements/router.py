"""Statement discovery and account-level acceptance."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status

from nc3_testing_platform.core.enums import StatementResponseKind
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.security import CredentialRequired
from nc3_testing_platform.domains.statements.schemas import (
    Statement,
    StatementResponseReceipt,
    StatementResponseSubmission,
)

router = APIRouter(tags=["statements"])

_T0 = datetime(2026, 1, 15, tzinfo=UTC)
_STATEMENT_ID = UUID("019ee1a2-0011-7c22-8d33-4e55f6a77b88")
_PRIVACY_ID = UUID("019ee1a2-3344-7f55-b066-7b88c9aadbcc")
_RECEIPT_ID = UUID("019ee1a2-1122-7d33-9e44-5f66a7b88c99")


@router.get(
    "/statements",
    summary="List active statements",
    responses=problem_responses(500),
)
async def list_statements() -> list[Statement]:
    """Statements currently in force.

    Unauthenticated: a visitor has to be able to read the terms before there is an
    account to attach an acceptance to.
    """
    # Values mirror the statement rows the migrations seed (a9f2c4e6b8d0 +
    # d7e3f1a2b4c6): the provisionally adopted v3 texts, whose digests are the
    # SHA-256 of the canonical snapshots under docs/legal/. The DPO's v4
    # texts arrive as new version rows (Non-functional → GDPR).
    return [
        Statement(
            id=_STATEMENT_ID,
            statement_key="terms_and_conditions",
            version="2024-10",
            response_kind=StatementResponseKind.ACCEPTANCE,
            content_hash="sha256:6d80fb1d091c6aaeeb406150fd635976fffde54ad314aac373e7601f60a2c21a",
            content_uri="https://testing.nc3.lu/terms-conditions/",
            effective_at=datetime(2024, 10, 1, tzinfo=UTC),
        ),
        Statement(
            id=_PRIVACY_ID,
            statement_key="privacy_policy",
            version="2026-08-18",
            response_kind=StatementResponseKind.ACCEPTANCE,
            content_hash="sha256:04c03ecda8de1e039eba8fa3e5f428a631308008166b87ddb5b7e4cbfe9d4b56",
            content_uri="https://testing.nc3.lu/privacy/",
            effective_at=datetime(2026, 8, 18, tzinfo=UTC),
        ),
        Statement(
            id=UUID("019ee1a2-2233-7e44-af55-6a77b899cdaa"),
            statement_key="scan_target_permission",
            version="2026-01-15",
            response_kind=StatementResponseKind.ATTESTATION,
            required_context_type="scan_job",
            content_hash="sha256:7b0a3f6c5d8e1b4a7f0c3d6e9b2a5f8c1d4e7b0a3f6c5d8e1b4a7f2f8a1c9d4e",
            content_uri="https://testing.nc3.lu/legal/scan-permission/2026-01-15",
            effective_at=_T0,
        ),
    ]


@router.post(
    "/statement-responses",
    status_code=status.HTTP_201_CREATED,
    summary="Record an account-level response",
    responses=problem_responses(401, 404, 409, 422),
    dependencies=[CredentialRequired],
)
async def record_statement_response(
    body: StatementResponseSubmission,
) -> StatementResponseReceipt:
    """Record acceptance of an account-level statement.

    Rejects any statement that requires a context: a per-launch declaration is bound
    to the launch it belongs to and travels in the launch payload, so recording one
    here would produce a receipt attached to nothing.
    """
    return StatementResponseReceipt(
        id=_RECEIPT_ID,
        statement_id=_STATEMENT_ID,
        responded_at=datetime(2026, 7, 31, 9, 0, tzinfo=UTC),
    )
