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
    # d7e3f1a2b4c6): the platform's adapted v3 texts, whose digests are the
    # SHA-256 of the canonical files under docs/legal/ (content_uri points
    # there). The DPO's v4 texts arrive as new version rows.
    return [
        Statement(
            id=_STATEMENT_ID,
            statement_key="terms_and_conditions",
            version="2026-08-18",
            response_kind=StatementResponseKind.ACCEPTANCE,
            content_hash="sha256:3cbaf4702d67aab5b7d57e9f77cd9e3087df9a4a69714fd23ce041abcb075b74",
            content_uri="https://github.com/NC3-TestingPlatform/testing-platform-backend/blob/fd0926985b6343c040a92a91c00ef3e63d804518/docs/legal/terms-of-service-2026-08-18.md",
            effective_at=datetime(2026, 8, 18, tzinfo=UTC),
        ),
        Statement(
            id=_PRIVACY_ID,
            statement_key="privacy_policy",
            version="2026-08-18",
            response_kind=StatementResponseKind.ACCEPTANCE,
            content_hash="sha256:0560cefecd67a08c81784b68f7644e36c5d897d36c559691ecaf9a5e6de5a0c0",
            content_uri="https://github.com/NC3-TestingPlatform/testing-platform-backend/blob/fd0926985b6343c040a92a91c00ef3e63d804518/docs/legal/privacy-statement-2026-08-18.md",
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
