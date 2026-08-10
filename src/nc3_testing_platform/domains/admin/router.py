"""Platform-administration operations.

Gated on the platform-administrator claim from the identity provider, which is independent of
any organization role — an organization administrator has no access here.
"""

from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Query

from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import CredentialRequired
from nc3_testing_platform.domains.admin.schemas import AuditEvent
from nc3_testing_platform.domains.scans.examples import ASSET_ID, ORGANIZATION_ID

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
)

_EVENT_ID = UUID("019ee1a9-0011-7a22-8b33-4c44d5e66f77")


@router.get(
    "/audit-events",
    summary="Read the audit log",
    responses=problem_responses(401, 403),
    dependencies=[CredentialRequired],
)
async def list_audit_events(
    page: CursorPage,
    chain_id: Annotated[str | None, Query(description="Restrict to one chain.")] = None,
    organization_id: Annotated[
        ResourceId | None, Query(description="Restrict to one organization's chain.")
    ] = None,
    event_type: Annotated[
        str | None, Query(description="Exact namespaced event type.")
    ] = None,
    occurred_after: Annotated[
        datetime | None, Query(description="Inclusive lower bound on `occurred_at`.")
    ] = None,
    occurred_before: Annotated[
        datetime | None, Query(description="Exclusive upper bound on `occurred_at`.")
    ] = None,
) -> Page[AuditEvent]:
    """Audit entries in chain order.

    Ordered by (`chain_id`, `sequence_number`) rather than by time, because that
    pair is what defines the hash chain — reading in timestamp order would not let
    a verifier follow `previous_hash` from one entry to the next.

    Encrypted payloads are returned as ciphertext. Decryption is a separate operator
    procedure and is not exposed by v4.0.
    """
    return Page(
        items=[
            AuditEvent(
                id=_EVENT_ID,
                organization_id=ORGANIZATION_ID,
                chain_id=f"org:{ORGANIZATION_ID}",
                sequence_number=4712,
                event_type="asset.verification.succeeded",
                subject_type="asset",
                subject_id=ASSET_ID,
                detail={"verified_scope": "zone", "attempt": 2},
                occurred_at=datetime(2026, 7, 31, 8, 30, tzinfo=UTC),
                previous_hash="sha256:1b4a7f0c3d6e9b2a5f8c1d4e7b0a3f6c5d8e1b4a7f0c3d6e",
                entry_hash="sha256:9b2a5f8c1d4e7b0a3f6c5d8e1b4a7f0c3d6e9b2a5f8c1d4e",
                retention_until=datetime(2028, 7, 31, 8, 30, tzinfo=UTC),
            )
        ],
        next_cursor=None,
    )
