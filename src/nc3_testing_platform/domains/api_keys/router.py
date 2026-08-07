"""API key management.

Every operation here requires current MFA assurance, read from the OIDC token
at request time.
"""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status

from nc3_testing_platform.core.enums import ApiKeyScope
from nc3_testing_platform.core.errors import problem_responses
from nc3_testing_platform.core.pagination import CursorPage, Page
from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import Authenticated
from nc3_testing_platform.domains.api_keys.schemas import (
    ApiKey,
    ApiKeyCreate,
    ApiKeyCreated,
    ApiKeyRevoke,
)
from nc3_testing_platform.domains.scans.examples import ORGANIZATION_ID, USER_ID

router = APIRouter(
    prefix="/api-keys",
    tags=["api-keys"],
)

_KEY_ID = UUID("019ee1a8-0011-7a22-8b33-4c44d5e66f77")
_T = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)


def _sample_key(revoked: bool = False) -> ApiKey:
    return ApiKey(
        id=_KEY_ID,
        organization_id=ORGANIZATION_ID,
        owner_user_id=USER_ID,
        created_by_user_id=USER_ID,
        name="CI pipeline",
        scope=ApiKeyScope.FULL_SCAN,
        key_prefix="nc3_sk_live_7pL4",
        revoked_at=_T if revoked else None,
        revocation_reason="Rotated" if revoked else None,
        last_used_at=datetime(2026, 7, 31, 8, 55, tzinfo=UTC),
        created_at=_T,
    )


@router.get(
    "",
    summary="List API keys",
    responses=problem_responses(401, 403),
    dependencies=[Authenticated],
)
async def list_api_keys(page: CursorPage) -> Page[ApiKey]:
    """Keys visible to the caller: their own, plus organization keys.

    Revoked keys stay listed. A key that once had access is part of the record of
    who could reach what.
    """
    return Page(items=[_sample_key()], next_cursor=None)


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    summary="Create an API key",
    responses=problem_responses(401, 403, 422),
    dependencies=[Authenticated],
)
async def create_api_key(body: ApiKeyCreate) -> ApiKeyCreated:
    """Issue a key and return its secret once.

    Requires current MFA assurance. Creating an organization key additionally
    requires the `organization_admin` role.
    """
    return ApiKeyCreated(
        **_sample_key().model_dump(),
        secret="nc3_sk_live_7pL4vR8nT1mQ2xK9jH5gF3dS6aW0zY",
    )


@router.post(
    "/{key_id}/revoke",
    summary="Revoke an API key",
    responses=problem_responses(401, 403, 404, 409),
    dependencies=[Authenticated],
)
async def revoke_api_key(key_id: ResourceId, body: ApiKeyRevoke) -> ApiKey:
    """Stop a key working while keeping its row.

    A `POST` rather than a `DELETE`, because `revoked_at` and the reason are the
    point. Erasing an account also revokes and deletes that user's keys.
    """
    return _sample_key(revoked=True)
