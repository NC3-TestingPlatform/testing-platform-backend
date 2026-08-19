"""Anti-abuse gates on the assets domain (B6a / US #82).

Keyed on `(organization, asset)` rather than client IP: every operation here is
authenticated, so an IP says nothing useful about who is spending the budget,
and a shared office NAT would penalise colleagues for each other's retries.

This bounds a cheap operation — one upsert, no network. It is **not** a bound on
the DNS check, which B6b adds: that one needs a hard concurrency limit and a
platform-wide cap, because the per-organization budget below divides by the
number of organizations an attacker registers, and registration is free.
"""

from fastapi import Depends

from nc3_testing_platform.core.schemas import ResourceId
from nc3_testing_platform.core.security import CurrentSession, enforce_rate_limit
from nc3_testing_platform.core.settings import settings


async def challenge_rate_limit(
    asset_id: ResourceId, current: CurrentSession
) -> None:
    """Per-(organization, asset) window on issuing or replacing a challenge."""
    await enforce_rate_limit(
        f"assets:verification:{current.organization_id}:{asset_id}",
        limit=settings.verification_challenge_rate_limit,
        window_seconds=settings.verification_challenge_rate_window_seconds,
    )


# Attach as `dependencies=[ChallengeRateLimited]` on a challenge-writing operation.
ChallengeRateLimited = Depends(challenge_rate_limit)
