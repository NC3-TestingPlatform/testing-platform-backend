"""Anti-abuse gates on the assets domain (B6a / US #82).

Keyed on `(organization, asset)` rather than client IP: every operation here is
authenticated, so an IP says nothing useful about who is spending the budget,
and a shared office NAT would penalise colleagues for each other's retries.

`challenge_rate_limit` bounds a cheap operation — one upsert, no network. The
check is the expensive one, so it carries three windows, narrowest last: a
platform-wide cap, a per-organization cap, and a per-asset window.

**None of them is the load-bearing bound.** `enforce_rate_limit` is deliberately
fail-open, so all three vanish the moment Redis does, which is exactly when the
platform is already degraded. What holds without Redis lives in
`core/dns_utils.py` and refuses rather than queues: the non-blocking semaphore
caps concurrent queries, and a process-local fixed window caps the outbound query
rate — a concurrency cap alone bounds nothing when resolvers answer fast. That
window is derived from `verification_global_rate_limit` rather than a knob of its
own, so the two cannot drift and it sits under this one instead of competing with
it. These windows shape ordinary use; the DNS boundary is what survives a bad day.

The global cap exists because every per-organization budget divides by the number
of organizations an attacker registers, and registration is free and instant. The
per-organization cap exists because a single global key is otherwise shared fate:
one tenant could spend the whole platform budget and deny verification to
everyone else, more cheaply than the abuse the cap prevents.
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


async def global_verification_cap() -> None:
    """Platform-wide ceiling on outbound verification queries, keyed on nothing.

    Deliberately independent of the caller: this is the only bound that does not
    divide by the number of accounts an attacker creates. It also bounds what the
    platform can inflict on third-party resolvers and authoritative servers, which
    is somebody else's infrastructure.
    """
    await enforce_rate_limit(
        "assets:verification:checks:global",
        limit=settings.verification_global_rate_limit,
        window_seconds=settings.verification_global_rate_window_seconds,
    )


async def org_verification_cap(current: CurrentSession) -> None:
    """Per-organization share of the global budget, so one tenant cannot take it all."""
    await enforce_rate_limit(
        f"assets:verification:checks:org:{current.organization_id}",
        limit=settings.verification_org_rate_limit,
        window_seconds=settings.verification_org_rate_window_seconds,
    )


async def check_rate_limit(asset_id: ResourceId, current: CurrentSession) -> None:
    """Per-(organization, asset) window on running the DNS check."""
    await enforce_rate_limit(
        f"assets:verification:checks:{current.organization_id}:{asset_id}",
        limit=settings.verification_check_rate_limit,
        window_seconds=settings.verification_check_rate_window_seconds,
    )


# Attach in this order on the check operation: broadest budget first, so a
# platform-wide flood is refused before it costs a per-asset lookup.
GlobalVerificationCapped = Depends(global_verification_cap)
OrgVerificationCapped = Depends(org_verification_cap)
CheckRateLimited = Depends(check_rate_limit)
