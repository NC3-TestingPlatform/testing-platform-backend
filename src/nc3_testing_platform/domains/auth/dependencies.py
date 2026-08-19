"""Anti-abuse gates on the anonymous auth operations (B3 / US #79).

Per-IP fixed-window counters on the delivered Redis primitive
(`core/redis_utils.py`). Deliberately fail-open: if Redis is unreachable the
request proceeds with a logged warning — login availability beats one
rate-limit layer, and the durable per-account lockout (`domains/auth/service`)
stands on its own. The adaptive PoW/CAPTCHA escalation on top is B10's.
"""

import logging

from fastapi import Depends, HTTPException, Request, status

from nc3_testing_platform.core import redis_utils
from nc3_testing_platform.core.settings import settings

logger = logging.getLogger("nc3_testing_platform.domains.auth")


def _client_ip(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


async def _consume_or_429(key: str, *, limit: int, window_seconds: int) -> None:
    try:
        decision = await redis_utils.consume(
            key, limit=limit, window_seconds=window_seconds
        )
    except Exception:
        logger.warning(
            "rate-limit backend unavailable; failing open for %s", key,
            exc_info=True,
        )
        return
    if decision.allowed:
        return
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many requests; retry after the window resets.",
        headers={
            "RateLimit": (
                f"limit={decision.limit}, remaining={decision.remaining}, "
                f"reset={decision.reset_seconds}"
            ),
            "RateLimit-Policy": f"{decision.limit};w={window_seconds}",
            "Retry-After": str(decision.reset_seconds),
        },
    )


async def login_rate_limit(request: Request) -> None:
    """Per-IP window on `POST /auth/login`."""
    await _consume_or_429(
        f"auth:login:{_client_ip(request)}",
        limit=settings.auth_login_rate_limit,
        window_seconds=settings.auth_login_rate_window_seconds,
    )


async def register_rate_limit(request: Request) -> None:
    """Per-IP window on `POST /auth/register`."""
    await _consume_or_429(
        f"auth:register:{_client_ip(request)}",
        limit=settings.auth_register_rate_limit,
        window_seconds=settings.auth_register_rate_window_seconds,
    )


async def mfa_verify_rate_limit(request: Request) -> None:
    """Per-IP window on `POST /auth/mfa/verify`.

    Tighter than the login window: the code space is six digits. The third
    guessable auth window — part of B10's PoW/CAPTCHA escalation surface.
    The per-account escalating lockout (`domains/auth/service`) is the
    control that must hold; this fail-open layer only blunts single-IP runs.
    """
    await _consume_or_429(
        f"auth:mfa:{_client_ip(request)}",
        limit=settings.auth_mfa_verify_rate_limit,
        window_seconds=settings.auth_mfa_verify_rate_window_seconds,
    )


LoginRateLimited = Depends(login_rate_limit)
RegisterRateLimited = Depends(register_rate_limit)
MfaVerifyRateLimited = Depends(mfa_verify_rate_limit)
