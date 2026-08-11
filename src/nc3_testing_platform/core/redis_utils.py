"""Redis primitives: client factory, rate-limit counters, PoW challenge state, cache.

The application's sole Redis I/O boundary, in the same style as the worker's
service access — everything that talks to Redis lives here, so tests mock (or
fake) exactly one module. Nothing here is wired into a route yet; the intended
consumers are:

* rate-limit counters → the anti-abuse gates on quota-bearing operations,
  whose responses carry ``RATE_LIMIT_HEADERS`` (`core/security.py`) — their
  own story wires them;
* PoW challenge state → the anti-abuse subsystem's proof-of-work gate on
  anonymous launches (system boundary per data-model §1.2). The PoW
  *algorithm* is presentation-layer and stays out; this is only the state;
* cache helpers → response caching for the read-heavy public surfaces;
* the client factory → also the future deep `/readyz` dependency probe.

Counters and challenges are state whose loss costs one extra request, matching
the compose stack's persistence-off Redis (`infra/compose/redis.yml`).
"""

import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from nc3_testing_platform.core.settings import settings

_client: Redis | None = None


def get_client() -> Redis:
    """The process-wide client, created lazily from ``settings.redis_url``.

    Lazy so importing this module costs nothing in processes that never touch
    Redis; process-wide because the client owns a connection pool and one pool
    per process is the point of having one.
    """
    global _client
    if _client is None:
        _client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _client


async def close_client() -> None:
    """Release the pool; for the application's lifespan shutdown hook."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


@dataclass(frozen=True)
class RateLimitDecision:
    """One consume's verdict, in the vocabulary of ``RATE_LIMIT_HEADERS``.

    ``limit``/``remaining``/``reset_seconds`` map onto the IETF-draft
    ``RateLimit: limit=…, remaining=…, reset=…`` fields the contract already
    declares on quota-bearing responses.
    """

    allowed: bool
    limit: int
    remaining: int
    reset_seconds: int


async def consume(
    key: str,
    *,
    limit: int,
    window_seconds: int,
    client: Redis | None = None,
) -> RateLimitDecision:
    """Count one request against ``key``'s window and decide.

    INCR + EXPIRE-if-unset in one transaction: the first request of a window
    starts its clock, every request increments, and the count dies with the
    window. The count keeps incrementing past the limit so ``reset_seconds``
    stays honest for a caller that keeps hammering.
    """
    con = client if client is not None else get_client()
    async with con.pipeline(transaction=True) as pipe:
        pipe.incr(f"ratelimit:{key}")
        pipe.expire(f"ratelimit:{key}", window_seconds, nx=True)
        pipe.ttl(f"ratelimit:{key}")
        count, _, ttl = await pipe.execute()
    return RateLimitDecision(
        allowed=count <= limit,
        limit=limit,
        remaining=max(0, limit - count),
        reset_seconds=max(0, ttl),
    )


# What issue_challenge emits: secrets.token_hex(16). Anything else is rejected
# before it can reach a key — a `:` smuggled into the nonce would otherwise let
# scope "a" redeem a challenge issued for scope "a:b".
_NONCE_RE = re.compile(r"[0-9a-f]{32}")


@dataclass(frozen=True)
class PowChallenge:
    """An issued proof-of-work challenge: what the client gets to solve."""

    nonce: str
    difficulty: int
    ttl_seconds: int


async def issue_challenge(
    scope: str,
    *,
    difficulty: int,
    ttl_seconds: int,
    client: Redis | None = None,
) -> PowChallenge:
    """Issue a single-use challenge under ``scope``, stored under TTL.

    The nonce is unguessable (128 bits), so possession of a solvable challenge
    proves it was issued here and has not expired.
    """
    con = client if client is not None else get_client()
    nonce = secrets.token_hex(16)
    await con.set(f"pow:{scope}:{nonce}", difficulty, ex=ttl_seconds)
    return PowChallenge(nonce=nonce, difficulty=difficulty, ttl_seconds=ttl_seconds)


async def verify_and_consume(
    scope: str,
    nonce: str,
    *,
    client: Redis | None = None,
) -> int | None:
    """Redeem a challenge exactly once.

    GETDEL makes consumption atomic: two concurrent redemptions of one nonce
    cannot both succeed. Returns the stored difficulty (the caller still
    checks the solution against it), or ``None`` for an unknown, expired, or
    already-consumed challenge — the three are deliberately indistinguishable
    (and so is a malformed nonce, rejected before it can touch a key).
    """
    if _NONCE_RE.fullmatch(nonce) is None:
        return None
    con = client if client is not None else get_client()
    value = await con.getdel(f"pow:{scope}:{nonce}")
    return None if value is None else int(value)


async def get_json(key: str, *, client: Redis | None = None) -> Any | None:
    """The cached document under ``key``, or ``None`` on a miss."""
    con = client if client is not None else get_client()
    raw = await con.get(f"cache:{key}")
    return None if raw is None else json.loads(raw)


async def set_json(
    key: str,
    value: Any,
    *,
    ttl_seconds: int,
    client: Redis | None = None,
) -> None:
    """Cache a JSON-serialisable document under ``key`` for ``ttl_seconds``.

    TTL is mandatory: an unexpiring cache entry in a persistence-off Redis is
    a memory leak with extra steps.
    """
    con = client if client is not None else get_client()
    await con.set(f"cache:{key}", json.dumps(value), ex=ttl_seconds)
