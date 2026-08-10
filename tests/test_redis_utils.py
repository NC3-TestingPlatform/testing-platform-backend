"""The Redis primitives, against a fake and (marker-gated) the real thing.

Unit tests inject a ``FakeAsyncRedis`` through each primitive's ``client``
parameter — the module's single I/O seam — so no test here needs a service.
The one ``redis``-marked test runs the same round trips against a real Redis
named by ``REDIS_URL``; the default run deselects it (``-m "not redis"`` in
`pyproject.toml`), CI runs it against a service container.
"""

import os

import pytest
from fakeredis import FakeAsyncRedis

from nc3_testing_platform.core import redis_utils

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    """The suite runs async tests on asyncio only; trio is not installed."""
    return "asyncio"


@pytest.fixture
def fake() -> FakeAsyncRedis:
    """A fresh fake per test, so counters and challenges cannot leak across."""
    return FakeAsyncRedis(decode_responses=True)


async def test_consume_allows_until_the_limit(fake: FakeAsyncRedis) -> None:
    """Each request under the limit is allowed and decrements `remaining`."""
    for expected_remaining in (2, 1, 0):
        decision = await redis_utils.consume(
            "guest:203.0.113.7", limit=3, window_seconds=60, client=fake
        )
        assert decision.allowed
        assert decision.limit == 3
        assert decision.remaining == expected_remaining


async def test_consume_blocks_over_the_limit_and_reports_reset(
    fake: FakeAsyncRedis,
) -> None:
    """The request after the limit is refused; `reset_seconds` stays honest."""
    for _ in range(2):
        await redis_utils.consume("k", limit=2, window_seconds=60, client=fake)
    decision = await redis_utils.consume("k", limit=2, window_seconds=60, client=fake)
    assert not decision.allowed
    assert decision.remaining == 0
    assert 0 < decision.reset_seconds <= 60


async def test_consume_keys_are_independent_windows(fake: FakeAsyncRedis) -> None:
    """Exhausting one key must not touch another's quota."""
    await redis_utils.consume("a", limit=1, window_seconds=60, client=fake)
    exhausted = await redis_utils.consume("a", limit=1, window_seconds=60, client=fake)
    fresh = await redis_utils.consume("b", limit=1, window_seconds=60, client=fake)
    assert not exhausted.allowed
    assert fresh.allowed


async def test_consume_window_carries_the_first_requests_clock(
    fake: FakeAsyncRedis,
) -> None:
    """Later requests must not push the window's expiry forward (EXPIRE NX)."""
    await redis_utils.consume("k", limit=5, window_seconds=60, client=fake)
    ttl_after_first = await fake.ttl("ratelimit:k")
    await redis_utils.consume("k", limit=5, window_seconds=60, client=fake)
    assert await fake.ttl("ratelimit:k") <= ttl_after_first


async def test_challenge_round_trip_is_single_use(fake: FakeAsyncRedis) -> None:
    """Issue → verify returns the difficulty once; the second redemption fails."""
    challenge = await redis_utils.issue_challenge(
        "guest-launch", difficulty=4, ttl_seconds=120, client=fake
    )
    assert challenge.difficulty == 4
    assert len(challenge.nonce) == 32
    first = await redis_utils.verify_and_consume(
        "guest-launch", challenge.nonce, client=fake
    )
    second = await redis_utils.verify_and_consume(
        "guest-launch", challenge.nonce, client=fake
    )
    assert first == 4
    assert second is None


async def test_challenge_is_scope_bound_and_expiring(fake: FakeAsyncRedis) -> None:
    """A nonce redeems only in its scope, and the stored state carries a TTL."""
    challenge = await redis_utils.issue_challenge(
        "scope-a", difficulty=5, ttl_seconds=120, client=fake
    )
    assert 0 < await fake.ttl(f"pow:scope-a:{challenge.nonce}") <= 120
    wrong_scope = await redis_utils.verify_and_consume(
        "scope-b", challenge.nonce, client=fake
    )
    assert wrong_scope is None
    # The failed cross-scope attempt must not have consumed it.
    assert (
        await redis_utils.verify_and_consume("scope-a", challenge.nonce, client=fake)
        == 5
    )


async def test_unknown_challenge_is_none(fake: FakeAsyncRedis) -> None:
    """Unknown, expired, and consumed challenges are indistinguishable."""
    assert await redis_utils.verify_and_consume("s", "0" * 32, client=fake) is None


async def test_cache_round_trip_and_miss(fake: FakeAsyncRedis) -> None:
    """A stored document comes back equal; a miss is None; the entry expires."""
    document = {"grade": "A+", "findings": [1, 2, 3]}
    await redis_utils.set_json("report:xyz", document, ttl_seconds=30, client=fake)
    assert await redis_utils.get_json("report:xyz", client=fake) == document
    assert await redis_utils.get_json("report:absent", client=fake) is None
    assert 0 < await fake.ttl("cache:report:xyz") <= 30


@pytest.mark.redis
async def test_round_trips_against_real_redis() -> None:
    """The same behaviours hold on a real server (fakeredis-drift guard)."""
    url = os.getenv("REDIS_URL")
    if not url:
        pytest.skip("REDIS_URL not set")
    from redis.asyncio import Redis

    client = Redis.from_url(url, decode_responses=True)
    try:
        key = "ci-smoke"
        await client.delete(f"ratelimit:{key}")
        allowed = await redis_utils.consume(
            key, limit=2, window_seconds=30, client=client
        )
        assert allowed.allowed and allowed.remaining == 1

        challenge = await redis_utils.issue_challenge(
            "ci", difficulty=4, ttl_seconds=30, client=client
        )
        assert (
            await redis_utils.verify_and_consume("ci", challenge.nonce, client=client)
            == 4
        )
        assert (
            await redis_utils.verify_and_consume("ci", challenge.nonce, client=client)
            is None
        )

        await redis_utils.set_json("ci", {"ok": True}, ttl_seconds=30, client=client)
        assert await redis_utils.get_json("ci", client=client) == {"ok": True}
    finally:
        await client.aclose()
