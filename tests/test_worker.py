"""Smoke tests for the worker package: configuration only, no broker.

The Celery app must be importable and carry the US #78 ADR settings — the
compose stack takes both for granted. Task round trips need the real stack and
run there (`make scan`), not here.
"""

import pytest

from nc3_testing_platform.worker.app import app
from nc3_testing_platform.worker.preflight import REQUIRED_BINARIES, run_preflight
from nc3_testing_platform.worker.tasks import MOCK_MODULES


def test_adr_limits_are_set() -> None:
    """Soft limit, hard limit, and child recycling are all configured, coherently."""
    assert app.conf.task_soft_time_limit is not None
    assert app.conf.task_time_limit > app.conf.task_soft_time_limit
    assert app.conf.worker_max_tasks_per_child is not None


def test_every_task_routes_to_a_known_queue() -> None:
    """Each registered scan task is pinned to one of the egress queues."""
    routes = app.conf.task_routes
    scan_tasks = [name for name in app.tasks if name.startswith("scan.")]
    assert scan_tasks, "the scan tasks must be registered on import"
    for name in scan_tasks:
        assert routes[name]["queue"] in REQUIRED_BINARIES


def test_mock_modules_exist() -> None:
    """The fan-out has something to fan out to."""
    assert len(MOCK_MODULES) > 0


def test_preflight_rejects_unknown_queue() -> None:
    """A worker that cannot name its egress profile must not start."""
    with pytest.raises(SystemExit):
        run_preflight("")
    with pytest.raises(SystemExit):
        run_preflight("no-such-queue")


def test_preflight_accepts_queue_with_no_requirements() -> None:
    """The platform queue needs no external binaries and passes anywhere."""
    run_preflight("platform")


def test_preflight_rejects_missing_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """An image lacking a required binary must refuse to start."""
    monkeypatch.setitem(
        REQUIRED_BINARIES, "platform", ("binary-that-cannot-exist-anywhere",)
    )
    with pytest.raises(SystemExit):
        run_preflight("platform")


def test_preflight_rejects_binary_below_minimum_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A present binary older than its queue's floor must refuse to start."""
    from nc3_testing_platform.worker import preflight

    monkeypatch.setitem(REQUIRED_BINARIES, "platform", ("python3",))
    monkeypatch.setitem(preflight.MINIMUM_VERSIONS, "python3", (99, 0))
    with pytest.raises(SystemExit):
        run_preflight("platform")
