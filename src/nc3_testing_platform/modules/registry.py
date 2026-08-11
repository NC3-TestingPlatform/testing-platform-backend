"""Entry-point discovery and the validated module roster.

Modules are found, never imported by name: each one registers under the
``nc3_testing_platform.modules`` entry-point group, and everything the
platform knows about the plug-in population comes from loading that group.
That indirection is what keeps the M* module stories core-touchless — a new
module is a new package (or a new entry in this one's `pyproject.toml`) and
zero edited core files (IDR-007, task #168).

Failure here is loud and total, in the spirit of `worker/preflight.py`: a
roster with a broken entry point, an impostor object, or two claimants to
one `test_key` raises :class:`ModuleRegistryError` instead of skipping the
offender — a silently thinner roster produces scans that look complete and
are not.
"""

from dataclasses import dataclass
from importlib import metadata

from nc3_testing_platform.modules.contract import TestModule

ENTRY_POINT_GROUP = "nc3_testing_platform.modules"


class ModuleRegistryError(Exception):
    """The module roster is unusable; the message names the offender."""


@dataclass(frozen=True)
class LoadedModule:
    """One discovered module: its entry-point name and its implementation."""

    entry_point: str
    implementation: TestModule


@dataclass(frozen=True)
class Roster:
    """The validated plug-in population, with the two lookups the platform does.

    The API asks :meth:`queue_for` at enqueue time to route a task from the
    module's declaration; a worker asks :meth:`require` to refuse a task that
    reached the wrong queue. Both are keyed by `test_key`, the identifier the
    `scan_task` row carries.
    """

    entries: tuple[LoadedModule, ...]

    def by_test_key(self, test_key: str) -> LoadedModule:
        """The module implementing `test_key`, or a loud refusal."""
        for entry in self.entries:
            tests = entry.implementation.descriptor.tests
            if any(test.test_key == test_key for test in tests):
                return entry
        raise ModuleRegistryError(
            f"no registered module implements test_key {test_key!r}."
        )

    def for_queue(self, queue: str) -> tuple[LoadedModule, ...]:
        """Every module whose declaration routes to `queue`."""
        return tuple(
            entry
            for entry in self.entries
            if entry.implementation.descriptor.queue == queue
        )

    def queue_for(self, test_key: str) -> str:
        """The egress queue `test_key` is routed to — read from the declaration."""
        return self.by_test_key(test_key).implementation.descriptor.queue

    def require(self, test_key: str, *, queue: str) -> LoadedModule:
        """The worker-side gate: resolve `test_key`, refusing an off-queue task.

        A worker consumes exactly one queue (its egress profile); a task
        whose module declares a different queue was mis-routed and must fail
        here rather than run with the wrong egress (egress ADR).
        """
        entry = self.by_test_key(test_key)
        declared = entry.implementation.descriptor.queue
        if declared != queue:
            raise ModuleRegistryError(
                f"test_key {test_key!r} declares queue {declared!r} and must not "
                f"run on {queue!r}."
            )
        return entry


def discover(
    *, entry_points: tuple[metadata.EntryPoint, ...] | None = None
) -> Roster:
    """Load and validate the entry-point group into a :class:`Roster`.

    `entry_points` exists for tests, which hand in synthetic entries; the
    default reads the installed distribution metadata. Every entry must load,
    must satisfy the :class:`TestModule` protocol, and must not collide with
    another entry on entry-point name or on any declared `test_key` —
    otherwise the whole discovery fails.
    """
    found = (
        entry_points
        if entry_points is not None
        else tuple(metadata.entry_points(group=ENTRY_POINT_GROUP))
    )
    entries: list[LoadedModule] = []
    seen_names: set[str] = set()
    seen_test_keys: dict[str, str] = {}
    for entry_point in found:
        if entry_point.name in seen_names:
            raise ModuleRegistryError(
                f"entry point {entry_point.name!r} is registered twice in "
                f"group {ENTRY_POINT_GROUP!r}."
            )
        seen_names.add(entry_point.name)
        try:
            implementation = entry_point.load()
        except Exception as exc:
            raise ModuleRegistryError(
                f"entry point {entry_point.name!r} ({entry_point.value}) failed "
                f"to load: {exc}"
            ) from exc
        if not isinstance(implementation, TestModule):
            raise ModuleRegistryError(
                f"entry point {entry_point.name!r} resolved to "
                f"{type(implementation).__name__!r}, which does not implement "
                "the TestModule protocol (descriptor / run / map_severity)."
            )
        for test in implementation.descriptor.tests:
            claimant = seen_test_keys.get(test.test_key)
            if claimant is not None:
                raise ModuleRegistryError(
                    f"test_key {test.test_key!r} is declared by both "
                    f"{claimant!r} and {entry_point.name!r}."
                )
            seen_test_keys[test.test_key] = entry_point.name
        entries.append(
            LoadedModule(entry_point=entry_point.name, implementation=implementation)
        )
    return Roster(entries=tuple(entries))
