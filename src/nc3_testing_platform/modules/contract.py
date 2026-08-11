"""The scan-module contract: what every plug-in declares, accepts, and returns.

This is the SDK of US #76. A module story implements exactly four things —
a :class:`ModuleDescriptor`, a :class:`TestModule`, a severity hook, and an
entry point — and the platform owns everything else: routing (from the
declaration, never from the module at runtime — egress ADR), persistence
(`ScanResult`/`Finding` rows), and event delivery. The vocabulary is
`core.enums` throughout; the contract adds no status or severity enums of
its own.

Execution follows the egress-queues ADR: every engine call goes through the
shared runner in `modules.execution`, which imports the engine in a
**killable child process**, calls its `assess()` (import-as-library — no
CLI shelling), enforces a wall-clock budget of its own, and marshals
progress lines and the report back over a pipe. The report crosses the
boundary as a `dataclasses.asdict()` dict, never as a pickled engine
object. Nothing here assumes a worker pool: the runner is the engine bound
under prefork and gevent alike, and Celery time limits are a backstop, not
the mechanism.
"""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from logging import getLogger
from types import MappingProxyType
from typing import Any, Protocol, runtime_checkable

from nc3_testing_platform.core.enums import (
    FindingSeverity,
    ScanClassification,
    ScanGrade,
    ScanModule,
)

logger = getLogger(__name__)

# The egress queues a module may declare, keyed by the classification that
# implies each. The names are the ones `worker/app.py` routes and
# `worker/preflight.py` validates; a drift test asserts they stay identical.
# `platform` is deliberately absent: orchestration tasks live there, modules
# never do.
QUEUE_BY_CLASSIFICATION: Mapping[ScanClassification, str] = {
    ScanClassification.NON_INTRUSIVE: "non-intrusive-scan",
    ScanClassification.INTRUSIVE: "intrusive-scan",
    ScanClassification.NOT_APPLICABLE: "file-analysis",
}

MODULE_QUEUES = frozenset(QUEUE_BY_CLASSIFICATION.values())

# `test_key` is namespaced text, not an enum (data model): lowercase segments
# joined by dots, at least two of them, e.g. `dnssec.chainvalidator`.
_TEST_KEY_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")


@dataclass(frozen=True)
class TestDeclaration:
    """One executable test a module implements, as the roster declares it.

    `test_key` and `test_version` are copied verbatim onto every `ScanTask`
    row the platform creates for this test; `check_id` regression matching
    and result-schema versioning both hang off them, so a change to either
    is a contract change, not a detail.
    """

    test_key: str
    test_version: str

    def __post_init__(self) -> None:
        if not _TEST_KEY_RE.fullmatch(self.test_key):
            raise ValueError(
                f"test_key {self.test_key!r} is not namespaced text of the form "
                "'<module>.<name>' (lowercase segments joined by dots)."
            )
        if not self.test_version:
            raise ValueError(f"test {self.test_key!r} declares an empty test_version.")


@dataclass(frozen=True)
class ModuleDescriptor:
    """A module's roster entry: everything the platform knows without running it.

    The descriptor is a *declaration*. The API routes a task to `queue` at
    enqueue time by reading it here, and a worker consuming a queue refuses a
    task whose module is not on that queue's roster — a module never chooses
    its own queue at runtime (egress-segregated task queues ADR).
    """

    name: ScanModule
    classification: ScanClassification
    queue: str
    engine: str
    engine_version: str
    tests: tuple[TestDeclaration, ...]

    def __post_init__(self) -> None:
        expected_queue = QUEUE_BY_CLASSIFICATION[self.classification]
        if self.queue != expected_queue:
            raise ValueError(
                f"module {self.name.value!r} declares queue {self.queue!r}, but a "
                f"{self.classification.value} module belongs on {expected_queue!r}."
            )
        if not self.engine or not self.engine_version:
            raise ValueError(
                f"module {self.name.value!r} must declare the engine package and "
                "version it wraps."
            )
        if not self.tests:
            raise ValueError(
                f"module {self.name.value!r} declares no executable tests."
            )
        keys = [test.test_key for test in self.tests]
        if len(set(keys)) != len(keys):
            raise ValueError(
                f"module {self.name.value!r} declares duplicate test keys."
            )
        prefix = f"{self.name.value}."
        for key in keys:
            if not key.startswith(prefix):
                raise ValueError(
                    f"test_key {key!r} does not carry its module's namespace "
                    f"{prefix!r} (catalog convention: '<module>.<name>')."
                )


@dataclass(frozen=True)
class ScanInput:
    """What one task hands a module: a concrete target, options, a timeout.

    Exactly one of `target_domain` and `file_path` is set, mirroring the
    `one_task_target` rule on the `scan_task` row. The platform resolves the
    launch contract's union before building this — a `target_asset_id`
    becomes its domain, a `file_upload_id` becomes a local path the worker
    fetched — because a module never touches the database or object storage.

    `options` carries the task's `configuration` JSONB verbatim; each module
    documents the keys it honors and ignores the rest. `timeout` is a float
    in seconds (engine convention), passed through to the engine's own
    ``timeout`` parameter — the per-probe network timeout. The wall-clock
    budget that kills an overrunning engine is separate and platform-owned:
    the module's runner hands it to `execution.run_engine`.
    """

    target_domain: str | None = None
    file_path: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)
    timeout: float = 30.0

    def __post_init__(self) -> None:
        targets = (self.target_domain, self.file_path)
        if sum(value is not None for value in targets) != 1:
            raise ValueError(
                "Exactly one of `target_domain` and `file_path` is set."
            )
        if isinstance(self.timeout, bool) or not isinstance(
            self.timeout, (int, float)
        ):
            raise ValueError("`timeout` is a float in seconds.")
        if self.timeout <= 0:
            raise ValueError("`timeout` must be positive.")
        # "frozen" protects the attribute, not the dict it points at; copy and
        # freeze so a module cannot mutate one caller's options under another.
        object.__setattr__(self, "options", MappingProxyType(dict(self.options)))


@dataclass(frozen=True)
class NormalizedFinding:
    """One diagnostic outcome, in the shape the `finding` row persists.

    `check_id` is the stable rule identifier regression matching keys on;
    renaming one is a breaking result-schema change. `status` (new,
    regression, …) is deliberately absent: the platform derives it from
    history at result time, a module cannot know it.
    """

    check_id: str
    severity: FindingSeverity
    title: str
    description: str
    affected_resource: str | None = None
    remediation: str | None = None
    evidence: Mapping[str, Any] | None = None
    external_references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.check_id:
            raise ValueError("A finding must carry a stable, non-empty check_id.")
        if not self.title:
            raise ValueError(f"finding {self.check_id!r} has an empty title.")
        if self.evidence is not None:
            object.__setattr__(
                self, "evidence", MappingProxyType(dict(self.evidence))
            )


@dataclass(frozen=True)
class ModuleResult:
    """What one run returns, in the shape the `scan_result` row persists.

    `raw_output` is the engine report as it crossed the process boundary —
    the `dataclasses.asdict()` dict the runner marshalled — so nothing is
    lost to normalization; `findings` is the normalized view of the same
    run. `schema_version` names the module's result schema, not the engine
    version — bump it when `raw_output` or the `check_id` vocabulary changes
    shape. `grade` stays ``None`` for modules whose catalog entry does not
    grade.
    """

    schema_version: str
    raw_output: Mapping[str, Any]
    summary: Mapping[str, Any] = field(default_factory=dict)
    findings: tuple[NormalizedFinding, ...] = ()
    grade: ScanGrade | None = None

    def __post_init__(self) -> None:
        if not self.schema_version:
            raise ValueError("A result must name its schema_version.")
        object.__setattr__(self, "raw_output", MappingProxyType(dict(self.raw_output)))
        object.__setattr__(self, "summary", MappingProxyType(dict(self.summary)))


@dataclass(frozen=True)
class ProgressEvent:
    """One advisory progress line from a running module.

    Advisory in the same sense as the SSE stream: database state stays
    authoritative, these only reduce latency. `channel` is ``progress`` for
    the engines' standard `progress_cb` and names the callback for anything
    extra a chattier engine offers (``debug``, ``cmd``, ``finish`` …).
    """

    test_key: str
    message: str
    channel: str = "progress"


@dataclass(frozen=True)
class ProgressEmitter:
    """The parent-side delivery point for a module's progress.

    The runner constructs one per task. Engine callbacks never touch it
    directly — the engine runs in a child process, where `execution` injects
    pipe-writing callbacks that mirror these signatures; each marshalled
    line is re-emitted here, parent-side, as a :class:`ProgressEvent` to
    `sink`. The worker wires `sink` to task state; without one, events go to
    the module logger and are not lost.

    The methods stay public because they *are* the callback shapes:
    `progress_cb` matches the `Callable[[str], None]` every engine's
    `assess()` accepts, and :meth:`extra_cb` manufactures a callback of any
    arity for engines that offer more (subdomainenum's ``debug_cb(tool,
    line)``, ``finish_cb(tool, result, ok)`` …), so no engine signature can
    break the contract. A module that narrates its own steps outside the
    engine call uses them in-process the same way.
    """

    test_key: str
    sink: Callable[[ProgressEvent], None] | None = None

    def emit(self, message: str, *, channel: str = "progress") -> None:
        """Deliver one event to the sink, or log it when no sink is wired."""
        event = ProgressEvent(test_key=self.test_key, message=message, channel=channel)
        if self.sink is None:
            logger.info("%s [%s] %s", event.test_key, event.channel, event.message)
            return
        self.sink(event)

    def progress_cb(self, message: str) -> None:
        """The standard engine callback: one short status string per step."""
        self.emit(message)

    def extra_cb(self, channel: str) -> Callable[..., None]:
        """A tolerant callback for one named extra channel, whatever its arity.

        Positional arguments are stringified and joined; ``None`` arguments
        are dropped rather than rendered, so ``finish_cb("ffuf", None, True)``
        stays readable.
        """

        def _callback(*args: object) -> None:
            rendered = " ".join(str(arg) for arg in args if arg is not None)
            self.emit(rendered or channel, channel=channel)

        return _callback


def map_engine_severity(engine_severity: str) -> FindingSeverity:
    """The default severity hook: engine `VerdictSeverity` name → platform value.

    The engines' five-tier vocabulary (CRITICAL, HIGH, MEDIUM, LOW, INFO)
    maps 1:1 onto :class:`FindingSeverity`, so the default is a case-blind
    rename. It stays an explicit per-module hook (`TestModule.map_severity`)
    because the 1:1 is an observation about today's engines, not a law; a
    module that needs to re-rank overrides the hook, everyone else delegates
    here. Unknown input raises rather than guessing a severity.
    """
    try:
        return FindingSeverity(engine_severity.strip().lower())
    except ValueError:
        raise ValueError(
            f"engine severity {engine_severity!r} has no FindingSeverity "
            "equivalent; the module must map it explicitly."
        ) from None


@runtime_checkable
class TestModule(Protocol):
    """The interface a module entry point resolves to.

    Structural, not inherited: implement the three members and the registry's
    `isinstance` check passes. `run` is synchronous and self-contained —
    everything it needs arrives in the input, and the engine work inside it
    goes through `execution.run_engine`, so the engine runs in a killable
    child no matter which pool the worker uses.
    """

    @property
    def descriptor(self) -> ModuleDescriptor:
        """The roster declaration for this module."""
        ...

    def run(self, scan_input: ScanInput, *, progress: ProgressEmitter) -> ModuleResult:
        """Execute one task: run the engine via the shared runner, normalize.

        Raise `ValueError` for input the module cannot accept; any other
        exception marks the task failed with the exception as the reason.
        """
        ...

    def map_severity(self, engine_severity: str) -> FindingSeverity:
        """Map one engine severity onto the platform vocabulary."""
        ...


@runtime_checkable
class ReportContribution(Protocol):
    """The report hook a module *may* implement; rendering is R1a's, not ours.

    Signature-only in this US: R1a consumes it when report generation lands.
    A module that implements it returns the fragments (tables, prose keys,
    chart series) the report composer may use; one that does not is reported
    from its normalized findings alone.
    """

    def contribute(self, result: ModuleResult) -> Mapping[str, Any]:
        """Return report fragments for one result, keyed by fragment name."""
        ...
