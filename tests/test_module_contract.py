"""Contract tests for the scan-module SDK (US #76).

Structural, like `test_models.py`: descriptors, registry discovery, input
validation, the severity hook, progress marshalling, and the child-process
runner are all exercised without a broker, a database, or the network. The
conformance block at the bottom is parametrized so every future module
(the dnssec exemplar first) runs the same suite the noop passes.
"""

import ast
import json
import logging
import os
import signal
import tempfile
import time
from importlib.metadata import EntryPoint
from pathlib import Path

import pytest

from nc3_testing_platform.core.enums import (
    FindingSeverity,
    ScanClassification,
    ScanModule,
)
from nc3_testing_platform.modules import contract, execution, noop, registry
from nc3_testing_platform.modules.noop import engine as noop_engine
from nc3_testing_platform.worker.preflight import REQUIRED_BINARIES

SRC_ROOT = Path(__file__).resolve().parent.parent / "src" / "nc3_testing_platform"

NOOP_ENGINE_ENTRY = "nc3_testing_platform.modules.noop.engine:assess"


def _descriptor(**overrides: object) -> contract.ModuleDescriptor:
    """A valid descriptor, with per-test field overrides."""
    fields: dict = {
        "name": ScanModule.WEB,
        "classification": ScanClassification.NON_INTRUSIVE,
        "queue": "non-intrusive-scan",
        "engine": "builtin",
        "engine_version": "0",
        "tests": (
            contract.TestDeclaration(test_key="web.noop", test_version="1.0.0"),
        ),
    }
    fields.update(overrides)
    return contract.ModuleDescriptor(**fields)


class _RecordingSink:
    """Collects emitted progress events for assertions."""

    def __init__(self) -> None:
        self.events: list[contract.ProgressEvent] = []

    def __call__(self, event: contract.ProgressEvent) -> None:
        self.events.append(event)


# --- descriptor and test declarations ---------------------------------------


def test_descriptor_accepts_a_valid_declaration() -> None:
    """The noop-shaped declaration is the reference for a valid descriptor."""
    descriptor = _descriptor()
    assert descriptor.queue in contract.MODULE_QUEUES


def test_descriptor_rejects_queue_classification_mismatch() -> None:
    """A non-intrusive module cannot declare the intrusive queue."""
    with pytest.raises(ValueError, match="belongs on"):
        _descriptor(queue="intrusive-scan")


def test_descriptor_rejects_foreign_test_key_namespace() -> None:
    """A test key must carry its own module's namespace prefix."""
    with pytest.raises(ValueError, match="namespace"):
        _descriptor(
            tests=(
                contract.TestDeclaration(test_key="dnssec.noop", test_version="1"),
            )
        )


def test_descriptor_rejects_empty_tests_and_duplicates() -> None:
    """A module declares at least one test, and never the same key twice."""
    with pytest.raises(ValueError, match="no executable tests"):
        _descriptor(tests=())
    declaration = contract.TestDeclaration(test_key="web.noop", test_version="1")
    with pytest.raises(ValueError, match="duplicate"):
        _descriptor(tests=(declaration, declaration))


def test_descriptor_rejects_missing_engine_metadata() -> None:
    """The roster must know which engine, at which version, a module wraps."""
    with pytest.raises(ValueError, match="engine"):
        _descriptor(engine="")
    with pytest.raises(ValueError, match="engine"):
        _descriptor(engine_version="")


def test_test_declaration_rejects_malformed_keys() -> None:
    """`test_key` is lowercase dotted text; `test_version` is non-empty."""
    for bad_key in ("noop", "Web.noop", "web.", ".noop", "web noop"):
        with pytest.raises(ValueError, match="namespaced text"):
            contract.TestDeclaration(test_key=bad_key, test_version="1")
    with pytest.raises(ValueError, match="test_version"):
        contract.TestDeclaration(test_key="web.noop", test_version="")


def test_module_queues_match_the_worker_queues() -> None:
    """The contract's queue names must stay the ones the worker validates.

    `platform` is a worker queue but never a module queue: orchestration
    tasks live there, engine work does not.
    """
    assert contract.MODULE_QUEUES < set(REQUIRED_BINARIES)
    assert "platform" not in contract.MODULE_QUEUES
    assert contract.MODULE_QUEUES == {
        "non-intrusive-scan",
        "intrusive-scan",
        "file-analysis",
    }


# --- input contract ----------------------------------------------------------


def test_scan_input_requires_exactly_one_target() -> None:
    """Zero targets and two targets are both rejected, like the row CHECK."""
    with pytest.raises(ValueError, match="Exactly one"):
        contract.ScanInput()
    with pytest.raises(ValueError, match="Exactly one"):
        contract.ScanInput(target_domain="example.com", file_path="/tmp/f")


def test_scan_input_accepts_each_target_kind() -> None:
    """A domain target and a file target are each valid alone."""
    assert contract.ScanInput(target_domain="example.com").target_domain
    assert contract.ScanInput(file_path="/uploads/sample.bin").file_path


def test_scan_input_options_are_isolated_from_the_caller() -> None:
    """`options` is a deep snapshot: one module cannot corrupt another's config.

    The stored payload stays plain JSON data (it maps onto JSONB), so the
    guarantee is isolation from the caller's structure — nested included —
    not attribute read-onlyness.
    """
    source = {"budget": 5.0, "nested": {"k": [1]}}
    scan_input = contract.ScanInput(target_domain="a.example", options=source)
    source["budget"] = 999.0
    source["nested"]["k"].append(2)  # type: ignore[index]
    assert scan_input.options["budget"] == 5.0
    assert scan_input.options["nested"] == {"k": [1]}


def test_module_result_mappings_are_isolated_from_the_caller() -> None:
    """raw_output and summary are deep snapshots for the same reason."""
    raw = {"steps": ["a"]}
    result = contract.ModuleResult(
        schema_version="x/1", raw_output=raw, summary={"b": 2}
    )
    raw["steps"].append("b")
    assert result.raw_output == {"steps": ["a"]}
    # Still plain JSON data, so it survives the JSONB serialization boundary.
    assert json.loads(json.dumps(dict(result.raw_output))) == {"steps": ["a"]}


def test_scan_input_validates_the_timeout() -> None:
    """The timeout is a positive float — not zero, negative, text, or bool."""
    assert contract.ScanInput(target_domain="a.example", timeout=2.5).timeout == 2.5
    for bad in (0, -1.0, "5", True, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="timeout"):
            contract.ScanInput(target_domain="a.example", timeout=bad)  # type: ignore[arg-type]


# --- severity hook -----------------------------------------------------------


def test_default_severity_mapping_is_one_to_one() -> None:
    """Every engine tier maps onto the platform value of the same name."""
    for name, expected in {
        "CRITICAL": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "Medium": FindingSeverity.MEDIUM,
        " low ": FindingSeverity.LOW,
        "INFO": FindingSeverity.INFO,
    }.items():
        assert contract.map_engine_severity(name) is expected


def test_default_severity_mapping_refuses_unknown_input() -> None:
    """An unmapped severity raises instead of guessing."""
    with pytest.raises(ValueError, match="map it explicitly"):
        contract.map_engine_severity("catastrophic")


# --- progress emitter --------------------------------------------------------


def test_progress_cb_delivers_to_the_sink() -> None:
    """The standard callback becomes one `progress` event per call."""
    sink = _RecordingSink()
    emitter = contract.ProgressEmitter(test_key="web.noop", sink=sink)
    emitter.progress_cb("Resolving zone hierarchy …")
    assert sink.events == [
        contract.ProgressEvent(
            test_key="web.noop", message="Resolving zone hierarchy …"
        )
    ]


def test_extra_cb_tolerates_any_engine_arity() -> None:
    """subdomainenum-style extra callbacks marshal whatever arity they have."""
    sink = _RecordingSink()
    emitter = contract.ProgressEmitter(test_key="web.subdomain_enumeration", sink=sink)
    emitter.extra_cb("debug")("subfinder", "probing wildcard DNS")
    emitter.extra_cb("finish")("ffuf", None, True)
    assert [(e.channel, e.message) for e in sink.events] == [
        ("debug", "subfinder probing wildcard DNS"),
        ("finish", "ffuf True"),
    ]


def test_emitter_without_a_sink_logs_instead(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Progress is advisory but never silently dropped: no sink means the log."""
    emitter = contract.ProgressEmitter(test_key="web.noop")
    with caplog.at_level(logging.INFO, logger="nc3_testing_platform.modules.contract"):
        emitter.progress_cb("still here")
    assert "still here" in caplog.text


# --- execution runner --------------------------------------------------------


def test_run_engine_marshals_report_and_progress() -> None:
    """A child run returns the `asdict()` report and streams progress lines."""
    sink = _RecordingSink()
    emitter = contract.ProgressEmitter(test_key="web.noop", sink=sink)
    outcome = execution.run_engine(
        NOOP_ENGINE_ENTRY,
        args=("example.com",),
        kwargs={"timeout": 1.0},
        budget=30.0,
        progress=emitter,
    )
    assert outcome.ok
    report = outcome.unwrap()
    assert report["domain"] == "example.com"
    assert report["steps"] == list(noop_engine.STEPS)
    # The marshalling rule made testable: the report is plain JSON data,
    # not a pickled engine object.
    assert json.loads(json.dumps(report)) == report
    assert [e.channel for e in sink.events] == ["progress"] * len(noop_engine.STEPS)
    assert "example.com" in sink.events[0].message


def test_run_engine_kills_an_overrunning_child() -> None:
    """The budget is enforced by killing the child, not by trusting it."""
    emitter = contract.ProgressEmitter(test_key="web.noop", sink=_RecordingSink())
    outcome = execution.run_engine(
        NOOP_ENGINE_ENTRY,
        args=("example.com",),
        kwargs={"timeout": 1.0, "delay": 30.0},
        budget=1.5,
        grace=1.0,
        progress=emitter,
    )
    assert outcome.timed_out
    assert outcome.report is None
    with pytest.raises(RuntimeError, match="budget"):
        outcome.unwrap()


def test_run_engine_marshals_a_child_error_as_text() -> None:
    """A child-side exception crosses the pipe as rendered text, not an object."""
    emitter = contract.ProgressEmitter(test_key="web.noop", sink=_RecordingSink())
    outcome = execution.run_engine(
        NOOP_ENGINE_ENTRY,
        args=("example.com",),
        kwargs={"timeout": 1.0, "fail": True},
        budget=30.0,
        progress=emitter,
    )
    assert not outcome.ok
    assert not outcome.timed_out
    assert outcome.error is not None and outcome.error.startswith("ValueError:")
    with pytest.raises(RuntimeError, match="failed on request"):
        outcome.unwrap()


def test_run_engine_reports_a_bad_entry_as_an_error() -> None:
    """A missing engine attribute is a child-side error, not a parent crash."""
    emitter = contract.ProgressEmitter(test_key="web.noop", sink=_RecordingSink())
    outcome = execution.run_engine(
        "nc3_testing_platform.modules.noop.engine:no_such_function",
        budget=30.0,
        progress=emitter,
    )
    assert outcome.error is not None and "AttributeError" in outcome.error


def test_run_engine_rejects_a_nonpositive_or_nonfinite_budget() -> None:
    """Zero means 'kill immediately'; inf/nan crash the poller. Refuse all."""
    emitter = contract.ProgressEmitter(test_key="web.noop")
    for bad in (0, -1.0, float("inf"), float("nan")):
        with pytest.raises(ValueError, match="budget"):
            execution.run_engine(NOOP_ENGINE_ENTRY, budget=bad, progress=emitter)


def test_run_engine_survives_a_failing_progress_sink() -> None:
    """A sink that raises degrades progress, never fails a healthy engine run."""

    def _angry_sink(_event: contract.ProgressEvent) -> None:
        raise RuntimeError("the sink is down")

    emitter = contract.ProgressEmitter(test_key="web.noop", sink=_angry_sink)
    outcome = execution.run_engine(
        NOOP_ENGINE_ENTRY,
        args=("example.com",),
        kwargs={"timeout": 1.0},
        budget=30.0,
        progress=emitter,
    )
    assert outcome.ok
    assert outcome.unwrap()["domain"] == "example.com"


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")
def test_run_engine_kills_a_grandchild_subprocess() -> None:
    """A budget kill must reach the subprocess an engine shelled out to.

    The engine child spawns a long `sleep` and records its PID before
    stalling; after the budget kills the group, that PID must be gone —
    otherwise a killed subdomainenum/portscanner leaks subfinder/nmap.
    """
    pid_file = Path(tempfile.gettempdir()) / f"noop-grandchild-{os.getpid()}.pid"
    if pid_file.exists():
        pid_file.unlink()
    emitter = contract.ProgressEmitter(test_key="web.noop", sink=_RecordingSink())
    outcome = execution.run_engine(
        "nc3_testing_platform.modules.noop.engine:assess",
        args=("example.com",),
        kwargs={"timeout": 1.0, "spawn_child_pidfile": str(pid_file)},
        budget=1.5,
        grace=1.0,
        progress=emitter,
    )
    assert outcome.timed_out
    deadline = time.monotonic() + 5.0
    while not pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    assert pid_file.exists(), "the engine child never recorded its grandchild"
    grandchild_pid = int(pid_file.read_text())
    pid_file.unlink()
    # Give the group kill a moment to propagate, then the PID must be dead.
    gone = False
    for _ in range(100):
        try:
            os.kill(grandchild_pid, 0)
        except ProcessLookupError:
            gone = True
            break
        time.sleep(0.05)
    if not gone:  # pragma: no cover - only on a leak, and we clean up first
        try:
            os.kill(grandchild_pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    assert gone, f"grandchild {grandchild_pid} survived the budget kill"


# --- registry ----------------------------------------------------------------


def test_discovery_finds_the_installed_noop() -> None:
    """The entry-point round trip: pyproject registration to loaded module."""
    roster = registry.discover()
    names = [entry.entry_point for entry in roster.entries]
    assert "noop" in names
    loaded = roster.by_test_key("web.noop")
    assert loaded.implementation.descriptor.name is ScanModule.WEB
    assert roster.queue_for("web.noop") == "non-intrusive-scan"


def test_roster_rejects_unknown_and_misrouted_test_keys() -> None:
    """Both platform-side lookups fail loudly rather than returning nothing."""
    roster = registry.discover()
    with pytest.raises(registry.ModuleRegistryError, match="no registered module"):
        roster.by_test_key("web.never_registered")
    with pytest.raises(registry.ModuleRegistryError, match="must not"):
        roster.require("web.noop", queue="intrusive-scan")
    assert roster.require("web.noop", queue="non-intrusive-scan").entry_point == "noop"


def test_discovery_rejects_duplicate_test_keys() -> None:
    """Two entries claiming one test_key abort discovery entirely."""
    noop_entry = "nc3_testing_platform.modules.noop:MODULE"
    entries = (
        EntryPoint("noop", noop_entry, registry.ENTRY_POINT_GROUP),
        EntryPoint("noop-again", noop_entry, registry.ENTRY_POINT_GROUP),
    )
    with pytest.raises(registry.ModuleRegistryError, match="declared by both"):
        registry.discover(entry_points=entries)


def test_discovery_rejects_duplicate_entry_names() -> None:
    """One name, one module: a doubled registration is a packaging bug."""
    noop_entry = "nc3_testing_platform.modules.noop:MODULE"
    entries = (
        EntryPoint("noop", noop_entry, registry.ENTRY_POINT_GROUP),
        EntryPoint("noop", noop_entry, registry.ENTRY_POINT_GROUP),
    )
    with pytest.raises(registry.ModuleRegistryError, match="registered twice"):
        registry.discover(entry_points=entries)


def test_discovery_rejects_an_impostor_object() -> None:
    """An entry point must resolve to a TestModule, not any importable thing."""
    entries = (
        EntryPoint(
            "impostor",
            "nc3_testing_platform.modules.noop:SCHEMA_VERSION",
            registry.ENTRY_POINT_GROUP,
        ),
    )
    with pytest.raises(registry.ModuleRegistryError, match="does not implement"):
        registry.discover(entry_points=entries)


def test_discovery_reports_an_unloadable_entry_point() -> None:
    """A broken registration names itself in the failure."""
    entries = (
        EntryPoint(
            "broken",
            "nc3_testing_platform.modules.noop:NO_SUCH_ATTRIBUTE",
            registry.ENTRY_POINT_GROUP,
        ),
    )
    with pytest.raises(registry.ModuleRegistryError, match="broken"):
        registry.discover(entry_points=entries)


# --- the dependency arrow ----------------------------------------------------


def test_core_never_imports_modules() -> None:
    """Nothing outside `modules/` imports `nc3_testing_platform.modules.*`.

    Discovery goes through entry points only (IDR-007); this is the test the
    plan calls core-never-imports-modules, over the actual import statements
    of every platform source file.
    """
    offenders: list[str] = []
    for path in sorted(SRC_ROOT.rglob("*.py")):
        if SRC_ROOT / "modules" in path.parents:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any(name.startswith("nc3_testing_platform.modules") for name in names):
                offenders.append(str(path.relative_to(SRC_ROOT)))
    assert offenders == []


# --- conformance suite (every module must pass; dnssec joins in Phase 2) -----

CONFORMING_MODULES = (noop.MODULE,)


@pytest.fixture(
    params=CONFORMING_MODULES,
    ids=lambda module: module.descriptor.tests[0].test_key,
)
def conforming_module(request: pytest.FixtureRequest) -> contract.TestModule:
    """Each registered module, run through the identical conformance checks."""
    return request.param


def test_conformance_protocol_and_descriptor(
    conforming_module: contract.TestModule,
) -> None:
    """The module satisfies the protocol and declares platform vocabulary."""
    assert isinstance(conforming_module, contract.TestModule)
    descriptor = conforming_module.descriptor
    assert isinstance(descriptor.name, ScanModule)
    assert isinstance(descriptor.classification, ScanClassification)
    assert descriptor.queue in contract.MODULE_QUEUES


def test_conformance_severity_hook(conforming_module: contract.TestModule) -> None:
    """The hook covers the engines' five tiers and refuses the unknown."""
    for tier in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        assert isinstance(conforming_module.map_severity(tier), FindingSeverity)
    with pytest.raises(ValueError):
        conforming_module.map_severity("not-a-severity")


def test_conformance_run_end_to_end(conforming_module: contract.TestModule) -> None:
    """One full run: child process, marshalled progress, normalized result.

    The JSON round trip of `raw_output` is the marshalling test: the report
    crossed the process boundary as plain data, not as a pickled object.
    """
    sink = _RecordingSink()
    test_key = conforming_module.descriptor.tests[0].test_key
    result = conforming_module.run(
        contract.ScanInput(target_domain="example.com", timeout=2.0),
        progress=contract.ProgressEmitter(test_key=test_key, sink=sink),
    )
    assert isinstance(result, contract.ModuleResult)
    assert result.schema_version
    assert json.loads(json.dumps(dict(result.raw_output))) == dict(result.raw_output)
    assert result.findings
    for finding in result.findings:
        assert isinstance(finding.severity, FindingSeverity)
        assert finding.check_id
    assert sink.events, "a run must narrate at least one progress step"


# --- noop specifics ----------------------------------------------------------


def test_noop_refuses_a_file_target() -> None:
    """The noop declares a domain test and validates its input accordingly."""
    with pytest.raises(ValueError, match="domain"):
        noop.MODULE.run(
            contract.ScanInput(file_path="/uploads/sample.bin"),
            progress=contract.ProgressEmitter(test_key="web.noop"),
        )


def test_noop_surfaces_an_engine_timeout_as_a_failure() -> None:
    """A budget kill becomes a raised RuntimeError, i.e. a failed task."""
    scan_input = contract.ScanInput(
        target_domain="example.com",
        timeout=1.0,
        options={"delay": 30.0, "budget": 1.5},
    )
    with pytest.raises(RuntimeError, match="budget"):
        noop.MODULE.run(
            scan_input, progress=contract.ProgressEmitter(test_key="web.noop")
        )
