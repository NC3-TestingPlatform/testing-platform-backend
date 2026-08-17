"""Tests for the DNSSEC exemplar module (US #76, task #174).

Mapping is checked against **recorded** chainvalidator output — the JSON
fixtures under `tests/fixtures/dnssec/`, captured in the marshalled
`asdict()` shape — so nothing here touches the network or needs the
chainvalidator package installed. The contract conformance run uses the same
recorded data through a replay engine, driven by the exact assertion helpers
in `tests/conformance.py` that the noop passes.
"""

import json
import tomllib
from pathlib import Path

import conformance
import dnssec_replay_engine
import pytest

from nc3_testing_platform.core.enums import FindingSeverity, ScanModule
from nc3_testing_platform.modules import registry
from nc3_testing_platform.modules.contract import ProgressEmitter, ScanInput
from nc3_testing_platform.modules.dnssec import MODULE as DNSSEC_MODULE
from nc3_testing_platform.modules.dnssec import DnssecModule, mapping, runner, schema
from nc3_testing_platform.worker.preflight import REQUIRED_ENGINES

FIXTURES = Path(__file__).parent / "fixtures" / "dnssec"


def _report(name: str) -> dict:
    """One recorded DNSSECReport dict by fixture name."""
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


# --- severity hook -----------------------------------------------------------


def test_status_severity_mapping() -> None:
    """Chainvalidator's four statuses map to deliberate finding severities."""
    assert mapping.map_status_severity("secure") is FindingSeverity.INFO
    assert mapping.map_status_severity("insecure") is FindingSeverity.MEDIUM
    assert mapping.map_status_severity("bogus") is FindingSeverity.HIGH
    assert mapping.map_status_severity("error") is FindingSeverity.LOW
    assert mapping.map_status_severity("BOGUS") is FindingSeverity.HIGH


def test_status_severity_rejects_unknown() -> None:
    """A status the engine never emits raises rather than guessing."""
    with pytest.raises(ValueError, match="no severity mapping"):
        mapping.map_status_severity("catastrophic")


def test_module_severity_hook_delegates_to_the_status_table() -> None:
    """The module's map_severity is the status table, not the 1:1 default."""
    assert DNSSEC_MODULE.map_severity("bogus") is FindingSeverity.HIGH


# --- mapping against recorded output -----------------------------------------


def test_mapping_secure_report_is_one_info_finding() -> None:
    """A fully secure chain yields a single INFO chain-of-trust finding."""
    findings = mapping.normalize(_report("secure"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == schema.CHECK_CHAIN
    assert finding.severity is FindingSeverity.INFO
    assert finding.affected_resource == "example.com"
    assert mapping.summarize(_report("secure"))["secure"] is True


def test_mapping_insecure_report_flags_the_unsigned_delegation() -> None:
    """An insecure chain surfaces the summary and the unsigned delegation."""
    findings = mapping.normalize(_report("insecure"))
    by_check = {f.check_id: f for f in findings}
    assert by_check[schema.CHECK_CHAIN].severity is FindingSeverity.MEDIUM
    delegation = by_check[f"{schema.CHECK_DELEGATION}.insecure"]
    assert delegation.severity is FindingSeverity.MEDIUM
    assert delegation.affected_resource == "example."
    # The unsigned leaf is flagged too.
    assert f"{schema.CHECK_LEAF}.insecure" in by_check
    summary = mapping.summarize(_report("insecure"))
    assert summary["insecure_delegations"] == 1
    assert summary["secure"] is False


def test_mapping_bogus_report_is_high_and_names_the_broken_link() -> None:
    """A bogus chain is HIGH and pins the broken delegation; no leaf finding."""
    findings = mapping.normalize(_report("bogus"))
    by_check = {f.check_id: f for f in findings}
    assert by_check[schema.CHECK_CHAIN].severity is FindingSeverity.HIGH
    delegation = by_check[f"{schema.CHECK_DELEGATION}.bogus"]
    assert delegation.severity is FindingSeverity.HIGH
    assert delegation.evidence is not None
    assert "does not match" in delegation.evidence["errors"][0]
    # leaf was null (chain broke before the leaf) — no leaf finding.
    assert not any(f.check_id.startswith(schema.CHECK_LEAF) for f in findings)


def test_mapping_findings_are_json_serializable() -> None:
    """Every finding's evidence survives the JSONB persistence boundary."""
    for name in ("secure", "insecure", "bogus"):
        for finding in mapping.normalize(_report(name)):
            if finding.evidence is not None:
                json.dumps(dict(finding.evidence))


# --- descriptor / discovery --------------------------------------------------


def test_descriptor_declares_the_dnssec_module() -> None:
    """The roster entry matches the platform vocabulary and the engine pin."""
    descriptor = DNSSEC_MODULE.descriptor
    assert descriptor.name is ScanModule.DNSSEC
    assert descriptor.queue == "non-intrusive-scan"
    assert descriptor.engine == "chainvalidator"
    assert descriptor.tests[0].test_key == "dnssec.chainvalidator"


def test_dnssec_is_discoverable_via_entry_points() -> None:
    """The module is found through the entry-point group, not by import."""
    roster = registry.discover()
    assert roster.queue_for("dnssec.chainvalidator") == "non-intrusive-scan"


def test_engine_pin_matches_schema_version() -> None:
    """The pyproject pin, the descriptor, and preflight cannot drift apart.

    Preflight refuses an image whose installed chainvalidator differs from its
    REQUIRED_ENGINES literal — a literal because preflight is core and never
    imports this module (IDR-007). This test is the coupling instead: one
    commit bumps the pin, `schema.ENGINE_VERSION`, the preflight literal, and
    the lock, or the suite fails.
    """
    pyproject = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    (requirement,) = [
        line
        for line in pyproject["project"]["optional-dependencies"]["modules"]
        if line.startswith("chainvalidator")
    ]
    assert requirement.endswith(f"@v{schema.ENGINE_VERSION}")
    assert (
        "chainvalidator",
        schema.ENGINE_VERSION,
    ) in REQUIRED_ENGINES["non-intrusive-scan"]


def test_budget_clamp_bounds_both_sides() -> None:
    """An untrusted options['budget'] is clamped, never passed through raw."""
    assert runner._clamp_budget(1e9) == runner.MAX_BUDGET
    assert runner._clamp_budget(30.0) == 30.0
    # Non-positive, non-finite, and non-numeric all fall back to the default.
    for bad in (0, -5, float("inf"), float("nan"), "sixty", None):
        assert runner._clamp_budget(bad) == runner.DEFAULT_BUDGET


def test_run_rejects_a_file_target() -> None:
    """The DNSSEC module scans a domain, not a file."""
    with pytest.raises(ValueError, match="domain"):
        DNSSEC_MODULE.run(
            ScanInput(file_path="/uploads/sample.bin"),
            progress=ProgressEmitter(test_key="dnssec.chainvalidator"),
        )


# --- contract conformance via the replay engine (no network) -----------------


@pytest.fixture
def replay_module(monkeypatch: pytest.MonkeyPatch) -> DnssecModule:
    """The dnssec module bound to the recorded-replay engine.

    The engine entry is swapped for the test-only replay engine and the
    fixture path is exported for the spawn child (which inherits the env), so
    the whole runner path runs against recorded output instead of live DNS.
    """
    monkeypatch.setenv(
        dnssec_replay_engine.FIXTURE_ENV, str(FIXTURES / "insecure.json")
    )
    return DnssecModule(engine_entry="dnssec_replay_engine:assess")


def test_conformance_protocol_and_descriptor(replay_module: DnssecModule) -> None:
    """The dnssec module passes the shared descriptor conformance check."""
    conformance.assert_protocol_and_descriptor(replay_module)


def test_conformance_severity_hook(replay_module: DnssecModule) -> None:
    """It maps its own status vocabulary and rejects anything else."""
    for status in ("secure", "insecure", "bogus", "error"):
        assert isinstance(replay_module.map_severity(status), FindingSeverity)
    conformance.assert_severity_hook_rejects_garbage(replay_module)


def test_conformance_run_end_to_end(replay_module: DnssecModule) -> None:
    """The full runner path passes the same end-to-end check the noop does."""
    conformance.assert_run_end_to_end(
        replay_module, ScanInput(target_domain="example.com", timeout=2.0)
    )


def test_run_marshals_progress_and_report_from_the_child(
    replay_module: DnssecModule,
) -> None:
    """A replayed run streams a progress line and returns the recorded report."""
    events: list[str] = []
    result = replay_module.run(
        ScanInput(target_domain="insecure-zone.example", timeout=2.0),
        progress=ProgressEmitter(
            test_key="dnssec.chainvalidator", sink=lambda e: events.append(e.message)
        ),
    )
    assert result.schema_version == schema.SCHEMA_VERSION
    assert result.raw_output["status"] == "insecure"
    assert any("Replaying" in message for message in events)
