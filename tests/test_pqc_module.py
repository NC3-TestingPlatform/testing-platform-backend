"""Tests for the PQC module (US #101).

Mapping is checked against **recorded** quantumvalidator output — the JSON
fixtures under `tests/fixtures/pqc/`, captured in the marshalled `asdict()`
shape — so nothing here touches the network or needs the quantumvalidator
package installed. The contract conformance run uses the same recorded data
through a replay engine, driven by the exact assertion helpers in
`tests/conformance.py` that the noop and dnssec modules pass.
"""

import json
import tomllib
from pathlib import Path

import conformance
import pqc_replay_engine
import pytest

from nc3_testing_platform.core.enums import FindingSeverity, ScanModule
from nc3_testing_platform.modules import registry
from nc3_testing_platform.modules.contract import ProgressEmitter, ScanInput
from nc3_testing_platform.modules.pqc import MODULE as PQC_MODULE
from nc3_testing_platform.modules.pqc import PqcModule, mapping, runner, schema
from nc3_testing_platform.worker.preflight import REQUIRED_ENGINES

FIXTURES = Path(__file__).parent / "fixtures" / "pqc"


def _report(name: str) -> dict:
    """One recorded QuantumReport dict by fixture name."""
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


# --- severity hook -----------------------------------------------------------


def test_status_severity_mapping() -> None:
    """Both engine enums map to deliberate finding severities."""
    assert mapping.map_status_severity("pass") is FindingSeverity.INFO
    assert mapping.map_status_severity("info") is FindingSeverity.INFO
    assert mapping.map_status_severity("safe") is FindingSeverity.INFO
    assert mapping.map_status_severity("fail") is FindingSeverity.MEDIUM
    assert mapping.map_status_severity("unsafe") is FindingSeverity.MEDIUM
    assert mapping.map_status_severity("error") is FindingSeverity.LOW
    assert mapping.map_status_severity("UNSAFE") is FindingSeverity.MEDIUM


def test_status_severity_rejects_unknown() -> None:
    """A value the engine never emits raises rather than guessing."""
    with pytest.raises(ValueError, match="no severity mapping"):
        mapping.map_status_severity("quantum-broken")


def test_module_severity_hook_delegates_to_the_status_table() -> None:
    """The module's map_severity is the declared table, not the 1:1 default."""
    assert PQC_MODULE.map_severity("unsafe") is FindingSeverity.MEDIUM


# --- mapping against recorded output -----------------------------------------


def test_mapping_safe_report_is_one_info_finding() -> None:
    """A PQC-ready host yields a single INFO readiness finding."""
    findings = mapping.normalize(_report("safe_tls"))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.check_id == schema.CHECK_READINESS
    assert finding.severity is FindingSeverity.INFO
    assert finding.affected_resource == "cloudflare.com"
    assert finding.evidence is not None
    assert finding.evidence["negotiated_group"] == "X25519MLKEM768"
    summary = mapping.summarize(_report("safe_tls"))
    assert summary["safe"] is True
    assert summary["failed_checks"] == 0


def test_mapping_unsafe_report_flags_each_failed_check() -> None:
    """A classical-only host surfaces the verdict and every failed check.

    The recorded host misses the PQC hybrid group *and* serves an RSA-2048
    certificate, so the v0.7.0 PQC-02 check contributes a second finding.
    """
    findings = mapping.normalize(_report("unsafe_tls"))
    by_check = {f.check_id: f for f in findings}
    assert by_check[schema.CHECK_READINESS].severity is FindingSeverity.MEDIUM
    failed = by_check[f"{schema.CHECK_PREFIX}.key_exchange"]
    assert failed.severity is FindingSeverity.MEDIUM
    assert failed.evidence is not None
    assert "standard" in failed.evidence
    certificate = by_check[f"{schema.CHECK_PREFIX}.certificate_key"]
    assert certificate.severity is FindingSeverity.MEDIUM
    assert certificate.evidence is not None
    assert certificate.evidence["value"] == "RSA-2048"
    summary = mapping.summarize(_report("unsafe_tls"))
    assert summary["safe"] is False
    assert summary["failed_checks"] == 2


def test_mapping_ssh_report_names_the_kex_and_host_key_gaps() -> None:
    """An SSH probe maps like any other: KEX and host-key gaps become findings.

    The recorded server still advertises `ssh-rsa`, so the v0.7.0 PQC-03
    check contributes a finding beside the non-PQC KEX one.
    """
    findings = mapping.normalize(_report("ssh"))
    by_check = {f.check_id: f for f in findings}
    assert f"{schema.CHECK_PREFIX}.kex_algorithm" in by_check
    host_keys = by_check[f"{schema.CHECK_PREFIX}.host_key_algorithms"]
    assert host_keys.severity is FindingSeverity.MEDIUM
    summary = mapping.summarize(_report("ssh"))
    assert summary["tls_version"] == "SSHv2"
    assert summary["port"] == 22


def test_mapping_connection_error_is_low_not_a_crash() -> None:
    """An unreachable host is a LOW could-not-assess finding, not a failure."""
    findings = mapping.normalize(_report("connection_error"))
    by_check = {f.check_id: f for f in findings}
    error = by_check[f"{schema.CHECK_PREFIX}.connection"]
    assert error.severity is FindingSeverity.LOW
    summary = mapping.summarize(_report("connection_error"))
    assert summary["error_checks"] == 1


def test_mapping_findings_are_json_serializable() -> None:
    """Every finding's evidence survives the JSONB persistence boundary."""
    for name in ("safe_tls", "unsafe_tls", "ssh", "connection_error"):
        for finding in mapping.normalize(_report(name)):
            if finding.evidence is not None:
                json.dumps(dict(finding.evidence))


# --- descriptor / discovery --------------------------------------------------


def test_descriptor_declares_the_pqc_module() -> None:
    """The roster entry matches the platform vocabulary and the engine pin."""
    descriptor = PQC_MODULE.descriptor
    assert descriptor.name is ScanModule.PQC
    assert descriptor.queue == "non-intrusive-scan"
    assert descriptor.engine == "quantumvalidator"
    assert descriptor.tests[0].test_key == "pqc.quantumvalidator"


def test_pqc_is_discoverable_via_entry_points() -> None:
    """The module is found through the entry-point group, not by import."""
    roster = registry.discover()
    assert roster.queue_for("pqc.quantumvalidator") == "non-intrusive-scan"


def test_engine_pin_matches_schema_version() -> None:
    """The pyproject pin, the descriptor, and preflight cannot drift apart.

    Preflight refuses an image whose installed quantumvalidator differs from
    its REQUIRED_ENGINES literal — a literal because preflight is core and
    never imports this module (IDR-007). This test is the coupling instead:
    one commit bumps the pin, `schema.ENGINE_VERSION`, the preflight literal,
    and the lock, or the suite fails.
    """
    pyproject = tomllib.loads(
        (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
    )
    (requirement,) = [
        line
        for line in pyproject["project"]["optional-dependencies"]["modules"]
        if line.startswith("quantumvalidator")
    ]
    assert requirement.endswith(f"@v{schema.ENGINE_VERSION}")
    assert (
        "quantumvalidator",
        schema.ENGINE_VERSION,
    ) in REQUIRED_ENGINES["non-intrusive-scan"]


# --- runner input handling ----------------------------------------------------


def test_budget_clamp_bounds_both_sides() -> None:
    """An untrusted options['budget'] is clamped, never passed through raw."""
    assert runner._clamp_budget(1e9) == runner.MAX_BUDGET
    assert runner._clamp_budget(15.0) == 15.0
    for bad in (0, -5, float("inf"), float("nan"), "thirty", None, True, False):
        assert runner._clamp_budget(bad) == runner.DEFAULT_BUDGET


def test_port_clamp_accepts_only_valid_tcp_ports() -> None:
    """An untrusted options['port'] is a real port or the engine default."""
    assert runner._clamp_port(22) == 22
    assert runner._clamp_port("8443") == 8443
    assert runner._clamp_port(443.0) == 443
    bad_ports = (0, -1, 65536, "https", None, True, False, 1.9, float("inf"), float("nan"))
    for bad in bad_ports:
        assert runner._clamp_port(bad) is None


def test_run_rejects_a_file_target() -> None:
    """The PQC module scans a domain, not a file."""
    with pytest.raises(ValueError, match="domain"):
        PQC_MODULE.run(
            ScanInput(file_path="/uploads/sample.bin"),
            progress=ProgressEmitter(test_key="pqc.quantumvalidator"),
        )


# --- contract conformance via the replay engine (no network) -----------------


@pytest.fixture
def replay_module(monkeypatch: pytest.MonkeyPatch) -> PqcModule:
    """The pqc module bound to the recorded-replay engine.

    The engine entry is swapped for the test-only replay engine and the
    fixture path is exported for the spawn child (which inherits the env), so
    the whole runner path runs against recorded output instead of a live
    handshake.
    """
    monkeypatch.setenv(
        pqc_replay_engine.FIXTURE_ENV, str(FIXTURES / "unsafe_tls.json")
    )
    return PqcModule(engine_entry="pqc_replay_engine:assess")


def test_conformance_protocol_and_descriptor(replay_module: PqcModule) -> None:
    """The pqc module passes the shared descriptor conformance check."""
    conformance.assert_protocol_and_descriptor(replay_module)


def test_conformance_severity_hook(replay_module: PqcModule) -> None:
    """It maps its own vocabulary and rejects anything else."""
    for status in ("pass", "fail", "info", "error", "safe", "unsafe"):
        assert isinstance(replay_module.map_severity(status), FindingSeverity)
    conformance.assert_severity_hook_rejects_garbage(replay_module)


def test_conformance_run_end_to_end(replay_module: PqcModule) -> None:
    """The full runner path passes the same end-to-end check the noop does."""
    conformance.assert_run_end_to_end(
        replay_module, ScanInput(target_domain="example.com", timeout=2.0)
    )


def test_run_marshals_progress_and_report_from_the_child(
    replay_module: PqcModule,
) -> None:
    """A replayed run streams a progress line and returns the recorded report."""
    events: list[str] = []
    result = replay_module.run(
        ScanInput(target_domain="classical.example", timeout=2.0),
        progress=ProgressEmitter(
            test_key="pqc.quantumvalidator", sink=lambda e: events.append(e.message)
        ),
    )
    assert result.schema_version == schema.SCHEMA_VERSION
    assert result.raw_output["verdict"] == "UNSAFE"
    assert result.summary["safe"] is False
    assert any("Replaying" in message for message in events)
