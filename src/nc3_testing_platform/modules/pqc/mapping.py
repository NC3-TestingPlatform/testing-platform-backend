"""QuantumReport (as a marshalled dict) → normalized findings.

The quantumvalidator engine reports its own vocabularies — a per-check
``Status`` (pass/fail/info/error) and an overall ``Verdict`` (safe/unsafe) —
not the engines' `VerdictSeverity` tiers, so this module owns an explicit
table rather than delegating to the contract's 1:1 default. The mapping reads
the report as the plain ``asdict()`` dict the runner marshalled across the
process boundary, never a live ``QuantumReport`` object, so it needs nothing
from the quantumvalidator package (the fixtures the tests replay are that
same dict).

Findings are generic over ``checks``: every FAIL/ERROR check becomes one
finding named ``pqc.check.<name>``, so a new engine check (the PQC-02/03
roadmap) flows through as a pin bump plus fixture refresh with no mapping
edit.
"""

from collections.abc import Mapping, Sequence
from typing import Any

from nc3_testing_platform.core.enums import FindingSeverity
from nc3_testing_platform.modules.contract import NormalizedFinding
from nc3_testing_platform.modules.normalization import severity as severity_rules
from nc3_testing_platform.modules.pqc import schema

# One table covers both engine enums (IDR-018): the module still owns *what*
# a value means — an unsafe verdict or failed check is a CNSA 2.0 / BSI
# TR-02102 posture gap with harvest-now-decrypt-later exposure, an error
# could not assess, and pass/safe are reported for the record — while the
# platform owns how a value is matched and what an unmapped one does.
_VOCABULARY = severity_rules.QUANTUMVALIDATOR_STATUS

_TITLE_BY_VERDICT: Mapping[str, str] = {
    "safe": "Key exchange is post-quantum ready",
    "unsafe": "Key exchange is not post-quantum ready",
}


def map_status_severity(status: str) -> FindingSeverity:
    """One quantumvalidator value → a platform :class:`FindingSeverity`.

    :param status: A check ``Status`` (``"pass"``/``"fail"``/``"info"``/
        ``"error"``) or the overall ``Verdict`` (``"safe"``/``"unsafe"``),
        case-insensitive.
    :raises ValueError: If *status* is not one the engine emits — the module
        maps its own vocabulary explicitly and never guesses a severity.
    """
    return _VOCABULARY.map_severity(status)


def _evidence(source: Mapping[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    """The truthy subset of *source* under *keys*, for a finding's evidence."""
    return {key: source[key] for key in keys if source.get(key)}


def normalize(report: Mapping[str, Any]) -> tuple[NormalizedFinding, ...]:
    """Turn one marshalled QuantumReport dict into normalized findings.

    Always yields the overall readiness finding (severity from the verdict);
    adds one finding per FAIL/ERROR check (keyed on ``pqc.check.<name>``), so
    an unready host surfaces both the summary verdict and each specific gap.
    PASS/INFO checks stay in ``raw_output`` for the evidence trail.
    """
    target = report.get("target", "")
    # Normalize once: map_status_severity is case- and space-insensitive, so
    # the title lookup and check-id suffixes must use the same canonical value.
    verdict = str(report.get("verdict", "unsafe")).strip().lower()
    findings: list[NormalizedFinding] = [
        NormalizedFinding(
            check_id=schema.CHECK_READINESS,
            severity=map_status_severity(verdict),
            title=_TITLE_BY_VERDICT.get(verdict, _TITLE_BY_VERDICT["unsafe"]),
            description=(
                f"quantumvalidator probed {target!r} and reported the key "
                f"exchange {verdict!r} against CNSA 2.0 / BSI TR-02102 "
                f"post-quantum migration targets."
            ),
            affected_resource=target or None,
            evidence=_evidence(
                report,
                (
                    "verdict",
                    "tls_version",
                    "negotiated_group",
                    "detected_starttls",
                    "port",
                ),
            ),
        )
    ]

    for check in report.get("checks", []):
        status = str(check.get("status", "pass")).strip().lower()
        if status not in ("fail", "error"):
            continue
        name = str(check.get("name", "unknown")).strip().lower()
        findings.append(
            NormalizedFinding(
                check_id=f"{schema.CHECK_PREFIX}.{name}",
                severity=map_status_severity(status),
                title=(
                    f"PQC check {name} failed"
                    if status == "fail"
                    else f"PQC check {name} could not run"
                ),
                description=str(check.get("reason", ""))
                or f"The {name} check reported {status!r}.",
                affected_resource=target or None,
                evidence=_evidence(check, ("value", "reason", "standard")),
            )
        )

    return tuple(findings)


def summarize(report: Mapping[str, Any]) -> dict[str, Any]:
    """A small, render-ready aggregate of one QuantumReport dict."""
    checks = report.get("checks", [])

    def _status(item: Mapping[str, Any]) -> str:
        return str(item.get("status", "")).strip().lower()

    verdict = str(report.get("verdict", "")).strip().lower()
    return {
        "verdict": verdict,
        "safe": verdict == "safe",
        "tls_version": report.get("tls_version"),
        "negotiated_group": report.get("negotiated_group"),
        "detected_starttls": report.get("detected_starttls"),
        "port": report.get("port"),
        "failed_checks": sum(1 for check in checks if _status(check) == "fail"),
        "error_checks": sum(1 for check in checks if _status(check) == "error"),
    }
