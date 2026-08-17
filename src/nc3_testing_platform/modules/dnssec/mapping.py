"""DNSSECReport (as a marshalled dict) → normalized findings.

The chainvalidator engine reports its own four-value ``Status`` vocabulary
(secure / insecure / bogus / error), not the engines' `VerdictSeverity`
tiers — so this module owns an explicit status→severity table rather than
delegating to the contract's 1:1 default. The mapping reads the report as
the plain ``asdict()`` dict the runner marshalled across the process
boundary, never a live ``DNSSECReport`` object, so it needs nothing from the
chainvalidator package (the fixtures the tests replay are that same dict).
"""

from collections.abc import Mapping, Sequence
from typing import Any

from nc3_testing_platform.core.enums import FindingSeverity
from nc3_testing_platform.modules.contract import NormalizedFinding
from nc3_testing_platform.modules.dnssec import schema
from nc3_testing_platform.modules.normalization import severity as severity_rules

# The engine's chain status, mapped to the platform severity of a *finding*
# about that status. The table is declared in the normalization layer's
# vocabulary registry rather than here (IDR-018): the module still owns *what*
# a status means — a bogus link is an active cryptographic failure, an insecure
# delegation is a posture gap, an operational error could not validate, and a
# secure chain is reported for the record — but the platform owns how a value
# is matched and what an unmapped one does.
_VOCABULARY = severity_rules.CHAINVALIDATOR_STATUS

_TITLE_BY_STATUS: Mapping[str, str] = {
    "secure": "DNSSEC chain of trust is intact",
    "insecure": "DNSSEC chain is not anchored end to end",
    "bogus": "DNSSEC validation failed",
    "error": "DNSSEC chain could not be validated",
}


def map_status_severity(status: str) -> FindingSeverity:
    """One chainvalidator ``Status`` value → a platform :class:`FindingSeverity`.

    :param status: The engine status string (``"secure"``/``"insecure"``/
        ``"bogus"``/``"error"``), case-insensitive.
    :raises ValueError: If *status* is not one the engine emits — the module
        maps its own vocabulary explicitly and never guesses a severity.
    """
    return _VOCABULARY.map_severity(status)


def _evidence(source: Mapping[str, Any], keys: Sequence[str]) -> dict[str, Any]:
    """The truthy subset of *source* under *keys*, for a finding's evidence."""
    return {key: source[key] for key in keys if source.get(key)}


def normalize(report: Mapping[str, Any]) -> tuple[NormalizedFinding, ...]:
    """Turn one marshalled DNSSECReport dict into normalized findings.

    Always yields the overall chain-of-trust finding; adds one finding per
    non-secure delegation (keyed on ``dnssec.delegation.<status>`` + the
    zone) and one for a non-secure leaf, so a report with a broken link
    surfaces both the summary verdict and the specific failure.
    """
    domain = report.get("domain", "")
    # Normalize once: map_status_severity is case- and space-insensitive, so the
    # title lookup and check-id suffixes must use the same canonical value or a
    # HIGH finding could read with the "error" title and a mixed-case check id.
    status = str(report.get("status", "error")).strip().lower()
    findings: list[NormalizedFinding] = [
        NormalizedFinding(
            check_id=schema.CHECK_CHAIN,
            severity=map_status_severity(status),
            title=_TITLE_BY_STATUS.get(status, _TITLE_BY_STATUS["error"]),
            description=(
                f"chainvalidator validated the DNSSEC chain of trust for "
                f"{domain!r} and reported {status!r}."
            ),
            affected_resource=domain or None,
            evidence=_evidence(
                report, ("status", "trust_anchor_keys", "errors", "warnings")
            ),
        )
    ]

    for link in report.get("chain", []):
        link_status = str(link.get("status", "secure")).strip().lower()
        if link_status == "secure":
            continue
        zone = link.get("zone", "")
        findings.append(
            NormalizedFinding(
                check_id=f"{schema.CHECK_DELEGATION}.{link_status}",
                severity=map_status_severity(link_status),
                title=f"Delegation {zone} is {link_status}",
                description=(
                    f"The delegation to {zone!r} from "
                    f"{link.get('parent_zone') or 'the root'!r} is {link_status}."
                ),
                affected_resource=zone or None,
                evidence=_evidence(
                    link, ("ds_records", "dnskeys", "errors", "warnings", "notes")
                ),
            )
        )

    leaf = report.get("leaf")
    if leaf is not None:
        leaf_status = str(leaf.get("status", "secure")).strip().lower()
        if leaf_status != "secure":
            qname = leaf.get("qname", domain)
            findings.append(
                NormalizedFinding(
                    check_id=f"{schema.CHECK_LEAF}.{leaf_status}",
                    severity=map_status_severity(leaf_status),
                    title=f"Leaf record {qname} is {leaf_status}",
                    description=(
                        f"The {leaf.get('record_type', '?')} record at {qname!r} "
                        f"is {leaf_status}."
                    ),
                    affected_resource=qname or None,
                    evidence=_evidence(
                        leaf, ("records", "nxdomain", "nodata", "errors", "warnings")
                    ),
                )
            )

    return tuple(findings)


def summarize(report: Mapping[str, Any]) -> dict[str, Any]:
    """A small, render-ready aggregate of one DNSSECReport dict."""
    chain = report.get("chain", [])

    def _status(item: Mapping[str, Any]) -> str:
        return str(item.get("status", "")).strip().lower()

    return {
        "status": _status(report),
        "secure": _status(report) == "secure",
        "zone_count": len(chain),
        "insecure_delegations": sum(1 for link in chain if _status(link) == "insecure"),
        "bogus_delegations": sum(1 for link in chain if _status(link) == "bogus"),
    }
