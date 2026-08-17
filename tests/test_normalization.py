"""Tests for the result-normalization layer (US #77 / B2c, IDR-018).

The layer is pure, so every test here is a plain function over plain data — no
broker, no database, no network, and no engine. It carries a 100 % branch
coverage gate (task #206), which is affordable precisely because the package is
small and pure; the assertions are all behavioural, so the gate cannot be
satisfied by touching a line without checking what it does.
"""

import uuid
from datetime import UTC, datetime
from types import MappingProxyType

import pytest

from nc3_testing_platform.core.enums import FindingSeverity, ScanGrade
from nc3_testing_platform.domains.findings.models import Finding
from nc3_testing_platform.domains.scans.models import ScanResult
from nc3_testing_platform.modules import contract
from nc3_testing_platform.modules.normalization import (
    findings as finding_rules,
)
from nc3_testing_platform.modules.normalization import (
    grading,
    rows,
)
from nc3_testing_platform.modules.normalization import (
    severity as severity_rules,
)

SCAN_TASK_ID = uuid.UUID("0198f3a0-0000-7000-8000-000000000001")
SCAN_RESULT_ID = uuid.UUID("0198f3a0-0000-7000-8000-000000000002")
ORGANIZATION_ID = uuid.UUID("0198f3a0-0000-7000-8000-000000000003")
COMPLETED_AT = datetime(2026, 8, 17, 12, 30, tzinfo=UTC)


def _finding(
    check_id: str = "web.noop.ran",
    severity: FindingSeverity = FindingSeverity.INFO,
    **overrides: object,
) -> contract.NormalizedFinding:
    """One valid `NormalizedFinding`, with per-test field overrides."""
    fields: dict = {
        "check_id": check_id,
        "severity": severity,
        "title": "A finding",
        "description": "Something the engine observed.",
    }
    fields.update(overrides)
    return contract.NormalizedFinding(**fields)


def _result(
    *normalized: contract.NormalizedFinding, **overrides: object
) -> contract.ModuleResult:
    """One valid `ModuleResult` carrying *normalized*."""
    fields: dict = {
        "schema_version": "noop/1.0",
        "raw_output": {"verdict": "ok"},
        "summary": {"findings": len(normalized)},
        "findings": normalized,
    }
    fields.update(overrides)
    return contract.ModuleResult(**fields)


# --- severity: the declared vocabulary ---------------------------------------


def test_vocabulary_maps_its_declared_values_case_and_space_blind() -> None:
    """A declared value is matched however the engine spells it."""
    vocabulary = severity_rules.CHAINVALIDATOR_STATUS
    for spelling in ("bogus", "BOGUS", " Bogus "):
        assert vocabulary.map_severity(spelling) is FindingSeverity.HIGH


def test_vocabulary_refuses_a_value_it_does_not_declare() -> None:
    """An unmapped value raises; the layer never guesses a severity."""
    with pytest.raises(ValueError, match="no severity mapping"):
        severity_rules.CHAINVALIDATOR_STATUS.map_severity("catastrophic")


def test_vocabulary_canonicalizes_its_table_once_at_construction() -> None:
    """Declared keys are folded, so lookup does no per-call normalization."""
    vocabulary = severity_rules.EngineVocabulary(
        name="loud-engine", table={" DISASTER ": FindingSeverity.CRITICAL}
    )
    assert dict(vocabulary.table) == {"disaster": FindingSeverity.CRITICAL}
    assert vocabulary.map_severity("disaster") is FindingSeverity.CRITICAL


def test_vocabulary_table_is_read_only() -> None:
    """A declared table cannot be mutated after construction."""
    assert isinstance(severity_rules.VERDICT_SEVERITY.table, MappingProxyType)


def test_vocabulary_must_be_named() -> None:
    """An unnamed vocabulary could not identify itself in an error."""
    with pytest.raises(ValueError, match="must be named"):
        severity_rules.EngineVocabulary(name="   ", table={"x": FindingSeverity.LOW})


def test_vocabulary_must_declare_at_least_one_value() -> None:
    """An empty table maps nothing and is a declaration mistake."""
    with pytest.raises(ValueError, match="declares no values"):
        severity_rules.EngineVocabulary(name="empty-engine", table={})


def test_vocabulary_rejects_an_empty_declared_value() -> None:
    """A blank key would match a blank engine value — reject it at declaration."""
    with pytest.raises(ValueError, match="empty value"):
        severity_rules.EngineVocabulary(
            name="blank-engine", table={"  ": FindingSeverity.LOW}
        )


def test_vocabulary_rejects_two_keys_that_fold_together() -> None:
    """Case-blind matching makes `High` and ` high ` one key, not last-one-wins."""
    with pytest.raises(ValueError, match="twice"):
        severity_rules.EngineVocabulary(
            name="sloppy-engine",
            table={"High": FindingSeverity.HIGH, " high ": FindingSeverity.LOW},
        )


def test_a_vocabulary_is_hashable_and_identified_by_its_name() -> None:
    """`frozen=True` promises dict-key/set-member usability; keep the promise.

    The auto-generated hash would otherwise include the `MappingProxyType`
    table and raise `TypeError` on every call.
    """
    assert hash(severity_rules.VERDICT_SEVERITY) == hash(
        severity_rules.EngineVocabulary(
            name="verdict-severity", table={"info": FindingSeverity.INFO}
        )
    )
    assert len({severity_rules.VERDICT_SEVERITY, severity_rules.VERDICT_SEVERITY}) == 1


def test_verdict_severity_covers_the_whole_platform_vocabulary() -> None:
    """The 1:1 default maps every tier — a new tier cannot be silently unmapped."""
    assert set(severity_rules.VERDICT_SEVERITY.table.values()) == set(FindingSeverity)
    for tier in FindingSeverity:
        assert severity_rules.map_engine_severity(tier.name) is tier


def test_the_registry_lists_every_in_tree_vocabulary_by_name() -> None:
    """`VOCABULARIES` is the lookup, keyed by the name each vocabulary declares."""
    assert severity_rules.VOCABULARIES == {
        "verdict-severity": severity_rules.VERDICT_SEVERITY,
        "chainvalidator-status": severity_rules.CHAINVALIDATOR_STATUS,
    }


def test_the_contract_re_exports_the_owner_rather_than_reimplementing_it() -> None:
    """US #76's published name resolves to the single owner (IDR-018)."""
    assert contract.map_engine_severity is severity_rules.map_engine_severity


# --- grading -----------------------------------------------------------------


def test_every_scan_grade_letter_round_trips() -> None:
    """The mapper's domain is exactly `ScanGrade` — no letter is unreachable."""
    assert {grading.map_engine_grade(grade.value) for grade in ScanGrade} == set(
        ScanGrade
    )


def test_grade_parsing_is_case_and_space_blind() -> None:
    """Engines are inconsistent about spelling; the letter is what matters."""
    assert grading.map_engine_grade(" a+ ") is ScanGrade.A_PLUS
    assert grading.map_engine_grade("d") is ScanGrade.D


def test_the_graded_engines_emit_exactly_the_platform_letters() -> None:
    """A drift guard on the three grading engines' letter vocabulary.

    mailvalidator, headersvalidator and tlsvalidator each emit ``A+ A B C D``
    with an ``F`` fallback. They are not backend dependencies — the worker
    images provision them (B1) — so the vocabulary is pinned here as a literal
    rather than imported: if an engine ever adds a letter, this list and the
    mapper have to be revisited together.
    """
    engine_letters = ("A+", "A", "B", "C", "D", "F")
    assert {grading.map_engine_grade(letter) for letter in engine_letters} == set(
        ScanGrade
    )


def test_an_unknown_grade_raises_rather_than_falling_back_to_f() -> None:
    """Silently grading a scan the worst letter is a data-integrity bug."""
    with pytest.raises(ValueError, match="is not one of"):
        grading.map_engine_grade("E")


def test_the_enum_member_spelling_is_rejected_not_aliased() -> None:
    """`A_PLUS` is a Python name for the value; no engine emits it."""
    with pytest.raises(ValueError, match="is not one of"):
        grading.map_engine_grade("A_PLUS")


# --- findings: check_id, counts, ordering ------------------------------------


def test_a_namespaced_check_id_is_accepted_and_returned_unchanged() -> None:
    """The validator is a guard, not a transformer."""
    assert (
        finding_rules.validate_check_id("dnssec.leaf.bogus", module_namespace="dnssec")
        == "dnssec.leaf.bogus"
    )


@pytest.mark.parametrize(
    "check_id",
    ["dnssec", "DNSSEC.chain", "dnssec..chain", "dnssec.chain-of-trust", ""],
)
def test_a_check_id_outside_the_vocabulary_is_refused(check_id: str) -> None:
    """Single-segment, uppercase, empty-segment and hyphenated ids all fail."""
    with pytest.raises(ValueError, match="namespaced text"):
        finding_rules.validate_check_id(check_id, module_namespace="dnssec")


def test_a_check_id_must_sit_under_its_own_module_namespace() -> None:
    """A finding is attributable to a module by its identifier alone."""
    with pytest.raises(ValueError, match="namespace"):
        finding_rules.validate_check_id("web.headers.hsts", module_namespace="dnssec")


def test_severity_counts_always_carry_all_five_bands() -> None:
    """A zero band is reported as 0, never omitted (`SeverityCounts` defaults)."""
    assert finding_rules.severity_counts(()) == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_severity_counts_tally_each_band() -> None:
    """Counts are a straight tally of the normalized findings."""
    counted = finding_rules.severity_counts(
        (
            _finding("web.a", FindingSeverity.HIGH),
            _finding("web.b", FindingSeverity.HIGH),
            _finding("web.c", FindingSeverity.INFO),
        )
    )
    assert counted == {"critical": 0, "high": 2, "medium": 0, "low": 0, "info": 1}


def test_findings_sort_by_severity_then_check_id_then_resource() -> None:
    """A shuffled input produces one fixed order, so a re-run is byte-identical."""
    shuffled = (
        _finding("web.z", FindingSeverity.INFO),
        _finding("web.a", FindingSeverity.CRITICAL, affected_resource="b.example"),
        _finding("web.a", FindingSeverity.CRITICAL, affected_resource="a.example"),
        _finding("web.b", FindingSeverity.MEDIUM),
        _finding("web.a", FindingSeverity.MEDIUM),
    )
    ordered = finding_rules.order_findings(shuffled)
    assert [
        (item.check_id, item.severity.value, item.affected_resource) for item in ordered
    ] == [
        ("web.a", "critical", "a.example"),
        ("web.a", "critical", "b.example"),
        ("web.a", "medium", None),
        ("web.b", "medium", None),
        ("web.z", "info", None),
    ]


def test_findings_tied_on_rule_and_resource_are_ordered_by_title() -> None:
    """One rule may raise several findings about the same resource.

    Without a fourth sort key these tie, and a stable sort then falls back to
    input order — engine iteration order — which is the non-determinism
    `order_findings` exists to remove.
    """
    tied = (
        _finding("dnssec.zone", FindingSeverity.LOW, affected_resource="example.",
                 title="Zone serial is stale"),
        _finding("dnssec.zone", FindingSeverity.LOW, affected_resource="example.",
                 title="NSEC3 iterations are high"),
    )
    forwards = finding_rules.order_findings(tied)
    backwards = finding_rules.order_findings(tuple(reversed(tied)))
    assert [item.title for item in forwards] == [
        "NSEC3 iterations are high",
        "Zone serial is stale",
    ]
    assert forwards == backwards


def test_ordering_is_stable_under_a_reversed_input() -> None:
    """Sorting the same set from the other end yields the identical sequence."""
    unordered = (
        _finding("web.b", FindingSeverity.LOW),
        _finding("web.a", FindingSeverity.LOW),
    )
    assert finding_rules.order_findings(unordered) == finding_rules.order_findings(
        tuple(reversed(unordered))
    )


def test_every_severity_tier_has_a_persistence_rank() -> None:
    """A new tier without a rank would raise mid-sort; fail here instead."""
    assert set(finding_rules._SEVERITY_RANK) == set(FindingSeverity)


# --- rows: the pure mappers --------------------------------------------------


def _scan_result_row(**overrides: object) -> dict:
    """`scan_result_row` over a one-finding result, with argument overrides."""
    kwargs: dict = {
        "scan_task_id": SCAN_TASK_ID,
        "completed_at": COMPLETED_AT,
        "organization_id": ORGANIZATION_ID,
    }
    kwargs.update(overrides)
    return rows.scan_result_row(_result(_finding()), **kwargs)


def _finding_rows(result: contract.ModuleResult) -> list[dict]:
    """`finding_rows` over *result*, with the fixed synthetic identifiers."""
    return rows.finding_rows(
        result, scan_result_id=SCAN_RESULT_ID, organization_id=ORGANIZATION_ID
    )


def test_the_scan_result_row_matches_its_orm_columns() -> None:
    """Every column but the database-assigned `id` is produced (§8.1)."""
    assert set(_scan_result_row()) == set(ScanResult.__table__.columns.keys()) - {"id"}


def test_the_scan_result_row_derives_severity_counts() -> None:
    """The count is platform-derived from the findings, not module-supplied."""
    row = rows.scan_result_row(
        _result(
            _finding("web.a", FindingSeverity.HIGH),
            _finding("web.b", FindingSeverity.INFO),
        ),
        scan_task_id=SCAN_TASK_ID,
        completed_at=COMPLETED_AT,
        organization_id=ORGANIZATION_ID,
    )
    assert row["severity_counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 1,
    }


def test_the_scan_result_row_carries_the_callers_task_clock_and_tenancy() -> None:
    """Nothing is resolved or read here: all three arrive from the caller."""
    row = _scan_result_row()
    assert row["scan_task_id"] == SCAN_TASK_ID
    assert row["completed_at"] == COMPLETED_AT
    assert row["organization_id"] == ORGANIZATION_ID


def test_a_guest_scan_maps_a_null_organization() -> None:
    """`organization_id` is nullable — a guest job has no organization."""
    assert _scan_result_row(organization_id=None)["organization_id"] is None


def test_an_ungraded_module_leaves_the_grade_null() -> None:
    """Most tests do not grade; `grade` passes through as the module set it."""
    assert _scan_result_row()["grade"] is None


def test_a_graded_module_passes_its_grade_through() -> None:
    """A graded result carries its letter onto the row unchanged."""
    row = rows.scan_result_row(
        _result(_finding(), grade=ScanGrade.B),
        scan_task_id=SCAN_TASK_ID,
        completed_at=COMPLETED_AT,
        organization_id=ORGANIZATION_ID,
    )
    assert row["grade"] is ScanGrade.B


def test_the_finding_rows_match_their_orm_columns_minus_the_deferred_ones() -> None:
    """`id` is database-assigned and `status` is B12a's; everything else is here."""
    produced = _finding_rows(_result(_finding()))
    assert set(produced[0]) == set(Finding.__table__.columns.keys()) - {"id", "status"}


def test_the_finding_rows_never_carry_a_status() -> None:
    """Historical classification needs history, which a single result has not."""
    assert "status" not in _finding_rows(_result(_finding()))[0]


def test_the_finding_rows_come_out_in_persistence_order() -> None:
    """Row order is the deterministic order, not the engine's emission order."""
    produced = _finding_rows(
        _result(
            _finding("web.z", FindingSeverity.INFO),
            _finding("web.a", FindingSeverity.CRITICAL),
        )
    )
    assert [row["check_id"] for row in produced] == ["web.a", "web.z"]


def test_a_result_with_no_findings_maps_to_no_rows() -> None:
    """A clean scan stores a result and zero findings, not an empty placeholder."""
    assert _finding_rows(_result()) == []


def test_json_payloads_leave_as_plain_containers() -> None:
    """A tuple does not survive the JSONB boundary; a list does."""
    produced = _finding_rows(
        _result(
            _finding(
                evidence={"records": ["a", "b"]},
                external_references=("https://example.test/rule",),
            )
        )
    )
    assert produced[0]["evidence"] == {"records": ["a", "b"]}
    assert produced[0]["external_references"] == ["https://example.test/rule"]


def test_absent_evidence_stays_null_rather_than_becoming_an_empty_object() -> None:
    """The column is nullable: no evidence and empty evidence are different rows."""
    assert _finding_rows(_result(_finding()))[0]["evidence"] is None


def test_empty_evidence_is_preserved_as_an_empty_object() -> None:
    """`{}` is a deliberate statement by the module and is stored as one."""
    assert _finding_rows(_result(_finding(evidence={})))[0]["evidence"] == {}


def test_the_result_row_does_not_alias_the_results_payloads() -> None:
    """Editing a produced row must not reach back into the `ModuleResult`.

    Deliberately mutates *nested* structures, not just top-level keys: a
    shallow `dict()` copy passes a top-level check while still sharing every
    nested list and dict, which is the aliasing that actually bites when B12a
    holds the result and the rows at the same time.
    """
    result = _result(
        _finding(),
        raw_output={"chain": [{"zone": ".", "status": "secure"}]},
        summary={"counts": {"zones": 1}},
    )
    row = rows.scan_result_row(
        result,
        scan_task_id=SCAN_TASK_ID,
        completed_at=COMPLETED_AT,
        organization_id=ORGANIZATION_ID,
    )
    row["raw_output"]["chain"][0]["status"] = "tampered"
    row["summary"]["counts"]["zones"] = 99
    assert result.raw_output["chain"][0]["status"] == "secure"
    assert result.summary["counts"]["zones"] == 1


def test_the_finding_rows_do_not_alias_the_findings_evidence() -> None:
    """Nested evidence is copied out, so a row edit cannot corrupt the finding."""
    result = _result(_finding(evidence={"records": ["a"]}))
    row = _finding_rows(result)[0]
    row["evidence"]["records"].append("tampered")
    assert result.findings[0].evidence == {"records": ["a"]}
