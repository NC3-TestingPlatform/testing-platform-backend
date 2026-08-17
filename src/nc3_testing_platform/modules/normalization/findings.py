"""Finding-level normalization rules: `check_id`, counts, deterministic order.

Three platform-owned rules that no single module can own, because each one is
a statement about how *all* findings compare with one another:

- **`check_id` vocabulary.** The stable anchor regression matching keys on
  (data-model §8.2). Same shape as `test_key` — lowercase namespaced segments
  joined by dots — and it must carry its module's namespace, so a finding can
  be attributed to a module by its identifier alone.
- **Severity counts.** `scan_result.severity_counts`, derived here from the
  normalized findings and never supplied by a module (IDR-018), so two modules
  cannot disagree about what a count means.
- **Deterministic ordering.** Findings are persisted in a fixed order —
  severity descending, then `check_id`, then `affected_resource` — so
  re-running an unchanged scan produces byte-identical rows and a diff between
  two results is a real change rather than engine iteration order.
"""

import json
import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType

from nc3_testing_platform.core.enums import FindingSeverity
from nc3_testing_platform.modules.contract import NormalizedFinding

# Mirrors `contract._TEST_KEY_RE`: at least two lowercase segments joined by
# dots. Deliberately the same shape — a `check_id` extends its module's
# namespace the way a `test_key` does, e.g. `dnssec.chain_of_trust`.
CHECK_ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")

# Persistence order, most severe first. Written out rather than derived from
# the enum's declaration order, which is incidental to how it is declared and
# would silently re-sort every stored result if a member were ever moved.
_SEVERITY_RANK: Mapping[FindingSeverity, int] = MappingProxyType(
    {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4,
    }
)


def validate_check_id(check_id: str, *, module_namespace: str) -> str:
    """Check one `check_id` against the vocabulary rule, returning it unchanged.

    :param check_id: The identifier to validate, e.g. ``"dnssec.leaf.bogus"``.
    :param module_namespace: The owning module's name — the value of the
        module's :class:`~nc3_testing_platform.core.enums.ScanModule` member,
        e.g. ``"dnssec"``. The id must be inside it.
    :raises ValueError: If the id is not namespaced lowercase-dotted text, or
        does not sit under *module_namespace*. Renaming a `check_id` breaks
        regression matching across the whole history of a test, so the shape is
        enforced when it is minted rather than discovered later.
    """
    if not CHECK_ID_RE.fullmatch(check_id):
        raise ValueError(
            f"check_id {check_id!r} is not namespaced text of the form "
            "'<module>.<rule>' (lowercase segments joined by dots)."
        )
    prefix = f"{module_namespace}."
    if not check_id.startswith(prefix):
        raise ValueError(
            f"check_id {check_id!r} does not carry its module's namespace "
            f"{prefix!r}."
        )
    return check_id


def severity_counts(findings: Iterable[NormalizedFinding]) -> dict[str, int]:
    """Count findings per severity band, every band present.

    All five keys are always returned, zeros included, matching the
    `SeverityCounts` schema whose fields each default to 0: a consumer reading
    ``counts["critical"]`` must never have to distinguish "no critical
    findings" from "this module does not report criticals".

    :param findings: The normalized findings of one result.
    :return: A plain dict keyed by `FindingSeverity` value, ready for the
        `scan_result.severity_counts` JSONB column.
    """
    counts = {severity.value: 0 for severity in FindingSeverity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def _order_key(finding: NormalizedFinding) -> tuple[int, str, str, str, str, str, str, str]:
    """The total persistence-order key over every persisted finding field.

    `severity`/`check_id`/`affected_resource` are the identity regression
    matching keys on (§8.2); `title` breaks the tie when one rule raises
    several findings about the same resource. The remaining fields exist
    because the order must be *total* over persisted content: two findings can
    match on all four identity keys and still differ in `description`,
    `remediation`, `evidence`, or `external_references`, and a stable sort
    would then fall back to input order — engine iteration order, the
    non-determinism this module exists to remove.

    `evidence` enters as canonical JSON (`sort_keys=True`, no whitespace
    variance): the contract guarantees it is a JSON-shaped plain tree, and
    canonicalizing keeps two dicts that differ only in insertion order from
    ordering differently. ``None`` and ``{}`` stay distinct (``""`` vs
    ``"{}"``), mirroring the row mapping. Everything in the key is a plain
    `int`/`str` — no set or dict iteration, nothing hash-derived — so the
    order reproduces across processes and `PYTHONHASHSEED` values.
    """
    return (
        _SEVERITY_RANK[finding.severity],
        finding.check_id,
        finding.affected_resource or "",
        finding.title,
        finding.description,
        finding.remediation or "",
        "" if finding.evidence is None else json.dumps(finding.evidence, sort_keys=True),
        json.dumps(list(finding.external_references)),
    )


def order_findings(
    findings: Iterable[NormalizedFinding],
) -> tuple[NormalizedFinding, ...]:
    """Findings in persistence order — a total order over persisted content.

    Severity descending, then `check_id`, then `affected_resource`, then
    `title`, then the remaining persisted fields (see :func:`_order_key`), so
    the ordering never depends on the order the engine produced them in.
    Findings identical in *every* persisted field are interchangeable for
    ordering by definition. `affected_resource` is optional; a finding without
    one sorts before its siblings that have one, which is arbitrary but fixed —
    what matters is that it never varies between runs.

    :param findings: The normalized findings of one result, in any order.
    :return: The same findings, sorted. The input is not mutated.
    """
    return tuple(sorted(findings, key=_order_key))
