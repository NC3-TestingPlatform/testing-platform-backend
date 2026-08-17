# The result-normalization layer

`nc3_testing_platform.modules.normalization` — US #77 (B2c), decided by
**IDR-018**.

US #76 delivered the *shapes* a module returns: `NormalizedFinding`,
`ModuleResult`, and a per-module `map_severity` hook. It deliberately left one
question open — **who owns the translation into them**. This layer answers it,
and supplies the two derivations nothing in the backend computed before:
`scan_result.severity_counts`, and an engine letter grade reconciled onto
`ScanGrade`.

Everything here is a pure function over plain data. No database session, no
clock read, no network, no engine import.

## The four surfaces

| Module | Owns |
|---|---|
| `severity` | The platform severity vocabulary, the strict unknown-value policy, and the registry of engine severity tables |
| `grading` | Engine letter grade → `ScanGrade`, a strict parse |
| `findings` | `check_id` vocabulary, severity counts, deterministic ordering |
| `rows` | `ModuleResult` → `scan_result` / `finding` row dicts |

The package `__init__.py` re-exports nothing on purpose: `modules.contract`
imports `normalization.severity` (to keep US #76's published
`contract.map_engine_severity` name working) while `normalization.findings` and
`normalization.rows` import the contract's dataclasses. Re-exporting would close
that into an import cycle, so consumers import the submodule they want —
`from nc3_testing_platform.modules.normalization import rows` — the same way the
DNSSEC module imports its own `schema`.

## 1. Severity — declare a table, not a mapper

The ownership IDR-018 settles on is **hybrid**: the platform owns the *policy*,
modules own the *tables*. A module does not write lookup logic; it declares an
`EngineVocabulary`, and the layer owns how a value is canonicalized and what an
unmapped one does.

```python
from nc3_testing_platform.core.enums import FindingSeverity
from nc3_testing_platform.modules.normalization.severity import EngineVocabulary

MY_ENGINE_STATUS = EngineVocabulary(
    name="my-engine-status",
    table={"clean": FindingSeverity.INFO, "broken": FindingSeverity.HIGH},
)

MY_ENGINE_STATUS.map_severity(" BROKEN ")   # FindingSeverity.HIGH
MY_ENGINE_STATUS.map_severity("weird")      # ValueError
```

Construction validates the declaration once, so a typo fails at import time
rather than mid-scan: the vocabulary must be named, must declare at least one
value, may not declare a blank value, and may not declare two keys that fold
together (`"High"` and `" high "` are the same key, not last-one-wins). The
resulting `table` is a read-only view keyed by canonical value.

Matching is case- and space-insensitive because engines are inconsistent about
both. Everything else is strict — **an unknown value raises**. There is no
silent `INFO` fallback anywhere in the layer: a vocabulary the platform does not
know is a module bug, and a wrong severity is worse than a failed task.

### Why the hook survives

`TestModule.map_severity` stays a per-module hook because chainvalidator's
four-value `secure / insecure / bogus / error` genuinely is not the engines'
five-tier `VerdictSeverity`, and no single table holds both. What changed is
that a module now points the hook at a declared table:

```python
_VOCABULARY = severity_rules.CHAINVALIDATOR_STATUS

def map_status_severity(status: str) -> FindingSeverity:
    return _VOCABULARY.map_severity(status)
```

Rejected alternatives are recorded in IDR-018: full centralization (kills
per-engine extensibility and forces a core edit per new engine vocabulary), and
leaving it per-module (the status quo, under which "single owner" is
unenforceable).

### The registry

`VOCABULARIES` maps name → vocabulary for everything that ships in-tree:

| Name | Vocabulary |
|---|---|
| `verdict-severity` | The engines' five-tier `VerdictSeverity`, 1:1 onto `FindingSeverity`. Built from `FindingSeverity` itself so the 1:1 cannot drift |
| `chainvalidator-status` | `secure`→INFO, `insecure`→MEDIUM, `bogus`→HIGH, `error`→LOW |

It is an immutable snapshot, **not** a mutable registry modules write into at
import time — what the platform knows must not depend on which modules happen to
have been imported. An out-of-tree module package constructs its own
`EngineVocabulary` and holds it as a module-level constant.

`severity.map_engine_severity` is the `verdict-severity` lookup, and is what
`contract.map_engine_severity` now resolves to — re-exported, not
re-implemented, so there is exactly one definition of what an unknown severity
does.

## 2. Grading — reconciliation, not conversion

```python
grading.map_engine_grade(" a+ ")     # ScanGrade.A_PLUS
grading.map_engine_grade("E")        # ValueError
grading.map_engine_grade("A_PLUS")   # ValueError — a Python name, not a grade
```

mailvalidator, headersvalidator and tlsvalidator each emit exactly
`A+ A B C D` with an `F` fallback, which is precisely the six `ScanGrade`
members, so the letter crosses the boundary unchanged.

What does *not* cross is the meaning. The engines' penalty thresholds differ —
mail `0/10/20/30/40`, headers and tls `0/5/20/40/60` — so a `B` from one engine
is not a `B` from another. **A grade is comparable only against the same test's
own history.** There is deliberately no rescaling, no averaging, and no
cross-module composite, which is data-model §8.1's "No cross-module composite
score is stored" restated as code.

There is also no `F` fallback for an unparseable grade: silently grading a scan
the worst possible letter is a data-integrity bug, not a safe default.

No v4.0 module populates `ModuleResult.grade` yet — the dnssec exemplar and the
noop reference do not grade. The first consumers are the M-stories for
`email.mailvalidator`, `web.headers` and `web.tls`.

## 3. Findings — identity, counts, order

Three rules that no single module can own, because each is a statement about how
*all* findings compare with one another.

**`check_id` vocabulary.** The stable anchor regression matching keys on (§8.2).
Same shape as `test_key` — at least two lowercase segments joined by dots — and
it must carry its module's namespace, so a finding is attributable to a module
by its identifier alone.

```python
findings.validate_check_id("dnssec.leaf.bogus", module_namespace="dnssec")
```

**Severity counts.** Platform-derived from the normalized findings, never
supplied by a module, so two modules cannot disagree about what a count means.
All five bands are always present, zeros included — matching the
`SeverityCounts` schema, whose fields each default to 0. A consumer reading
`counts["critical"]` must never have to distinguish "no critical findings" from
"this module does not report criticals".

**Deterministic ordering.** Severity descending, then `check_id`, then
`affected_resource`, then `title`, then the remaining persisted fields
(`description`, `remediation`, canonical-JSON `evidence`,
`external_references`). A re-run of an unchanged scan therefore produces
byte-identical rows in an identical sequence, so a diff between two results is
a real change rather than engine iteration order.

The tail of the key exists because the order must be **total over persisted
content**. `check_id` and `affected_resource` are what regression matching
keys on, but one rule may legitimately raise several findings about the same
resource — and two findings can even share a title while differing in evidence.
Any tie left in the key makes Python's stable sort fall back to input order,
which *is* engine iteration order: exactly what this function exists to remove.
Findings identical in every persisted field are interchangeable for ordering by
definition. `evidence` enters the key as canonical JSON (`sort_keys=True`), so
two dicts differing only in insertion order do not order differently. The key
is plain `int`/`str` throughout — nothing hash-derived — so the order
reproduces across processes and `PYTHONHASHSEED` values.

The severity ranking is written out explicitly rather than derived from the
enum's declaration order, which is incidental to how the enum is declared and
would silently re-sort every stored result if a member were ever moved.

## 4. Rows — the last step before the database, and not the database step

```python
result_row = rows.scan_result_row(
    module_result,
    scan_task_id=task.id,
    completed_at=finished_at,
    organization_id=task.organization_id,
)
# … the caller writes it and flushes …
finding_rows = rows.finding_rows(
    module_result,
    scan_result_id=written.id,
    organization_id=task.organization_id,
)
```

Two calls, not one, because `finding.scan_result_id` does not exist until the
result row is written.

### The boundary, restated because it is easy to erode

| Not done here | Owner |
|---|---|
| Opening a session, writing rows | B8 / US #84 |
| Resolving `organization_id` | The caller — supplied, never looked up |
| Reading a clock for `completed_at` | The caller — the platform owns the timeline |
| `finding.status` (new / regression / persistent / resolved) | B12a / US #87 — needs history, which one result does not have |
| RLS revalidation | B5 / US #81 |

The produced key sets are the ORM columns of §8.1 and §8.2 minus the
database-assigned `id`, and for findings minus `status`. Tests assert that
against `ScanResult.__table__.columns` and `Finding.__table__.columns` directly,
so a migration that adds a column breaks the mapper's test rather than silently
dropping data.

`evidence` and `external_references` are copied out to plain JSON-shaped
containers — a `tuple` does not survive the JSONB boundary. `evidence` preserves
the `None` / `{}` distinction: the column is nullable, and a finding that
carries no evidence is not the same as one that carries an empty object.

The copies are **deep**, for the same reason `contract._snapshot` is. A shallow
`dict()` shares every nested list and dict with the `ModuleResult`, so a caller
editing a row — redacting a field, stripping a key before write — would reach
back and mutate the result it was derived from. B12a / US #87 holds both at once
when it compares this run's findings against history, so that aliasing is a live
hazard, not a theoretical one. The tests mutate *nested* structures specifically,
because a top-level-only check passes against a shallow copy and proves nothing.

## Worked example — the DNSSEC insecure fixture

Running `tests/fixtures/dnssec/insecure.json` (an unsigned `example.`
delegation) through the module and then the mappers:

```text
summary          {"status": "insecure", "secure": false, "zone_count": 2,
                  "insecure_delegations": 1, "bogus_delegations": 0}
severity_counts  {"critical": 0, "high": 0, "medium": 3, "low": 0, "info": 0}
grade            None                      # dnssec does not grade

severity  check_id                     affected_resource
medium    dnssec.chain_of_trust        insecure-zone.example
medium    dnssec.delegation.insecure   example.
medium    dnssec.leaf.insecure         insecure-zone.example.
```

Three findings, all MEDIUM because `chainvalidator-status` maps `insecure`
there; the counts carry all five bands; the grade stays `None`; and the rows
come out in `check_id` order because the severities tie.

## Testing

The layer carries a **100 % branch-coverage gate** (task #206), enforced by a
dedicated CI step scoped to this package and run from
`tests/test_normalization.py` alone — so the gate proves *this* suite is
complete rather than borrowing coverage from the module tests. The rest of the
backend is nowhere near 100 % and a repo-wide gate would red every build.

```bash
uv run --locked pytest tests/test_normalization.py \
  --cov=nc3_testing_platform.modules.normalization \
  --cov-branch --cov-fail-under=100
```

A 100 % gate is a magnet for coverage theatre, so the suite is deliberately
behavioural: no test asserts `is not None`, every test names the rule it is
pinning, and several assert *domains* rather than examples —
`VERDICT_SEVERITY`'s values cover `FindingSeverity`, `map_engine_grade`'s
reachable results cover `ScanGrade`, and the severity ranking covers every tier.
A new enum member therefore breaks CI instead of silently going unmapped.
