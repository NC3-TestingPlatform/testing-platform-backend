"""The result-normalization layer: engine vocabulary → platform vocabulary (B2c).

US #76 delivered the *shapes* — `NormalizedFinding`, `ModuleResult`, and a
per-module `map_severity` hook. This package decides who **owns** the
translation into them (IDR-018) and supplies the two derivations nothing
computed before: `scan_result.severity_counts`, and an engine letter grade
reconciled onto :class:`~nc3_testing_platform.core.enums.ScanGrade`.

The four surfaces, one module each:

- `severity` — the platform severity vocabulary, the strict unknown-value
  policy, and the registry of engine severity tables. The single owner.
- `grading` — engine letter grade → `ScanGrade`, a strict parse.
- `findings` — `check_id` vocabulary rules, severity counts, and the
  deterministic ordering that makes a re-run byte-identical.
- `rows` — pure `ModuleResult` → `scan_result` / `finding` row dicts.

Everything here is a pure function over plain data: no database session, no
clock read, no network. Persistence is B8 / US #84, `finding.status` is
derived from history by B12a / US #87, and RLS revalidation is B5 / US #81.

**Why this file re-exports nothing.** `modules.contract` imports
`normalization.severity` to keep US #76's public `contract.map_engine_severity`
name working, while `normalization.findings` and `normalization.rows` import
the contract's dataclasses. Re-exporting those here would close that loop into
an import cycle, so consumers import the submodule they need —
``from nc3_testing_platform.modules.normalization import rows`` — the same way
the DNSSEC module imports its own `schema`.
"""
