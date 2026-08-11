# PR Review: #18 — Data model v4.0.2 — review-deferred row-level checks (Taiga #161)

**Reviewed**: 2026-08-11
**Author**: adanjon (Claude-assisted)
**Branch**: feature/161-data-model-v4.0.2 → main
**Decision**: APPROVE

## Summary

Doc-first revision closing the ER design review: data-model v4.0.2 folds in the four
constraint candidates deferred from the PR #15 CodeRabbit review, and one Alembic
revision implements them. Doc, models, structural tests, and migration are mutually
consistent; every §14 expression is pinned verbatim by `EXPECTED_CHECKS`.

## Findings

### CRITICAL
None.

### HIGH
None — one was prevented at design time: the candidate expression recorded on Taiga
#162 was `array_length(modules, 1) >= 1`, which never rejects an empty array
(`array_length` of `'{}'` is NULL, and a NULL CHECK passes). Implemented as
`cardinality(modules) >= 1` instead; both empty-array probes rejected live on
PostgreSQL 18.4. The rationale is recorded in the doc's §14 intro and as code
comments on both models.

### MEDIUM
1. `docs/database-migrations.md` claimed CHECK constraints are never detected by
   autogenerate; Alembic 1.19's `checkconstraint_byname` plugin detected all four
   additions by name. **Fixed in this PR** (commit 6a3e730): the blind spot is now
   correctly described as expression-changes-under-an-unchanged-name.

### LOW
1. `purge_within_24_hours` and `purge_not_before_upload` could be one BETWEEN-style
   constraint; kept as two to match the doc's one-row-per-invariant §14 layout and
   avoid dropping/recreating the existing constraint. No action.

## Independent pass (ecc:database-reviewer agent, 2026-08-11)

Second, independent review of the full PR diff. **No CRITICAL/HIGH/MEDIUM.**
Verified clean: NULL semantics (all compared columns NOT NULL), timestamptz on
both sides of temporal CHECKs, `cardinality()` returning 0 (not NULL) on empty
arrays, migration/model 1:1 parity incl. `op.f()` names against the naming
convention, upgrade/downgrade symmetry, no cross-table name collision on
`modules_not_empty`, byte-identical doc §14 / model / EXPECTED_CHECKS strings,
and the Alembic 1.19 doc-correction claim against the pinned version.

One LOW: `op.create_check_constraint` without `NOT VALID` takes an
ACCESS EXCLUSIVE lock + full validation scan — irrelevant pre-release (wipe
rules guarantee empty tables) but a real outage risk if the pattern is reused
post-GA. **Outcome: documented** as rule 5 of the revision-review checklist in
`docs/database-migrations.md` (shipped in PR #20, commit 9d5bc36, which owns
the migrations-doc edits).

## Validation Results

| Check | Result |
|---|---|
| Lint (ruff) | Pass |
| Type check (pyright) | Pass |
| Tests (pytest, 116) | Pass |
| `alembic upgrade head` (PostgreSQL 18.4-trixie) | Pass |
| `alembic check` | Pass (no drift) |
| `downgrade base` → `upgrade head` round trip | Pass (run twice) |
| Constraint rejection probes (audit_event, scan_job) | Pass (both INSERTs rejected) |

## Files Reviewed

- `docs/reference/data-model-v4_0_2.md` — Added (authoritative doc revision)
- `src/nc3_testing_platform/domains/admin/models.py` — Modified (retention CHECK)
- `src/nc3_testing_platform/domains/scans/models.py` — Modified (purge lower bound, modules CHECK)
- `src/nc3_testing_platform/domains/schedules/models.py` — Modified (modules CHECK)
- `tests/test_models.py` — Modified (EXPECTED_CHECKS, doc reference)
- `migrations/versions/2026_08_11_eb34e144eb97_v4_0_2_row_level_checks.py` — Added
- `docs/database-migrations.md` — Modified (autogenerate blind-spot correction)
