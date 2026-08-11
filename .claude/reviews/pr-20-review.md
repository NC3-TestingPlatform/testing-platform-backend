# PR Review: #20 — nc3_app runtime role + grant matrix (Taiga #163)

**Reviewed**: 2026-08-11
**Author**: adanjon (Claude-assisted)
**Branch**: feature/163-database-role-strategy → feature/161-data-model-v4.0.2 (stacked; retargets to main when #18 merges)
**Decision**: APPROVE

## Summary

Hand-written role revision plus design note and forward wiring. The grant
matrix implements the data model's append-only rules in the database; the doc
records the B5 design decisions (org-context GUC, guest rows, platform-admin
path, FORCE off) so the RLS work starts from a written baseline.

## Findings

### CRITICAL
None. No secrets in DDL or committed files — `NC3_APP_DB_PASSWORD=nc3_app` in
`.env.example` is a development default consistent with the file's existing
dev-only credentials (`postgres`/`postgres`, `rabbitmq`/`rabbitmq`); the
Dokploy stack `:?`-requires a real value and README documents it.

### HIGH
None.

### MEDIUM
1. `DROP ROLE` in the downgrade fails if another database in the cluster still
   holds grants to `nc3_app`. Documented in the revision docstring and
   database-roles.md; single-database dev/CI (the only current consumers) is
   unaffected. No action.

### LOW
1. The blanket `GRANT ... ON ALL TABLES` snapshots the tables existing at the
   revision; future tables need per-revision grants. This is deliberate
   (reviewable privilege surface) and documented in both docs plus the
   migrations doc's autogenerate blind-spot list.

## Independent pass (ecc:database-reviewer agent, 2026-08-11)

Second, independent review of the full PR diff. **No CRITICAL/HIGH.**
Verified clean: idempotent CREATE pattern, no missing sequence/function/CONNECT
grants (UUIDv7 PKs are app-side, no sequences exist), REVOKE matrix accuracy by
table name, downgrade ordering ahead of the initial-schema drop, doc-to-SQL
accuracy, secret handling (`.env.example` dev-defaults convention, Dokploy
`:?`-required), and that `APP_DATABASE_URL` is referenced nowhere in `src/`.

- MEDIUM: the "one GRANT per new table" rule has no automated enforcement until
  the B5 isolation suite (Taiga #166) connects as `nc3_app`. **Accepted**: the
  suite is the designed gate and moved to US #81 [B5] by explicit decision;
  until the B5 cutover the app connects as the owning role, so a missed grant
  cannot bite in production before the suite exists.
- MEDIUM: `DROP ROLE` in downgrade is cluster-scoped and fails opaquely when
  another database holds grants. **Fixed** (commit 9d5bc36): wrapped in a DO
  block raising an actionable message pointing at database-roles.md.
- LOW: role attributes relied on server defaults. **Fixed** (commit 9d5bc36):
  `CREATE ROLE` now spells out NOSUPERUSER/NOCREATEDB/NOCREATEROLE/
  NOBYPASSRLS/NOREPLICATION; `pg_roles` probed after upgrade —
  `f|f|f|f|f|t` (login only).
- LOW: `GRANT USAGE ON SCHEMA public` is redundant under PG 15+ defaults.
  **Fixed** (commit 9d5bc36): kept as defense-in-depth with a comment saying
  exactly that.

Post-fix validation re-run: lint, upgrade head, attribute probe, downgrade
(role gone), upgrade head, `alembic check` — all green on PostgreSQL 18.4.

## Validation Results

| Check | Result |
|---|---|
| Lint (ruff) | Pass |
| Type check (pyright) | Pass |
| Tests (pytest, 116) | Pass |
| `alembic upgrade head` → fa547b13b972 (PostgreSQL 18.4) | Pass |
| `alembic check` | Pass |
| `downgrade base` → role dropped (pg_roles count 0) → `upgrade head` | Pass |
| Grant probes (`has_table_privilege`) | Pass — statement_response UPDATE=f/INSERT=t, audit_event DELETE=f, scan_job UPDATE=t, alembic_version SELECT=f |
| `docker compose config` | Pass |

## Files Reviewed

- `docs/database-roles.md` — Added (design note)
- `migrations/versions/2026_08_11_fa547b13b972_nc3_app_role_and_grants.py` — Added (hand-written)
- `docs/database-migrations.md` — Modified (grants blind-spot bullet)
- `README.md` — Modified (roles-doc link, Dokploy env list)
- `.env.example` — Modified (NC3_APP_DB_PASSWORD)
- `infra/compose/api.yml`, `infra/compose/celery.yml` — Modified (APP_DATABASE_URL)
- `docker-compose.dokploy.yml` — Modified (APP_DATABASE_URL, `:?`-required)
