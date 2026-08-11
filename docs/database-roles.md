# Database roles

Two PostgreSQL roles, two jobs. Migrations run as the **owning role** — the
`postgres` superuser in the local Compose stack, whatever owner the deployment
provisions — and own every object they create. The application connects as
**`nc3_app`**, a runtime role that can touch data but never the schema. The
split is the foundation the B5 row-level-security work builds on: RLS policies
bind to `nc3_app`, while the owning role keeps its bypass so migrations and
operational surgery stay possible.

## The roles

| Role | Who connects as it | Privileges |
|---|---|---|
| owning role (`postgres` in dev) | Alembic (`make db-*`), operators | Superuser/owner: DDL, grants, everything. Will bypass RLS (owner, `FORCE` off). |
| `nc3_app` | API service, Celery workers — **planned**: both still connect as the owning role via `DATABASE_URL` until the B5 session-layer cutover (see below) | `SELECT`/`INSERT`/`UPDATE`/`DELETE` on application tables — minus the exceptions below. No DDL, no role management, no `alembic_version`. |

Exceptions to the blanket data grant, from the data model's append-only rules
(§5.2, §12.1): `nc3_app` has **no `UPDATE` or `DELETE` on `statement_response`
and `audit_event`**. A statement response is corrected by a new statement
version and a new response; an audit event is never touched. The database
refuses what application discipline would otherwise have to promise.

`alembic_version` is revoked entirely: the runtime has no business reading or
writing migration state.

## Where the role comes from

The role and its grants are created by a hand-written Alembic revision
(`nc3_app role and grants`). Roles are cluster-level, so the revision creates
it idempotently — `CREATE ROLE` with the `duplicate_object` error trapped, so
even two databases of one cluster upgrading concurrently cannot collide — and
then re-asserts the role's attributes, so a pre-existing `nc3_app` cannot
carry `BYPASSRLS` (or any other attribute) past the revision. It refuses to
proceed while `nc3_app` holds any role membership: inherited privileges would
bypass the grant matrix, and revoking cluster-level memberships some other
database may rely on is the operator's call, not the migration's. As a final
gate it validates the role's *effective* privileges (`has_table_privilege`) —
catching grants made to `PUBLIC` out of band, which reach every role and which
no `REVOKE ... FROM nc3_app` overrides. A second database migrated in the same
cluster reuses the existing role, and re-running the revision after a partial
downgrade cannot collide.

**No password appears in any migration.** The revision creates the role with
`LOGIN` but no credential; each environment sets its own:

- **Development**: `NC3_APP_DB_PASSWORD` in `.env` (see `.env.example`), applied
  once per PostgreSQL cluster — the role and its password are cluster-level
  state, shared by every database in it:

  ```bash
  docker compose exec postgres psql -U postgres -d nc3_testing_platform \
    -c "ALTER ROLE nc3_app PASSWORD 'nc3_app'"
  ```

- **Dokploy**: set `NC3_APP_DB_PASSWORD` in the application's environment tab
  and run the same `ALTER ROLE` against the deployment database.

The API and worker services carry an `APP_DATABASE_URL` environment variable
wired to `nc3_app`. Nothing reads it yet — the application still connects with
`DATABASE_URL` as the owning role until the session layer lands — the same
forward-wiring the compose stack used for `CELERY_BROKER_URL` before Celery
existed. Cutting the application over to `APP_DATABASE_URL` is part of the B5
multi-tenancy work, together with the RLS policies and the org-context
(`SET LOCAL`) plumbing.

## Rules for future revisions

- **Autogenerate never sees grants** (or roles, or RLS). Every revision that
  creates a table must `GRANT` on it by hand in the same revision — and
  `REVOKE UPDATE, DELETE` again if the new table is append-only. See
  [database-migrations.md](database-migrations.md).
- The blanket `GRANT ... ON ALL TABLES IN SCHEMA public` in the role revision
  covers only tables existing when it runs; it is not a default privilege and
  does not extend to future tables. That is deliberate — an explicit grant per
  table keeps the privilege surface reviewable in the diff.
- The B5 two-org isolation suite (Taiga #166) is the regression gate: it
  connects as `nc3_app` and asserts the grant matrix, including the
  append-only refusals.

## Decisions recorded for B5 (design, not yet implemented)

- **Org context injection**: one GUC per transaction —
  `SET LOCAL app.org_id = '<uuid>'` — set by the session layer per request and
  by the Celery result-write path per task (re-asserted from the job's
  `organization_id`, which is the §13.2 revalidation). `SET LOCAL` is
  transaction-scoped, so pooled connections cannot leak context.
- **Guest scans**: represented by `organization_id IS NULL` (data model
  §7.1), not a sentinel organization. Guest rows get their own narrow policy
  in B5; they are visible to no organization.
- **Platform-admin access**: an explicit separate path (dedicated role or
  policy) designed in B5 — never an exception carved into the tenant
  policies, and never `nc3_app` with RLS disabled.
- **Migrations bypass**: the owning role bypasses RLS as table owner because
  `FORCE ROW LEVEL SECURITY` stays off. Enabling `FORCE` on a table is a
  deliberate B5-or-later decision, not a default.
