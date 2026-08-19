# Database roles

Migrations run as the **owning role** — the `postgres` superuser in the
local Compose stack, whatever owner the deployment provisions — and own every
object they create. The application connects as three non-owner runtime
roles: **`nc3_app`** for tenant work (the API and the scan-queue workers),
**`app_platform`** for cross-organization platform duties (the
platform-queue worker and beat), and **`nc3_auth`** for the credential
surface (the API service alone, B3 / US #79). A fourth, NOLOGIN role —
**`nc3_auth_definer`** — exists only to own the two SECURITY DEFINER auth
lookups. Row-level security
binds to both (IDR-012): every application table carries `ENABLE` **and**
`FORCE ROW LEVEL SECURITY`, `nc3_app` reaches rows only through the
per-transaction context arms below, and `app_platform` only through its
per-duty allowlist policies. Neither role has `BYPASSRLS`; nothing does.

## The roles

| Role | Who connects as it | Privileges |
|---|---|---|
| owning role (`postgres` in dev) | Alembic (`make db-*`), operators | Superuser/owner: DDL, grants, everything. The dev superuser bypasses RLS outright; a non-superuser owner is subject to `FORCE` (see [database-migrations.md](database-migrations.md)). |
| `nc3_app` | API service, scan-queue workers (`APP_DATABASE_URL`) | `SELECT`/`INSERT`/`UPDATE`/`DELETE` on application tables — minus the append-only exceptions below — scoped per row by the `tenant_rows` policies. No DDL, no role management, no `alembic_version`. |
| `app_platform` | platform-queue worker and beat (`APP_DATABASE_URL`, overridden per service in compose) | Duty allowlist only: `SELECT`/`INSERT`/`UPDATE` on `scan_job` and `scan_task` (dispatch, reaper, heartbeat, seed tool), `INSERT` on `audit_event`. Nothing else — adding a platform duty means adding a grant + policy in a revision, never widening one. |
| `nc3_auth` | API service only (`AUTH_DATABASE_URL`) | Credential surface: `SELECT`/`INSERT`/`UPDATE` on `user_credential`, `user_session`, `user_mfa`, and `mfa_recovery_code` (no `DELETE` anywhere — revocation, MFA disable, and recovery-code burn are UPDATEs; hard deletion arrives with the erasure story), the registration transaction (`SELECT`/`INSERT` on `organization`, `app_user`, `key_envelope`, `statement_response`; `SELECT` on `statement`), and `EXECUTE` on the two auth lookups. Deliberately **not** granted to `nc3_app`: the scan workers hold that role and GUCs are app-asserted, so any `nc3_app` grant here would let a compromised worker forge a session row (US #79) or read TOTP-seed ciphertext (US #80). |
| `nc3_auth_definer` | nobody (NOLOGIN) | Owns `auth_login_lookup` and `auth_session_bootstrap`; its only privilege is an explicit `FOR SELECT USING (true)` policy + `SELECT` grant on `app_user`, `user_credential`, `user_session` — the reviewable "bypass" of IDR-012's session bootstrap, with no BYPASSRLS anywhere. Deliberately **no reach into the MFA tables** (US #80): MFA state is read in-policy after the user context opens, so the definer owner never touches seed ciphertext. |

> **Operator note — MFA reset (v4.0):** there is no self-service or API-driven MFA reset. A user who loses both the authenticator and the recovery codes goes through the out-of-band platform-operator procedure (identity verification, then an operator soft-revoke of the `user_mfa` row). `user_mfa` carries `FORCE ROW LEVEL SECURITY` with one policy scoped `TO nc3_auth`, so the owner connection matches no policy and the reset must go through the app role, not the raw owner connection: connect directly with the `nc3_auth` credential (`AUTH_DATABASE_URL`), or — from the owner connection — `SET ROLE nc3_auth` if that owner has been granted membership in `nc3_auth` (a Postgres superuser can always `SET ROLE`; a non-superuser owner needs an explicit `GRANT nc3_auth TO <owner-role>` first). Either way: `SET LOCAL app.current_user = '<user-id>'; UPDATE user_mfa SET totp_secret_ciphertext = NULL, confirmed_at = NULL WHERE user_id = '<user-id>'; RESET ROLE;` (the last step only if `SET ROLE` was used) inside one transaction. Check the row count before committing — a plain owner-connection `UPDATE` here silently affects zero rows and gives no error.

Exceptions to `nc3_app`'s blanket data grant, from the data model's
append-only rules (§5.2, §12.1): **no `UPDATE` or `DELETE` on
`statement_response` and `audit_event`**. A statement response is corrected by
a new statement version and a new response; an audit event is never touched.
`audit_event` additionally has no `SELECT` *policy* for either runtime role —
the v4.0 platform-admin audit read is an out-of-band operator procedure
(Non-functional → Roles). Because of that, audit inserts must not use
`RETURNING`: PostgreSQL applies SELECT policies to returned rows. And because
an audit row can never be corrected in-band, `nc3_app`'s INSERT arm binds
`organization_id` to the asserted org context (org-less rows — guest and
user-scoped events — pass); only `app_platform` appends unconstrained.

`alembic_version` is revoked entirely from both runtime roles: the runtime
has no business reading or writing migration state.

## The row classes and their context (IDR-012)

The `tenant_rows` policies read three transaction-local GUCs, set only by
`core/rls.py` (`set_org_context` / `set_user_context` /
`set_guest_job_context`) — always via `SET LOCAL` semantics
(`set_config(..., true)`), so a pooled connection cannot carry a context past
its transaction:

- **`app.current_org`** — org-shared rows: assets, verifications, schedules,
  reports, feeds, webhooks, invitations, statement responses, the org row
  itself, and org-owned scan rows.
- **`app.current_user`** — user-owned rows: `api_key` (carries
  `secret_hash` — private even inside the org) and `notification`;
  `app_user` rows are visible to their owner *and* to the same org (member
  management).
- **`app.current_job`** — the guest arm: an unclaimed guest scan job and its
  task/result/finding/file chain, reachable only with the validated job id.
  The claim transition happens *through* this arm (the arm keys on the
  immutable `scan_job.id`), so no NULL→org policy exists.

`key_envelope` follows its `scope` column across all three arms (IDR-017). A
missing or cleared GUC is NULL/'' and every predicate denies with an **empty
result, never an error**. New tables are deny-until-classified: the RLS
revision's closing gate fails the migration round trip on any application
table without `FORCE` and a policy.

**Workers revalidate by hint-then-verify** (`worker/tasks.py`): dispatch —
running as `app_platform` — threads the owning org/job id into each
`scan.run_module` payload; the scan worker opens the hinted arm and claims
the task row *under the policy*. A forged or missing hint loads zero rows and
the delivery drops without writing. That is what "RLS revalidated on Celery
result write" means mechanically.

## The SECURITY DEFINER auth lookups (IDR-012, B3)

Before identity is known no RLS arm can open, so exactly two pre-context
reads exist, as `SECURITY DEFINER` SQL functions: `auth_login_lookup(email)`
(login: email → credential row) and `auth_session_bootstrap(token_hash)`
(every authenticated request: cookie hash → session row). Hardening, all
asserted by `tests/test_auth_postgres.py`:

- owned by `nc3_auth_definer` (NOLOGIN, NOBYPASSRLS) — on a non-superuser
  owner `FORCE` binds function owners too, so the functions read through an
  explicit `definer_lookup` `FOR SELECT USING (true)` policy on exactly the
  three tables they join, in the same allowlist shape as `app_platform`'s
  duty policies;
- `SET search_path = ''` with schema-qualified references;
- `EXECUTE` revoked from `PUBLIC`, granted to `nc3_auth` alone — `nc3_app`
  and `app_platform` calling either is a permission error;
- read-only (`STABLE`): the lockout increment and the `last_seen_at` touch
  are ordinary in-policy writes under the user context, never definer writes.

## Where the roles come from

Both roles are created by hand-written Alembic revisions (`nc3_app role and
grants`, `RLS policies and app_platform role`). Roles are cluster-level, so
each revision creates idempotently — `CREATE ROLE` with the
`duplicate_object` error trapped — then re-asserts the role's attributes
(`NOBYPASSRLS` included), refuses to proceed while the role holds any role
membership, and finally validates the role's *effective* privileges
(`has_table_privilege`), catching out-of-band grants to `PUBLIC`.

**No password appears in any migration.** The revisions create the roles with
`LOGIN` but no credential; each environment sets its own:

- **Development**: `NC3_APP_DB_PASSWORD`, `NC3_PLATFORM_DB_PASSWORD`, and
  `NC3_AUTH_DB_PASSWORD` in `.env` (see `.env.example`), applied once per
  PostgreSQL cluster — the
  `ALTER ROLE` must set the same values the compose URLs interpolate:

  ```bash
  set -a; . ./.env; set +a
  docker compose exec postgres psql -U postgres -d nc3_testing_platform \
    -c "ALTER ROLE nc3_app PASSWORD '${NC3_APP_DB_PASSWORD}'" \
    -c "ALTER ROLE app_platform PASSWORD '${NC3_PLATFORM_DB_PASSWORD}'" \
    -c "ALTER ROLE nc3_auth PASSWORD '${NC3_AUTH_DB_PASSWORD}'"
  ```

  `nc3_auth_definer` is NOLOGIN and never gets a password.

- **Dokploy**: set all three variables in the application's environment tab
  and run the same `ALTER ROLE` against the deployment database.

The API service additionally carries `AUTH_DATABASE_URL` (`core/api_db.py`; settings field `auth_database_url`) for the `nc3_auth` engine — no worker service gets it, and the deployment master-key secret mounts into the api service only. The API and worker services carry `APP_DATABASE_URL`; `worker/db.py` reads it
(via `settings.app_database_url`). Which role the credential names is compose
topology: the api and scan-worker services get `nc3_app`, worker-platform and
beat get `app_platform`. `PLATFORM_DATABASE_URL` is a **Compose interpolation
variable only** — the platform services map it into their `APP_DATABASE_URL`;
`Settings` never reads it directly — set it when the platform password needs
percent-encoding. `DATABASE_URL` stays the owning role, for Alembic and
`make db-*` only — the application never connects with it.

## Rules for future revisions

- **Autogenerate never sees grants** (or roles, or RLS). Every revision that
  creates a table must `GRANT` on it by hand in the same revision — and
  `REVOKE UPDATE, DELETE` again if the new table is append-only — and give it
  `ENABLE` + `FORCE ROW LEVEL SECURITY` plus a classified policy. See
  [database-migrations.md](database-migrations.md).
- The blanket `GRANT ... ON ALL TABLES IN SCHEMA public` in the `nc3_app`
  revision covers only tables existing when it ran; it is not a default
  privilege and does not extend to future tables. That is deliberate — an
  explicit grant per table keeps the privilege surface reviewable in the diff.
- `app_platform` gets **no** blanket grant, ever. A new platform duty is a
  new grant + policy pair named after the duty.
- **The isolation suites (`tests/test_org_isolation.py` and
  `tests/test_auth_postgres.py`, `pytest -m postgres`) are the standing
  regression gate for any change to roles, grants, or policies.** It connects as the runtime roles and asserts the cross-org,
  cross-user, and guest boundaries, the worker hint-then-verify path, the
  pool-leak guard, the append-only refusals, and the duty allowlist. CI runs
  it inside the Migration round trip job.
