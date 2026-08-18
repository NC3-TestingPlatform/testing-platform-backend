"""RLS policies and app_platform role.

Revision: 0d5679b5500d
Revises: fa547b13b972

Hand-written: autogenerate never sees roles, grants, or policies
(docs/database-roles.md). Implements IDR-012: ENABLE + FORCE row-level
security on every application table, tenant policies for ``nc3_app`` over
three row classes, and the ``app_platform`` maintenance role whose per-duty
allowlist policies replace any GUC-based admin arm. No BYPASSRLS anywhere.

Row-class matrix (data-model v4.0.2 §3-§14; IDR-017 for key_envelope). The
GUCs are set per transaction by ``core/rls.py``; a missing or cleared GUC is
NULL/'' and every predicate below then denies with an empty result:

  organization                    org arm on its own id
  app_user                        user arm on id, OR same-org arm (member
                                  visibility; credential material is B3's and
                                  lands in user-private tables)
  asset, domain_verification,     org arm on organization_id
  domain_verification_challenge,
  schedule, report, asset_feed,
  organization_webhook,
  organization_invitation,
  statement_response
  api_key                         user arm on owner_user_id only — carries
                                  secret_hash, private even inside the org
                                  (IDR-012)
  notification                    user arm on user_id
  key_envelope                    arm per key_scope column: organization_id /
                                  user_id / scan_job_id (IDR-017)
  scan_job                        org arm OR guest arm on id
  scan_task                       org arm OR guest arm on scan_job_id
  scan_result, finding,           org arm OR guest arm through EXISTS up to
  file_upload                     the owning scan_job (no direct job column)
  statement                       reference data (versioned legal text): read
                                  for nc3_app, writes stay with the owner
  audit_event                     INSERT-only for both roles, rows carrying
                                  org, user, or neither; no SELECT policy —
                                  the platform-admin read is out-of-band in
                                  v4.0 (Non-functional → Roles)

The EXISTS arms nest acyclically (finding → scan_result → scan_task; the
referenced tables' own policies apply inside the subquery and agree under the
same GUCs), so PostgreSQL's policy-recursion guard is never tripped.

FORCE means the *owning* role is subject to the policies too on any
non-superuser deployment: a future data/seed migration touching tenant rows
must account for it (docs/database-migrations.md). The dev/CI owner is the
``postgres`` superuser, which bypasses RLS unconditionally — which is also
why the isolation suite connects as the runtime roles, never the owner.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0d5679b5500d"
down_revision: str | None = "fa547b13b972"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ORG = "NULLIF(current_setting('app.current_org', true), '')::uuid"
_USER = "NULLIF(current_setting('app.current_user', true), '')::uuid"
_JOB = "NULLIF(current_setting('app.current_job', true), '')::uuid"

# Every application table (the 21 of the v4.0.2 schema). alembic_version is
# owner-only state and stays outside RLS; nc3_app/app_platform hold no grant
# on it (fa547b13b972).
_ALL_TABLES = (
    "organization",
    "statement",
    "app_user",
    "audit_event",
    "statement_response",
    "api_key",
    "asset",
    "file_upload",
    "notification",
    "organization_invitation",
    "organization_webhook",
    "report",
    "asset_feed",
    "domain_verification",
    "domain_verification_challenge",
    "schedule",
    "scan_job",
    "key_envelope",
    "scan_task",
    "scan_result",
    "finding",
)

# The FOR ALL tenant predicate per table (USING and WITH CHECK are the same
# expression: what a context cannot see, it cannot create either — the claim
# transition works through the guest arm because scan_job.id never changes).
_TENANT_PREDICATES: dict[str, str] = {
    "organization": f"id = {_ORG}",
    "app_user": f"id = {_USER} OR organization_id = {_ORG}",
    "asset": f"organization_id = {_ORG}",
    "domain_verification": f"organization_id = {_ORG}",
    "domain_verification_challenge": f"organization_id = {_ORG}",
    "schedule": f"organization_id = {_ORG}",
    "report": f"organization_id = {_ORG}",
    "asset_feed": f"organization_id = {_ORG}",
    "organization_webhook": f"organization_id = {_ORG}",
    "organization_invitation": f"organization_id = {_ORG}",
    "statement_response": f"organization_id = {_ORG}",
    "api_key": f"owner_user_id = {_USER}",
    "notification": f"user_id = {_USER}",
    "key_envelope": (
        f"organization_id = {_ORG} OR user_id = {_USER} OR scan_job_id = {_JOB}"
    ),
    "scan_job": f"organization_id = {_ORG} OR id = {_JOB}",
    "scan_task": f"organization_id = {_ORG} OR scan_job_id = {_JOB}",
    "scan_result": (
        f"organization_id = {_ORG} OR EXISTS ("
        "SELECT 1 FROM scan_task t "
        "WHERE t.id = scan_result.scan_task_id "
        f"AND t.scan_job_id = {_JOB})"
    ),
    "finding": (
        f"organization_id = {_ORG} OR EXISTS ("
        "SELECT 1 FROM scan_result r "
        "JOIN scan_task t ON t.id = r.scan_task_id "
        "WHERE r.id = finding.scan_result_id "
        f"AND t.scan_job_id = {_JOB})"
    ),
    "file_upload": (
        f"organization_id = {_ORG} OR EXISTS ("
        "SELECT 1 FROM scan_job j "
        "WHERE j.file_upload_id = file_upload.id "
        f"AND j.id = {_JOB})"
    ),
}

# app_platform's duty allowlist — exactly the delivered platform-queue work:
# scan.dispatch / scan.reap / scan.heartbeat and the seed tool (worker/tasks.py,
# tools/seed_scan.py) read, update, and create scan_job/scan_task rows across
# organizations; audit appends are duty-shaped from day one. Adding a platform
# duty means adding a policy here — never widening an existing one (IDR-012).
_PLATFORM_DUTY_TABLES = ("scan_job", "scan_task")


def upgrade() -> None:
    """Apply this revision."""
    # --- app_platform role, with the same defensive shape as nc3_app
    # (fa547b13b972): duplicate_object-trapped creation, attribute
    # re-assertion, and a loud refusal on inherited memberships.
    op.execute(
        """
        DO $$
        BEGIN
            CREATE ROLE app_platform LOGIN
                NOSUPERUSER NOCREATEDB NOCREATEROLE
                NOBYPASSRLS NOREPLICATION;
        EXCEPTION WHEN duplicate_object THEN
            NULL;  -- created by another database's upgrade or a prior run
        END
        $$;
        """
    )
    op.execute(
        "ALTER ROLE app_platform LOGIN "
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION"
    )
    op.execute(
        """
        DO $$
        DECLARE
            memberships text;
        BEGIN
            SELECT string_agg(r.rolname, ', ')
            INTO memberships
            FROM pg_auth_members m
            JOIN pg_roles r ON r.oid = m.roleid
            WHERE m.member = 'app_platform'::regrole;
            IF memberships IS NOT NULL THEN
                RAISE EXCEPTION 'app_platform is a member of: % — inherited '
                    'privileges would bypass this revision''s duty allowlist; '
                    'revoke those memberships first (docs/database-roles.md)',
                    memberships;
            END IF;
        END
        $$;
        """
    )
    # Duty grants only — no blanket grant like nc3_app's: the allowlist is the
    # point. The grants say which verbs exist at all; the policies below say
    # which rows they reach.
    op.execute("GRANT USAGE ON SCHEMA public TO app_platform")
    for table in _PLATFORM_DUTY_TABLES:
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON TABLE {table} TO app_platform")
    op.execute("GRANT INSERT ON TABLE audit_event TO app_platform")

    # --- ENABLE + FORCE on every application table. FORCE subjects even the
    # table owner to the policies (IDR-012 closes the classic silent no-op).
    for table in _ALL_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    # --- Tenant policies for nc3_app: one FOR ALL policy per classified
    # table, WITH CHECK mirroring USING.
    for table, predicate in _TENANT_PREDICATES.items():
        op.execute(
            f"CREATE POLICY tenant_rows ON {table} FOR ALL TO nc3_app "
            f"USING ({predicate}) WITH CHECK ({predicate})"
        )
    # statement is versioned legal reference text: readable in any
    # authenticated context, writable by nobody but the owner (operational
    # seeding). No INSERT/UPDATE/DELETE policy exists, so those verbs deny
    # for nc3_app despite the blanket grant.
    op.execute(
        "CREATE POLICY reference_read ON statement FOR SELECT TO nc3_app USING (true)"
    )
    # audit_event accepts appends carrying org, user, or neither (guest and
    # platform events) from both runtime roles; reads have no policy — the
    # v4.0 platform-admin read is an out-of-band operator procedure, and
    # UPDATE/DELETE are already revoked at the grant layer (fa547b13b972).
    op.execute(
        "CREATE POLICY audit_append ON audit_event FOR INSERT "
        "TO nc3_app, app_platform WITH CHECK (true)"
    )

    # --- app_platform duty policies (row scope for the duty grants above).
    for table in _PLATFORM_DUTY_TABLES:
        op.execute(
            f"CREATE POLICY platform_duty_select ON {table} "
            "FOR SELECT TO app_platform USING (true)"
        )
        op.execute(
            f"CREATE POLICY platform_duty_update ON {table} "
            "FOR UPDATE TO app_platform USING (true) WITH CHECK (true)"
        )
        op.execute(
            f"CREATE POLICY platform_duty_insert ON {table} "
            "FOR INSERT TO app_platform WITH CHECK (true)"
        )

    # --- The silent-hole gate: refuse to complete while any application
    # table is missing ENABLE, FORCE, or a policy. Generic over the schema on
    # purpose — a table someone adds without classifying it fails the next
    # round trip instead of shipping unprotected (deny-until-classified).
    op.execute(
        """
        DO $$
        DECLARE
            offending text;
        BEGIN
            SELECT string_agg(c.relname, ', ' ORDER BY c.relname)
            INTO offending
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relkind = 'r'
              AND c.relname <> 'alembic_version'
              AND (NOT c.relrowsecurity
                   OR NOT c.relforcerowsecurity
                   OR NOT EXISTS (
                       SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid));
            IF offending IS NOT NULL THEN
                RAISE EXCEPTION 'tables without forced RLS and a policy: % — '
                    'classify them in a revision before shipping '
                    '(docs/database-roles.md)', offending;
            END IF;
        END
        $$;
        """
    )
    # And the mirror-image gate for the duty allowlist: app_platform must not
    # have gained effective privileges beyond its enumerated duties — a PUBLIC
    # grant would reach it silently (same stance as fa547b13b972).
    op.execute(
        """
        DO $$
        DECLARE
            offending text;
        BEGIN
            SELECT string_agg(check_name, ', ')
            INTO offending
            FROM (VALUES
                ('organization (any write)',
                 has_table_privilege('app_platform', 'organization',
                     'INSERT, UPDATE, DELETE')),
                ('api_key (any)',
                 has_table_privilege('app_platform', 'api_key',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('key_envelope (any write)',
                 has_table_privilege('app_platform', 'key_envelope',
                     'INSERT, UPDATE, DELETE')),
                ('scan_job DELETE',
                 has_table_privilege('app_platform', 'scan_job', 'DELETE')),
                ('scan_task DELETE',
                 has_table_privilege('app_platform', 'scan_task', 'DELETE')),
                ('audit_event UPDATE',
                 has_table_privilege('app_platform', 'audit_event', 'UPDATE')),
                ('audit_event DELETE',
                 has_table_privilege('app_platform', 'audit_event', 'DELETE')),
                ('alembic_version (any)',
                 has_table_privilege('app_platform', 'alembic_version',
                     'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')),
                ('schema public CREATE',
                 has_schema_privilege('app_platform', 'public', 'CREATE'))
            ) AS t(check_name, held)
            WHERE held;
            IF offending IS NOT NULL THEN
                RAISE EXCEPTION 'app_platform holds privileges beyond its '
                    'duty allowlist (%) — likely granted to PUBLIC out of '
                    'band; revoke them first (docs/database-roles.md)',
                    offending;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Revert this revision."""
    for table in _PLATFORM_DUTY_TABLES:
        op.execute(f"DROP POLICY IF EXISTS platform_duty_select ON {table}")
        op.execute(f"DROP POLICY IF EXISTS platform_duty_update ON {table}")
        op.execute(f"DROP POLICY IF EXISTS platform_duty_insert ON {table}")
    op.execute("DROP POLICY IF EXISTS audit_append ON audit_event")
    op.execute("DROP POLICY IF EXISTS reference_read ON statement")
    for table in _TENANT_PREDICATES:
        op.execute(f"DROP POLICY IF EXISTS tenant_rows ON {table}")
    for table in _ALL_TABLES:
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM app_platform")
    op.execute("REVOKE USAGE ON SCHEMA public FROM app_platform")
    # Cluster-level role: dropping fails while another database still holds
    # grants to it — surface that actionably (same shape as fa547b13b972).
    op.execute(
        """
        DO $$
        BEGIN
            DROP ROLE IF EXISTS app_platform;
        EXCEPTION WHEN dependent_objects_still_exist THEN
            RAISE EXCEPTION 'app_platform still holds grants in another '
                'database of this cluster; downgrade that database first '
                '(docs/database-roles.md)';
        END
        $$;
        """
    )
