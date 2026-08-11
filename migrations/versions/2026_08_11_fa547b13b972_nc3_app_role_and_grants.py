"""nc3_app role and grants.

Revision: fa547b13b972
Revises: eb34e144eb97

Hand-written: autogenerate never sees roles or grants (docs/database-roles.md).
The role is cluster-level, so creation is idempotent — a second database
migrated in the same cluster reuses it. No password here; each environment
sets its own with ALTER ROLE (docs/database-roles.md).

The blanket grant covers the tables existing at this revision. It is not a
default privilege: every later revision that creates a table grants on it by
hand, and revokes UPDATE/DELETE again if the table is append-only.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "fa547b13b972"
down_revision: str | None = "eb34e144eb97"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Apply this revision."""
    # The attributes are PostgreSQL's defaults, spelled out so the privilege
    # boundary is verifiable in this diff — NOBYPASSRLS in particular is what
    # the B5 policies will rely on. Trapping duplicate_object (rather than
    # checking pg_roles first) closes the check-then-create race when two
    # databases of one cluster upgrade concurrently.
    op.execute(
        """
        DO $$
        BEGIN
            CREATE ROLE nc3_app LOGIN
                NOSUPERUSER NOCREATEDB NOCREATEROLE
                NOBYPASSRLS NOREPLICATION;
        EXCEPTION WHEN duplicate_object THEN
            NULL;  -- created by another database's upgrade or a prior run
        END
        $$;
        """
    )
    # CREATE ROLE never touches an existing role, and the role is
    # cluster-level: a second database migrated in the same cluster reuses
    # whatever nc3_app already is. Re-assert the attributes so a pre-existing
    # role cannot carry BYPASSRLS (or any other privilege) past this revision.
    # The migration runs as the owning role — a superuser, which may change
    # BYPASSRLS; CREATEROLE alone could not.
    op.execute(
        "ALTER ROLE nc3_app LOGIN "
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION"
    )
    # Attributes are not the whole story: a membership would hand nc3_app the
    # granting role's privileges (inherited, or one SET ROLE away), bypassing
    # the grant matrix below. Refuse loudly rather than revoke silently — the
    # membership is cluster-level state some other database may rely on, and
    # deciding for the operator is not this revision's call. With zero
    # memberships, the direct grants below fully determine what nc3_app can do.
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
            WHERE m.member = 'nc3_app'::regrole;
            IF memberships IS NOT NULL THEN
                RAISE EXCEPTION 'nc3_app is a member of: % — inherited '
                    'privileges would bypass this revision''s grant matrix; '
                    'revoke those memberships first (docs/database-roles.md)',
                    memberships;
            END IF;
        END
        $$;
        """
    )
    # PUBLIC already has USAGE on the public schema (PostgreSQL default, kept
    # in PG 15+); granted explicitly so hardening PUBLIC away later cannot
    # silently cut the application off.
    op.execute("GRANT USAGE ON SCHEMA public TO nc3_app")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        "TO nc3_app"
    )
    # §5.2 / §12.1 append-only rules: corrections are new rows, never edits.
    op.execute(
        "REVOKE UPDATE, DELETE ON TABLE statement_response, audit_event "
        "FROM nc3_app"
    )
    # The runtime has no business reading or writing migration state.
    op.execute("REVOKE ALL ON TABLE alembic_version FROM nc3_app")
    # Direct grants and memberships are still not the whole story: a privilege
    # granted to PUBLIC reaches every role, including nc3_app, and no REVOKE
    # ... FROM nc3_app overrides it. Validate what nc3_app can *effectively*
    # do and refuse if the matrix does not hold — same stance as the
    # membership check: name the problem, leave cluster policy to the
    # operator. PUBLIC grants none of these by default on PostgreSQL 15+
    # (the stacks pin 18), so this only trips on out-of-band grants.
    op.execute(
        """
        DO $$
        DECLARE
            offending text;
        BEGIN
            SELECT string_agg(check_name, ', ')
            INTO offending
            FROM (VALUES
                ('statement_response UPDATE',
                 has_table_privilege('nc3_app', 'statement_response', 'UPDATE')),
                ('statement_response DELETE',
                 has_table_privilege('nc3_app', 'statement_response', 'DELETE')),
                ('audit_event UPDATE',
                 has_table_privilege('nc3_app', 'audit_event', 'UPDATE')),
                ('audit_event DELETE',
                 has_table_privilege('nc3_app', 'audit_event', 'DELETE')),
                ('alembic_version (any)',
                 has_table_privilege('nc3_app', 'alembic_version',
                     'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')),
                ('schema public CREATE',
                 has_schema_privilege('nc3_app', 'public', 'CREATE'))
            ) AS t(check_name, held)
            WHERE held;
            IF offending IS NOT NULL THEN
                RAISE EXCEPTION 'nc3_app still holds prohibited effective '
                    'privileges (%) — likely granted to PUBLIC out of band; '
                    'revoke them first (docs/database-roles.md)', offending;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Revert this revision."""
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nc3_app")
    op.execute("REVOKE USAGE ON SCHEMA public FROM nc3_app")
    # The role is cluster-level: dropping it fails while another database in
    # the cluster still holds grants to it. Surface that as an actionable
    # message instead of a bare dependency error. Single-database dev/CI is
    # unaffected.
    op.execute(
        """
        DO $$
        BEGIN
            DROP ROLE IF EXISTS nc3_app;
        EXCEPTION WHEN dependent_objects_still_exist THEN
            RAISE EXCEPTION 'nc3_app still holds grants in another database '
                'of this cluster; downgrade that database first '
                '(docs/database-roles.md)';
        END
        $$;
        """
    )
