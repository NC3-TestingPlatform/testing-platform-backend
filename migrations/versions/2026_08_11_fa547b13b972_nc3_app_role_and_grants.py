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
    # the B5 policies will rely on.
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nc3_app') THEN
                CREATE ROLE nc3_app LOGIN
                    NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOBYPASSRLS NOREPLICATION;
            END IF;
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
