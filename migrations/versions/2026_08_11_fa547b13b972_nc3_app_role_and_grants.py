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
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nc3_app') THEN
                CREATE ROLE nc3_app LOGIN;
            END IF;
        END
        $$;
        """
    )
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
    # Fails if another database in the cluster still holds grants to the role;
    # that database must downgrade first. Single-database dev/CI is unaffected.
    op.execute("DROP ROLE IF EXISTS nc3_app")
