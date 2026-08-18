"""Auth tables, nc3_auth role, and the session-bootstrap lookups.

Revision: b3c7a9e2f4d1
Revises: 0d5679b5500d

Hand-written past the two table creations: autogenerate never sees roles,
grants, policies, or functions (docs/database-roles.md). Implements the B3
slice of IDR-012:

* `user_credential` and `user_session` — user-owned RLS rows, granted to a
  new **`nc3_auth`** connection role that only the API service holds. The
  scan workers share `nc3_app`, and RLS GUCs are application-asserted, so
  any `nc3_app` grant here would let a compromised worker forge a session
  row or exfiltrate credential ciphertext (US #79 review).
* Two SECURITY DEFINER lookups — `auth_login_lookup` (email → credential)
  and `auth_session_bootstrap` (token hash → session) — the only reads that
  can happen before an RLS context exists, because identity is what they
  resolve. They are owned by **`nc3_auth_definer`**, a NOLOGIN role whose
  only privilege is an explicit `FOR SELECT USING (true)` policy on exactly
  the three tables the lookups join. No BYPASSRLS anywhere: on a
  non-superuser owner FORCE RLS binds even function owners, so the "bypass"
  is a reviewable allowlist policy, in the same shape as `app_platform`'s
  duty policies.
* The org-arm policies of the registration transaction (organization,
  app_user, key_envelope, statement_response; the statement read) are
  extended to `nc3_auth` — registration provisions the workspace org
  (IDR-016) inside one `nc3_auth` transaction.
* `app_user` gains the case-insensitive unique email index the login
  lookup relies on.

Closing gates re-run the deny-until-classified check (this revision creates
tables after 0d5679b5500d's gate ran) and pin both new roles to their
enumerated privileges.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "b3c7a9e2f4d1"
down_revision: str | None = "0d5679b5500d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_USER = "NULLIF(current_setting('app.current_user', true), '')::uuid"

# The tables of the registration transaction whose existing nc3_app policies
# gain the nc3_auth arm (ALTER POLICY replaces the role list).
_REGISTRATION_TENANT_TABLES = (
    "organization",
    "app_user",
    "key_envelope",
    "statement_response",
)

# The tables the two SECURITY DEFINER lookups join.
_DEFINER_LOOKUP_TABLES = ("app_user", "user_credential", "user_session")


def _create_role_defensively(role: str, *, login: bool) -> None:
    """CREATE ROLE with the fa547b13b972 defensive shape.

    Idempotent creation (roles are cluster-level), attribute re-assertion
    (NOBYPASSRLS included), and a loud refusal while the role inherits
    anything through a membership.
    """
    login_sql = "LOGIN" if login else "NOLOGIN"
    op.execute(
        f"""
        DO $$
        BEGIN
            CREATE ROLE {role} {login_sql}
                NOSUPERUSER NOCREATEDB NOCREATEROLE
                NOBYPASSRLS NOREPLICATION;
        EXCEPTION WHEN duplicate_object THEN
            NULL;  -- created by another database's upgrade or a prior run
        END
        $$;
        """
    )
    op.execute(
        f"ALTER ROLE {role} {login_sql} "
        "NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION"
    )
    op.execute(
        f"""
        DO $$
        DECLARE
            memberships text;
        BEGIN
            SELECT string_agg(r.rolname, ', ')
            INTO memberships
            FROM pg_auth_members m
            JOIN pg_roles r ON r.oid = m.roleid
            WHERE m.member = '{role}'::regrole;
            IF memberships IS NOT NULL THEN
                RAISE EXCEPTION '{role} is a member of: % — inherited '
                    'privileges would bypass this revision''s allowlist; '
                    'revoke those memberships first (docs/database-roles.md)',
                    memberships;
            END IF;
        END
        $$;
        """
    )


def upgrade() -> None:
    """Apply this revision."""
    # --- The two user-owned tables (models: domains/auth/models.py).
    op.create_table(
        "user_credential",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("password_ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column(
            "failed_login_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "password_updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name=op.f("fk_user_credential_user_id_app_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_credential")),
        sa.UniqueConstraint("user_id", name=op.f("uq_user_credential_user_id")),
    )
    op.create_table(
        "user_session",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name=op.f("fk_user_session_user_id_app_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_session")),
        sa.UniqueConstraint("token_hash", name=op.f("uq_user_session_token_hash")),
    )
    op.create_index(
        op.f("ix_user_session_user_id"), "user_session", ["user_id"], unique=False
    )
    # One account per email, case-insensitive; also what auth_login_lookup
    # scans. The application lowercases at the boundary.
    op.create_index(
        "uq_app_user_email_lower",
        "app_user",
        [sa.text("lower(email)")],
        unique=True,
    )

    # --- The two roles.
    _create_role_defensively("nc3_auth", login=True)
    _create_role_defensively("nc3_auth_definer", login=False)

    # --- Grants: duty-minimal, spelled per table (docs/database-roles.md).
    op.execute("GRANT USAGE ON SCHEMA public TO nc3_auth")
    op.execute("GRANT USAGE ON SCHEMA public TO nc3_auth_definer")
    # The credential surface belongs to nc3_auth alone — deliberately NOT
    # granted to nc3_app (US #79). No DELETE: logout and rotation revoke,
    # hard deletion arrives with the erasure story on its own grant.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON TABLE user_credential, user_session "
        "TO nc3_auth"
    )
    # The registration transaction (IDR-016): INSERT the workspace org, the
    # admin user, both envelopes, and the consent receipts; SELECT is needed
    # by the ORM's INSERT..RETURNING of server defaults.
    op.execute(
        "GRANT SELECT, INSERT ON TABLE organization, app_user, key_envelope, "
        "statement_response TO nc3_auth"
    )
    op.execute("GRANT SELECT ON TABLE statement TO nc3_auth")
    # The definer owner reads exactly what its two functions join.
    op.execute(
        "GRANT SELECT ON TABLE app_user, user_credential, user_session "
        "TO nc3_auth_definer"
    )

    # --- RLS on the new tables: deny-until-classified means classify now.
    for table in ("user_credential", "user_session"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_rows ON {table} FOR ALL TO nc3_auth "
            f"USING (user_id = {_USER}) WITH CHECK (user_id = {_USER})"
        )
    # The definer arm: an explicit, reviewable USING (true) SELECT policy on
    # a NOLOGIN role — the IDR-012 "sole bypass", without BYPASSRLS. On a
    # non-superuser owner FORCE RLS binds function owners too, so without
    # these the lookups would return nothing exactly where it matters.
    for table in _DEFINER_LOOKUP_TABLES:
        op.execute(
            f"CREATE POLICY definer_lookup ON {table} "
            "FOR SELECT TO nc3_auth_definer USING (true)"
        )
    # Registration runs as nc3_auth: extend the existing arms. ALTER POLICY
    # replaces the role list, so both roles are named.
    for table in _REGISTRATION_TENANT_TABLES:
        op.execute(f"ALTER POLICY tenant_rows ON {table} TO nc3_app, nc3_auth")
    op.execute("ALTER POLICY reference_read ON statement TO nc3_app, nc3_auth")

    # --- The SECURITY DEFINER lookups (IDR-012). Hardened: pinned empty
    # search_path, schema-qualified references, at most one row out, EXECUTE
    # revoked from PUBLIC and granted to nc3_auth alone.
    op.execute(
        """
        CREATE FUNCTION public.auth_login_lookup(p_email text)
        RETURNS TABLE (
            user_id uuid,
            organization_id uuid,
            disabled_at timestamptz,
            password_ciphertext bytea,
            failed_login_count integer,
            locked_until timestamptz,
            observed_at timestamptz
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = ''
        AS $$
            SELECT u.id, u.organization_id, u.disabled_at,
                   c.password_ciphertext, c.failed_login_count, c.locked_until,
                   now()
            FROM public.app_user u
            JOIN public.user_credential c ON c.user_id = u.id
            WHERE lower(u.email) = lower(p_email)
        $$;
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.auth_session_bootstrap(p_token_hash bytea)
        RETURNS TABLE (
            session_id uuid,
            user_id uuid,
            organization_id uuid,
            session_created_at timestamptz,
            last_seen_at timestamptz,
            revoked_at timestamptz,
            user_disabled_at timestamptz,
            observed_at timestamptz
        )
        LANGUAGE sql
        STABLE
        SECURITY DEFINER
        SET search_path = ''
        AS $$
            SELECT s.id, s.user_id, u.organization_id, s.created_at,
                   s.last_seen_at, s.revoked_at, u.disabled_at, now()
            FROM public.user_session s
            JOIN public.app_user u ON u.id = s.user_id
            WHERE s.token_hash = p_token_hash
        $$;
        """
    )
    # Ownership transfer needs momentary membership on a non-superuser owner
    # (a no-op privilege-wise for the dev superuser); revoked right after.
    op.execute("GRANT nc3_auth_definer TO CURRENT_USER")
    op.execute(
        "ALTER FUNCTION public.auth_login_lookup(text) OWNER TO nc3_auth_definer"
    )
    op.execute(
        "ALTER FUNCTION public.auth_session_bootstrap(bytea) "
        "OWNER TO nc3_auth_definer"
    )
    op.execute("REVOKE nc3_auth_definer FROM CURRENT_USER")
    for signature in (
        "public.auth_login_lookup(text)",
        "public.auth_session_bootstrap(bytea)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {signature} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {signature} TO nc3_auth")

    # --- Gate 1: deny-until-classified, re-run because this revision created
    # tables after 0d5679b5500d's gate ran (same SQL; docs/database-roles.md).
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
    # --- Gate 2: nc3_auth must hold nothing beyond its enumerated duties —
    # in particular nothing on the scan chain or the audit log (audit writes
    # are B7's), and no DELETE anywhere.
    op.execute(
        """
        DO $$
        DECLARE
            offending text;
        BEGIN
            SELECT string_agg(check_name, ', ')
            INTO offending
            FROM (VALUES
                ('scan_job (any)',
                 has_table_privilege('nc3_auth', 'scan_job',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('asset (any)',
                 has_table_privilege('nc3_auth', 'asset',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('api_key (any)',
                 has_table_privilege('nc3_auth', 'api_key',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('audit_event (any)',
                 has_table_privilege('nc3_auth', 'audit_event',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('user_credential DELETE',
                 has_table_privilege('nc3_auth', 'user_credential', 'DELETE')),
                ('user_session DELETE',
                 has_table_privilege('nc3_auth', 'user_session', 'DELETE')),
                ('organization UPDATE/DELETE',
                 has_table_privilege('nc3_auth', 'organization',
                     'UPDATE, DELETE')),
                ('app_user UPDATE/DELETE',
                 has_table_privilege('nc3_auth', 'app_user', 'UPDATE, DELETE')),
                ('statement (any write)',
                 has_table_privilege('nc3_auth', 'statement',
                     'INSERT, UPDATE, DELETE')),
                ('alembic_version (any)',
                 has_table_privilege('nc3_auth', 'alembic_version',
                     'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')),
                ('schema public CREATE',
                 has_schema_privilege('nc3_auth', 'public', 'CREATE'))
            ) AS t(check_name, held)
            WHERE held;
            IF offending IS NOT NULL THEN
                RAISE EXCEPTION 'nc3_auth holds privileges beyond its duty '
                    'allowlist (%) — likely granted to PUBLIC out of band; '
                    'revoke them first (docs/database-roles.md)', offending;
            END IF;
        END
        $$;
        """
    )
    # --- Gate 3: the definer owner reads its three tables and does nothing
    # else, anywhere, ever.
    op.execute(
        """
        DO $$
        DECLARE
            offending text;
        BEGIN
            SELECT string_agg(check_name, ', ')
            INTO offending
            FROM (VALUES
                ('user_credential (any write)',
                 has_table_privilege('nc3_auth_definer', 'user_credential',
                     'INSERT, UPDATE, DELETE')),
                ('user_session (any write)',
                 has_table_privilege('nc3_auth_definer', 'user_session',
                     'INSERT, UPDATE, DELETE')),
                ('app_user (any write)',
                 has_table_privilege('nc3_auth_definer', 'app_user',
                     'INSERT, UPDATE, DELETE')),
                ('key_envelope (any)',
                 has_table_privilege('nc3_auth_definer', 'key_envelope',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('alembic_version (any)',
                 has_table_privilege('nc3_auth_definer', 'alembic_version',
                     'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')),
                ('schema public CREATE',
                 has_schema_privilege('nc3_auth_definer', 'public', 'CREATE'))
            ) AS t(check_name, held)
            WHERE held;
            IF offending IS NOT NULL THEN
                RAISE EXCEPTION 'nc3_auth_definer holds privileges beyond its '
                    'lookup allowlist (%) — revoke them first '
                    '(docs/database-roles.md)', offending;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Revert this revision."""
    op.execute("DROP FUNCTION IF EXISTS public.auth_login_lookup(text)")
    op.execute("DROP FUNCTION IF EXISTS public.auth_session_bootstrap(bytea)")
    op.execute("DROP POLICY IF EXISTS definer_lookup ON app_user")
    for table in _REGISTRATION_TENANT_TABLES:
        op.execute(f"ALTER POLICY tenant_rows ON {table} TO nc3_app")
    op.execute("ALTER POLICY reference_read ON statement TO nc3_app")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nc3_auth")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM nc3_auth_definer")
    op.execute("REVOKE USAGE ON SCHEMA public FROM nc3_auth")
    op.execute("REVOKE USAGE ON SCHEMA public FROM nc3_auth_definer")
    # Table drops take their policies, FORCE flags, and remaining grants along.
    op.drop_index(op.f("ix_user_session_user_id"), table_name="user_session")
    op.drop_table("user_session")
    op.drop_table("user_credential")
    op.drop_index("uq_app_user_email_lower", table_name="app_user")
    # Cluster-level roles: dropping fails while another database still holds
    # grants to them — surface that actionably (same shape as fa547b13b972).
    for role in ("nc3_auth", "nc3_auth_definer"):
        op.execute(
            f"""
            DO $$
            BEGIN
                DROP ROLE IF EXISTS {role};
            EXCEPTION WHEN dependent_objects_still_exist THEN
                RAISE EXCEPTION '{role} still holds privileges in another '
                    'database of this cluster; revoke them there, then rerun '
                    'the downgrade (docs/database-roles.md)';
            END
            $$;
            """
        )
