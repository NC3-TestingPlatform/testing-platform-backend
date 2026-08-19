"""MFA tables and the session assurance stamp.

Revision: e5a1c3d7f9b2
Revises: d7e3f1a2b4c6

Hand-written past the table creations: autogenerate never sees grants,
policies, or gates (docs/database-roles.md). Implements the B4 slice of
IDR-010/IDR-012 (US #80):

* `user_mfa` and `mfa_recovery_code` — user-owned RLS rows, granted to
  `nc3_auth` alone, exactly like `user_credential`/`user_session` (B3): the
  scan workers share `nc3_app` with app-asserted GUCs, so any `nc3_app`
  grant here would let a compromised worker read seed ciphertext or burn
  recovery codes. **No DELETE**: disable and regeneration are soft-revokes
  (`totp_secret_ciphertext`/`confirmed_at` nulled, codes superseded); hard
  deletion arrives with the erasure story on its own grant, same as B3
  decided for the credential tables.
* `user_session.mfa_verified_at` — current MFA assurance lives on the
  session, never as a User boolean (data-model §13.6). It is read
  **in-policy** after the RLS user context opens (`core/security.py`), so
  the `auth_session_bootstrap` SECURITY DEFINER function is deliberately
  untouched and `nc3_auth_definer` gains no reach into the seed table.

Closing gates re-run the deny-until-classified check (this revision creates
tables after the earlier gates ran) and pin the two new tables to the
enumerated privileges: `nc3_auth` read/write without DELETE, everyone else
nothing.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "e5a1c3d7f9b2"
down_revision: str | None = "d7e3f1a2b4c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_USER = "NULLIF(current_setting('app.current_user', true), '')::uuid"

_MFA_TABLES = ("user_mfa", "mfa_recovery_code")


def upgrade() -> None:
    """Apply this revision."""
    # --- The two user-owned tables (models: domains/auth/models.py).
    op.create_table(
        "user_mfa",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        # Nullable by design: disable is a soft-revoke that nulls the seed
        # and confirmed_at, never a row deletion (no DELETE grant below).
        sa.Column("totp_secret_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_step", sa.BigInteger(), nullable=True),
        sa.Column(
            "failed_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "lockout_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
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
            name=op.f("fk_user_mfa_user_id_app_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_mfa")),
        sa.UniqueConstraint("user_id", name=op.f("uq_user_mfa_user_id")),
    )
    op.create_table(
        "mfa_recovery_code",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("code_hash", sa.LargeBinary(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["app_user.id"],
            name=op.f("fk_mfa_recovery_code_user_id_app_user"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_mfa_recovery_code")),
        # Unique per user, not globally: a global index would refuse one
        # user's INSERT against another tenant's row — a cross-tenant
        # existence oracle under FORCE RLS.
        sa.UniqueConstraint(
            "user_id",
            "code_hash",
            name=op.f("uq_mfa_recovery_code_user_id_code_hash"),
        ),
    )
    op.create_index(
        op.f("ix_mfa_recovery_code_user_id"),
        "mfa_recovery_code",
        ["user_id"],
        unique=False,
    )
    # Current MFA assurance lives on the session (data-model §13.6); read
    # in-policy, so the definer bootstrap is untouched by this revision.
    op.add_column(
        "user_session",
        sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=True),
    )

    # --- Grants: duty-minimal (docs/database-roles.md). No DELETE — disable
    # and regeneration are soft-revokes; hard deletion is the erasure story's.
    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON TABLE user_mfa, mfa_recovery_code "
        "TO nc3_auth"
    )

    # --- RLS: deny-until-classified means classify now (user-arm rows).
    for table in _MFA_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_rows ON {table} FOR ALL TO nc3_auth "
            f"USING (user_id = {_USER}) WITH CHECK (user_id = {_USER})"
        )

    # --- Gate 1: deny-until-classified, re-run because this revision created
    # tables after the earlier gates ran (same SQL; docs/database-roles.md).
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
    # --- Gate 2 extension (B3's shape): the MFA tables hold seed ciphertext
    # and one-time credentials — nc3_auth stays DELETE-less on them, and no
    # other runtime role touches them at all.
    op.execute(
        """
        DO $$
        DECLARE
            offending text;
        BEGIN
            SELECT string_agg(check_name, ', ')
            INTO offending
            FROM (VALUES
                ('user_mfa DELETE (nc3_auth)',
                 has_table_privilege('nc3_auth', 'user_mfa', 'DELETE')),
                ('mfa_recovery_code DELETE (nc3_auth)',
                 has_table_privilege('nc3_auth', 'mfa_recovery_code', 'DELETE')),
                ('user_mfa (nc3_app any)',
                 has_table_privilege('nc3_app', 'user_mfa',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('mfa_recovery_code (nc3_app any)',
                 has_table_privilege('nc3_app', 'mfa_recovery_code',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('user_mfa (app_platform any)',
                 has_table_privilege('app_platform', 'user_mfa',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('mfa_recovery_code (app_platform any)',
                 has_table_privilege('app_platform', 'mfa_recovery_code',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('user_mfa (nc3_auth_definer any)',
                 has_table_privilege('nc3_auth_definer', 'user_mfa',
                     'SELECT, INSERT, UPDATE, DELETE')),
                ('mfa_recovery_code (nc3_auth_definer any)',
                 has_table_privilege('nc3_auth_definer', 'mfa_recovery_code',
                     'SELECT, INSERT, UPDATE, DELETE'))
            ) AS t(check_name, held)
            WHERE held;
            IF offending IS NOT NULL THEN
                RAISE EXCEPTION 'MFA tables hold privileges beyond the B4 '
                    'allowlist (%) — likely granted out of band; revoke them '
                    'first (docs/database-roles.md)', offending;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Revert this revision."""
    op.drop_column("user_session", "mfa_verified_at")
    # Table drops take their policies, FORCE flags, and grants along.
    op.drop_index(
        op.f("ix_mfa_recovery_code_user_id"), table_name="mfa_recovery_code"
    )
    op.drop_table("mfa_recovery_code")
    op.drop_table("user_mfa")
