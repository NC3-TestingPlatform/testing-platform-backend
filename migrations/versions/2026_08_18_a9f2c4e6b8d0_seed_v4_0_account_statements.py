"""Seed the v4.0 statements: terms acceptance and scan-target attestation.

Revision: a9f2c4e6b8d0
Revises: b3c7a9e2f4d1

Registration (B3 / US #79) records a consent receipt against real `statement`
rows, so the reference rows must exist. Ids, versions, hashes, and URIs are
verbatim from the mock `GET /statements` (domains/statements/router.py) —
the mock and the database agree until that operation is realized. The DPO
delivers the final texts (Non-functional → GDPR); a new text is a new version
row, never an edit here.

`statement` carries FORCE RLS with a read-only policy, so on a non-superuser
owner this DML must lift FORCE for the duration of its own transaction
(docs/database-migrations.md — the table is empty, the ACCESS EXCLUSIVE lock
is momentary).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "a9f2c4e6b8d0"
down_revision: str | None = "b3c7a9e2f4d1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TERMS_ID = "019ee1a2-0011-7c22-8d33-4e55f6a77b88"
_ATTESTATION_ID = "019ee1a2-2233-7e44-af55-6a77b899cdaa"


def upgrade() -> None:
    """Apply this revision."""
    op.execute("ALTER TABLE statement NO FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        INSERT INTO statement
            (id, statement_key, version, response_kind, required_context_type,
             content_hash, content_uri, effective_at, retired_at)
        VALUES
            ('{_TERMS_ID}', 'terms_and_conditions', '2026-01-15', 'acceptance',
             NULL,
             'sha256:2f8a1c9d4e7b0a3f6c5d8e1b4a7f0c3d6e9b2a5f8c1d4e7b0a3f6c5d8e1b4a7f',
             'https://testing.nc3.lu/legal/terms/2026-01-15',
             '2026-01-15T00:00:00Z', NULL),
            ('{_ATTESTATION_ID}', 'scan_target_permission', '2026-01-15',
             'attestation', 'scan_job',
             'sha256:7b0a3f6c5d8e1b4a7f0c3d6e9b2a5f8c1d4e7b0a3f6c5d8e1b4a7f2f8a1c9d4e',
             'https://testing.nc3.lu/legal/scan-permission/2026-01-15',
             '2026-01-15T00:00:00Z', NULL)
        """
    )
    op.execute("ALTER TABLE statement FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    """Revert this revision."""
    op.execute("ALTER TABLE statement NO FORCE ROW LEVEL SECURITY")
    op.execute(
        f"DELETE FROM statement WHERE id IN ('{_TERMS_ID}', '{_ATTESTATION_ID}')"
    )
    op.execute("ALTER TABLE statement FORCE ROW LEVEL SECURITY")
