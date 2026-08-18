"""Adopt the v3 legal texts for the account statements.

Revision: d7e3f1a2b4c6
Revises: a9f2c4e6b8d0

The a9f2c4e6b8d0 seed carried placeholder digests that correspond to no
document, so a consent receipt could not be verified against a text (GDPR
Art. 7(1) demonstrability — flagged in PR #38 review). Until the DPO delivers
the v4 texts (Non-functional → GDPR), the live v3 documents are adopted
provisionally (decision 2026-08-18):

* `terms_and_conditions` → version `2024-10` ("last updated October 2024"
  per the page), pointing at https://testing.nc3.lu/terms-conditions/ with
  the SHA-256 of the canonical snapshot committed at
  `docs/legal/terms-of-service-2024-10.md`. The placeholder row is corrected
  in place rather than versioned: its 2026-01-15 "version" named no real
  text, and no production registration exists to have attested to it.
* `privacy_policy` → new acceptance statement (the NFR requires explicit
  privacy consent at signup), version `2026-08-18` (the page is undated, so
  the snapshot date pins the text), pointing at
  https://testing.nc3.lu/privacy/ with the SHA-256 of
  `docs/legal/privacy-statement-2026-08-18.md`. Registration requires every
  active account-level acceptance, so the new row binds automatically.
* `scan_target_permission` keeps its placeholder: it is a per-launch
  attestation, and no test in the v4.0 executable catalog is classified
  intrusive, so nothing can record a receipt against it yet.

The DPO's v4 texts land later as NEW version rows (retiring these), never as
edits. Same NO FORCE wrap as the seed (docs/database-migrations.md).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "d7e3f1a2b4c6"
down_revision: str | None = "a9f2c4e6b8d0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TERMS_ID = "019ee1a2-0011-7c22-8d33-4e55f6a77b88"
_PRIVACY_ID = "019ee1a2-3344-7f55-b066-7b88c9aadbcc"

_TERMS_HASH = (
    "sha256:6d80fb1d091c6aaeeb406150fd635976fffde54ad314aac373e7601f60a2c21a"
)
_PRIVACY_HASH = (
    "sha256:04c03ecda8de1e039eba8fa3e5f428a631308008166b87ddb5b7e4cbfe9d4b56"
)

# The seed's placeholder values, restored verbatim on downgrade.
_SEED_TERMS_HASH = (
    "sha256:2f8a1c9d4e7b0a3f6c5d8e1b4a7f0c3d6e9b2a5f8c1d4e7b0a3f6c5d8e1b4a7f"
)


def upgrade() -> None:
    """Apply this revision."""
    op.execute("ALTER TABLE statement NO FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        UPDATE statement
        SET version = '2024-10',
            content_hash = '{_TERMS_HASH}',
            content_uri = 'https://testing.nc3.lu/terms-conditions/',
            effective_at = '2024-10-01T00:00:00Z'
        WHERE id = '{_TERMS_ID}'
        """
    )
    op.execute(
        f"""
        INSERT INTO statement
            (id, statement_key, version, response_kind, required_context_type,
             content_hash, content_uri, effective_at, retired_at)
        VALUES
            ('{_PRIVACY_ID}', 'privacy_policy', '2026-08-18', 'acceptance',
             NULL, '{_PRIVACY_HASH}', 'https://testing.nc3.lu/privacy/',
             '2026-08-18T00:00:00Z', NULL)
        """
    )
    op.execute("ALTER TABLE statement FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    """Revert this revision."""
    op.execute("ALTER TABLE statement NO FORCE ROW LEVEL SECURITY")
    op.execute(f"DELETE FROM statement WHERE id = '{_PRIVACY_ID}'")
    op.execute(
        f"""
        UPDATE statement
        SET version = '2026-01-15',
            content_hash = '{_SEED_TERMS_HASH}',
            content_uri = 'https://testing.nc3.lu/legal/terms/2026-01-15',
            effective_at = '2026-01-15T00:00:00Z'
        WHERE id = '{_TERMS_ID}'
        """
    )
    op.execute("ALTER TABLE statement FORCE ROW LEVEL SECURITY")
