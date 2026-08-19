"""Adopt the v3 legal texts for the account statements.

Revision: d7e3f1a2b4c6
Revises: a9f2c4e6b8d0

The a9f2c4e6b8d0 seed carried placeholder digests that correspond to no
document, so a consent receipt could not be verified against a text (GDPR
Art. 7(1) demonstrability — flagged in PR #38 review). Until the DPO delivers
the v4 texts (Non-functional → GDPR), the live v3 documents are adopted
provisionally (decision 2026-08-18):

* `terms_and_conditions` → version `2026-08-18`: the platform's adapted
  Terms of Service, committed at `docs/legal/terms-of-service-2026-08-18.md`
  (adapted from the v3 page with four corrections found in the PR #39
  review — mistyped privacy link, malformed survival clause, undefined
  "Data Shared", account-creation data list aligned with what
  registration collects; the file header lists them). The placeholder row is
  corrected in place rather than versioned: its 2026-01-15 "version" named
  no real text, and no production registration exists to have attested to it.
* `privacy_policy` → new acceptance statement (the NFR requires explicit
  privacy consent at signup), version `2026-08-18`: the platform's adapted
  Privacy Statement at `docs/legal/privacy-statement-2026-08-18.md`
  (truncated sentence completed; the approved retention figures added
  and reconciled with the anonymizing deletion workflow).
  Registration requires every active account-level acceptance, so the new
  row binds automatically.
* `content_hash` is the SHA-256 of the committed file; `content_uri` points
  at the file on the public repository — the live v3 pages no longer match
  the adapted text, so a receipt must reference the exact document shown.
* `scan_target_permission` keeps its placeholder: it is a per-launch
  attestation, and no test in the v4.0 executable catalog is classified
  intrusive, so nothing can record a receipt against it yet.

The DPO's v4 texts land later as NEW version rows (retiring these), never as
edits. Same NO FORCE wrap as the seed (docs/database-migrations.md).

Downgrade refuses while any consent receipt references these statements:
deleting the privacy row would fail on its FK anyway, and rewriting the
terms row would silently invalidate the text identity recorded consent
attests to. A development database in that state is wiped, not downgraded
(docs/database-migrations.md wipe rules).
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
    "sha256:5849ebd2b3c3eb22985f1507483fa21e9a364ddd72e72a7a6f00034438fb1515"
)
_PRIVACY_HASH = (
    "sha256:4035948413e80ebea43cae2a53f956ea26939838f3ec0c2064a554cf9c0d28b9"
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
        SET version = '2026-08-18',
            content_hash = '{_TERMS_HASH}',
            content_uri = 'https://github.com/NC3-TestingPlatform/testing-platform-backend/blob/fd0926985b6343c040a92a91c00ef3e63d804518/docs/legal/terms-of-service-2026-08-18.md',
            effective_at = '2026-08-18T00:00:00Z'
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
             NULL, '{_PRIVACY_HASH}', 'https://github.com/NC3-TestingPlatform/testing-platform-backend/blob/fd0926985b6343c040a92a91c00ef3e63d804518/docs/legal/privacy-statement-2026-08-18.md',
             '2026-08-18T00:00:00Z', NULL)
        """
    )
    op.execute("ALTER TABLE statement FORCE ROW LEVEL SECURITY")


def downgrade() -> None:
    """Revert this revision; refused while consent receipts exist."""
    # The count must run with FORCE lifted: on a non-superuser owner the
    # receipts table's policies would otherwise hide every row and the guard
    # would silently pass (docs/database-migrations.md). A raised exception
    # aborts the transaction, so the lift never outlives a refusal.
    op.execute("ALTER TABLE statement_response NO FORCE ROW LEVEL SECURITY")
    op.execute(
        f"""
        DO $$
        DECLARE
            receipts bigint;
        BEGIN
            SELECT count(*) INTO receipts
            FROM statement_response
            WHERE statement_id IN ('{_TERMS_ID}', '{_PRIVACY_ID}');
            IF receipts > 0 THEN
                RAISE EXCEPTION 'refusing downgrade: % consent receipt(s) '
                    'attest to these statement versions — deleting or '
                    'rewriting them would invalidate recorded consent. Wipe '
                    'the development database instead '
                    '(docs/database-migrations.md wipe rules)', receipts;
            END IF;
        END
        $$;
        """
    )
    op.execute("ALTER TABLE statement_response FORCE ROW LEVEL SECURITY")
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
