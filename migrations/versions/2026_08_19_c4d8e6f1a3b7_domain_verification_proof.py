"""Domain-verification proof: platform-wide claim, provenance, org promotion.

Revision: c4d8e6f1a3b7
Revises: e5a1c3d7f9b2

All of B6's schema work in one revision; B6a (US #82) shipped none. Implements
the proof half (US #263 / B6b) of IDR-016 and IDR-019.

The load-bearing change is `uq_domain_verification_value`: a **global** unique
index that makes a verified domain name at most one organization, which is
IDR-016's single-active-claim rule. It works under FORCE RLS for one specific
reason worth writing down, because the next reader will assume the opposite:
**PostgreSQL exempts unique-index and referential-integrity checks from row
security.** The conflicting row is invisible to a tenant's `SELECT`, so the
application cannot detect the conflict itself — and must not try, since reading
it would need a SECURITY DEFINER function and would turn the refusal into a
cross-tenant disclosure. The constraint violation *is* the adjudication, and the
service discriminates it by this constraint's name.

`value` is denormalised onto the proof so that index has something to be unique
over, and pinned to its asset by a composite foreign key so the two copies cannot
drift. That key is named explicitly: the convention in `core/db.py` renders
`fk_domain_verification_asset_id_asset` for any foreign key whose first column is
`asset_id` and whose target is `asset`, which the initial schema already used for
the single-column key, and `pg_constraint` is unique on (conrelid, conname).

Provenance columns (`dnssec_validated`, `resolvers`, `corroborating_answers`) and
`last_reverified_at` are written by this story and read by nothing in v4.0: the
v4.1 intrusive gate is their consumer, and `last_reverified_at` ships now so that
story needs no second migration.

No new tables, so the deny-until-classified gates and the role grants are
untouched: column privileges follow the table grants already in place.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4d8e6f1a3b7"
down_revision: str | None = "e5a1c3d7f9b2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the claim index, the proof's provenance, and the org name stamp."""
    # The composite foreign key's target.
    op.create_unique_constraint("uq_asset_id_value", "asset", ["id", "value"])

    # `value` arrives nullable so an existing proof can be backfilled from its
    # asset, then becomes NOT NULL. There should be no such rows — the check
    # endpoint was a mock until this revision — but a dev database may hold some,
    # and a migration that assumes an empty table is a migration that fails once.
    op.add_column("domain_verification", sa.Column("value", sa.Text(), nullable=True))
    op.execute(
        """
        UPDATE domain_verification AS dv
           SET value = a.value
          FROM asset AS a
         WHERE a.id = dv.asset_id
           AND dv.value IS NULL
        """
    )
    op.alter_column("domain_verification", "value", nullable=False)

    op.add_column(
        "domain_verification",
        sa.Column("verified_by_user_id", sa.Uuid(), nullable=True),
    )
    op.add_column(
        "domain_verification",
        sa.Column(
            "dnssec_validated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
    )
    op.add_column(
        "domain_verification",
        sa.Column(
            "resolvers",
            sa.ARRAY(sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::text[]"),
        ),
    )
    op.add_column(
        "domain_verification",
        sa.Column(
            "corroborating_answers",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
    )
    op.add_column(
        "domain_verification",
        sa.Column("last_reverified_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        op.f("ix_domain_verification_verified_by_user_id"),
        "domain_verification",
        ["verified_by_user_id"],
        unique=False,
    )
    op.create_foreign_key(
        op.f("fk_domain_verification_verified_by_user_id_app_user"),
        "domain_verification",
        "app_user",
        ["verified_by_user_id"],
        ["id"],
        ondelete="SET NULL",
    )

    # The claim adjudication. Global on purpose: not scoped to organization.
    op.create_unique_constraint(
        "uq_domain_verification_value", "domain_verification", ["value"]
    )
    # Explicitly named; see the module docstring for why the convention's name
    # would collide with the existing single-column key.
    op.create_foreign_key(
        "fk_domain_verification_asset_value",
        "domain_verification",
        "asset",
        ["asset_id", "value"],
        ["id", "value"],
        ondelete="RESTRICT",
    )

    # First successful verification promotes the workspace to a named org
    # (IDR-016). Null means the name is still provisional.
    op.add_column(
        "organization",
        sa.Column("named_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    """Reverse in dependency order: the composite key before its target."""
    op.drop_column("organization", "named_at")
    op.drop_constraint(
        "fk_domain_verification_asset_value", "domain_verification", type_="foreignkey"
    )
    op.drop_constraint(
        "uq_domain_verification_value", "domain_verification", type_="unique"
    )
    op.drop_constraint(
        op.f("fk_domain_verification_verified_by_user_id_app_user"),
        "domain_verification",
        type_="foreignkey",
    )
    op.drop_index(
        op.f("ix_domain_verification_verified_by_user_id"),
        table_name="domain_verification",
    )
    op.drop_column("domain_verification", "last_reverified_at")
    op.drop_column("domain_verification", "corroborating_answers")
    op.drop_column("domain_verification", "resolvers")
    op.drop_column("domain_verification", "dnssec_validated")
    op.drop_column("domain_verification", "verified_by_user_id")
    op.drop_column("domain_verification", "value")
    op.drop_constraint("uq_asset_id_value", "asset", type_="unique")
