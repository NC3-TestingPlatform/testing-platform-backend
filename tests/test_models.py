"""Structural tests of the ORM against data-model-v4_0_2.md.

No database: the metadata itself is checked — the table inventory of the doc,
the §1 conventions (UUIDv7 primary keys named `id`, timestamptz everywhere),
and the §14 row-level constraints by name *and* expression — and the DDL is
compiled for the PostgreSQL dialect, which catches types, expressions, and
index predicates the target database cannot express. Behavior against a live
PostgreSQL arrives with the migration workflow (issue #6).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateIndex, CreateTable
from uuid6 import uuid7

from nc3_testing_platform.models import Base

# §3 through §12, one entry per table section of the doc.
EXPECTED_TABLES = {
    "organization",
    "app_user",
    "key_envelope",
    "organization_invitation",
    "asset",
    "domain_verification",
    "domain_verification_challenge",
    "statement",
    "statement_response",
    "file_upload",
    "scan_job",
    "scan_task",
    "scan_result",
    "finding",
    "schedule",
    "api_key",
    "report",
    "asset_feed",
    "notification",
    "organization_webhook",
    "audit_event",
}

# §14 verbatim: every row-level CHECK, keyed by table and constraint name.
# Comparing the expressions, not just counts, so a renamed, weakened, or
# tautological constraint cannot slip through.
EXPECTED_CHECKS: dict[str, dict[str, str]] = {
    "organization_invitation": {
        "acceptance_actor_implies_time": (
            "accepted_by_user_id IS NULL OR accepted_at IS NOT NULL"
        ),
    },
    "key_envelope": {
        "user_scope_has_user": "(scope = 'user') = (user_id IS NOT NULL)",
        "scan_job_scope_has_job": "(scope = 'scan_job') = (scan_job_id IS NOT NULL)",
        "guest_scope_lacks_org": "(scope = 'scan_job') = (organization_id IS NULL)",
    },
    "asset": {
        "child_implies_discovered": "parent_asset_id IS NULL OR origin = 'discovered'",
    },
    "domain_verification_challenge": {
        "failure_follows_recheck": (
            "failure_code IS NULL OR last_recheck_at IS NOT NULL"
        ),
    },
    "file_upload": {
        "storage_key_while_bytes_exist": (
            "(purged_at IS NULL) = (storage_key IS NOT NULL)"
        ),
        "uploader_implies_org": (
            "uploaded_by_user_id IS NULL OR organization_id IS NOT NULL"
        ),
        "purge_within_24_hours": "purge_due_at <= uploaded_at + interval '24 hours'",
        "purge_not_before_upload": "purge_due_at >= uploaded_at",
    },
    "scan_job": {
        "one_launch_target": (
            "num_nonnulls(asset_id, target_domain, file_upload_id) = 1"
        ),
        "modules_not_empty": "cardinality(modules) >= 1",
        "schedule_provenance": "(source = 'schedule') = (schedule_id IS NOT NULL)",
        "api_key_provenance": "(source = 'api') = (api_key_id IS NOT NULL)",
        "guest_only_target_text": "target_domain IS NULL OR source = 'guest'",
        "guest_only_claimable": "claim_token_hash IS NULL OR source = 'guest'",
        "unclaimed_guest_holds_hash": (
            "source <> 'guest' OR claimed_at IS NOT NULL "
            "OR claim_token_hash IS NOT NULL"
        ),
        "claim_actor_implies_time": (
            "claimed_by_user_id IS NULL OR claimed_at IS NOT NULL"
        ),
        "claimed_job_has_org": "claimed_at IS NULL OR organization_id IS NOT NULL",
        "claim_discards_hash": "claimed_at IS NULL OR claim_token_hash IS NULL",
        "only_guest_lacks_org": "organization_id IS NOT NULL OR source = 'guest'",
        "terminal_state_has_finish": (
            "(status IN ('completed', 'partial', 'failed', 'canceled')) "
            "= (finished_at IS NOT NULL)"
        ),
        "running_has_start": "status <> 'running' OR started_at IS NOT NULL",
        "purge_deadline_placement": (
            "(purge_at IS NOT NULL) = "
            "(status IN ('completed', 'partial', 'failed', 'canceled') "
            "OR (source = 'guest' AND claimed_at IS NULL))"
        ),
    },
    "scan_task": {
        "one_task_target": (
            "num_nonnulls(target_asset_id, target_domain, file_upload_id) = 1"
        ),
        "blocked_says_why": "status <> 'blocked' OR status_reason IS NOT NULL",
        "not_applicable_is_file_only": (
            "(module = 'file') = (classification = 'not_applicable')"
        ),
        "file_task_targets_upload": (
            "(file_upload_id IS NOT NULL) = (module = 'file')"
        ),
        "terminal_state_has_finish": (
            "(status IN ('completed', 'failed', 'skipped', 'blocked', 'canceled')) "
            "= (finished_at IS NOT NULL)"
        ),
        "running_has_start": "status <> 'running' OR started_at IS NOT NULL",
    },
    "schedule": {
        "modules_not_empty": "cardinality(modules) >= 1",
    },
    "statement_response": {
        "context_named_and_bound": "(context_type IS NULL) = (context_id IS NULL)",
    },
    "report": {
        "one_source": "num_nonnulls(source_scan_job_id, source_scan_task_id) = 1",
        "view_is_technical_only": "tier = 'technical' OR technical_view IS NULL",
    },
    "api_key": {
        "reason_implies_revocation": (
            "revocation_reason IS NULL OR revoked_at IS NOT NULL"
        ),
    },
    "audit_event": {
        "payload_group_all_or_none": (
            "num_nonnulls(payload_encrypted, wrapped_dek, envelope_id, "
            "encryption_metadata) IN (0, 4)"
        ),
        "detail_or_payload": "detail IS NOT NULL OR payload_encrypted IS NOT NULL",
        "retention_not_before_occurrence": "retention_until >= occurred_at",
    },
}

# §14: the uniqueness rules that need a partial or expression index, with the
# fragments their compiled DDL must contain.
EXPECTED_PARTIAL_UNIQUES: dict[tuple[str, str], tuple[str, ...]] = {
    ("organization_invitation", "uq_organization_invitation_live_email"): (
        "lower(email)",
        "WHERE accepted_at IS NULL AND revoked_at IS NULL",
    ),
    ("key_envelope", "uq_key_envelope_organization_scope"): (
        "WHERE scope = 'organization'",
    ),
    ("statement_response", "uq_statement_response_account_level"): (
        "WHERE context_type IS NULL",
    ),
    ("statement_response", "uq_statement_response_contextual"): (
        "WHERE context_type IS NOT NULL",
    ),
}


def test_table_inventory_matches_the_doc() -> None:
    """Every documented table exists and nothing undocumented crept in."""
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_every_table_has_a_uuid7_primary_key_named_id() -> None:
    """§1: primary keys are UUIDv7 values in a column called `id`.

    The default must be the application-side uuid7 callable itself, so key
    order stays creation order without waiting for a database round trip.
    """
    assert uuid7().version == 7
    for table in Base.metadata.tables.values():
        pk = list(table.primary_key.columns)
        assert len(pk) == 1, table.name
        assert pk[0].name == "id", table.name
        assert isinstance(pk[0].type, sa.Uuid), table.name
        default = pk[0].default
        assert isinstance(default, sa.ColumnDefault), table.name
        assert default.is_callable, table.name
        # SQLAlchemy wraps the callable to accept an execution context, so the
        # proof is invoking it: the generated value must be a version-7 UUID.
        generated = default.arg(None)  # type: ignore[call-arg]
        assert generated.version == 7, table.name


def test_timestamps_are_timezone_aware() -> None:
    """§1: timestamps use UTC timestamptz."""
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, sa.DateTime):
                assert column.type.timezone, f"{table.name}.{column.name}"


def test_section_14_checks_match_by_name_and_expression() -> None:
    """Each §14 table carries exactly the documented CHECKs, verbatim."""
    for table_name, expected in EXPECTED_CHECKS.items():
        table = Base.metadata.tables[table_name]
        # The naming convention has already stamped the ck_<table>_ prefix on.
        actual = {
            str(c.name).removeprefix(f"ck_{table_name}_"): str(c.sqltext)
            for c in table.constraints
            if isinstance(c, sa.CheckConstraint)
        }
        assert actual == expected, table_name
    for table_name in EXPECTED_TABLES - set(EXPECTED_CHECKS):
        table = Base.metadata.tables[table_name]
        stray = [c for c in table.constraints if isinstance(c, sa.CheckConstraint)]
        assert not stray, f"undocumented CHECK on {table_name}"


def test_partial_unique_indexes_compile_with_their_predicates() -> None:
    """§14: the partial/expression uniqueness rules render the right DDL."""
    dialect = postgresql.dialect()
    for (table_name, index_name), fragments in EXPECTED_PARTIAL_UNIQUES.items():
        index = next(
            i for i in Base.metadata.tables[table_name].indexes if i.name == index_name
        )
        assert index.unique, index_name
        ddl = str(CreateIndex(index).compile(dialect=dialect))
        assert "UNIQUE" in ddl, index_name
        for fragment in fragments:
            assert fragment in ddl, f"{index_name}: {fragment!r}"


def test_ddl_compiles_for_postgresql() -> None:
    """Every table and every index renders on the PostgreSQL dialect."""
    dialect = postgresql.dialect()
    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=dialect))
        assert table.name in ddl
        for index in table.indexes:
            assert str(CreateIndex(index).compile(dialect=dialect))
