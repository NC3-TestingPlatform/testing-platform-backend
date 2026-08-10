"""Structural tests of the ORM against data-model-v4_0_1.md.

No database: the metadata itself is checked — the table inventory of the doc,
the §1 conventions (UUIDv7 primary keys named `id`, timestamptz everywhere),
and the presence of the §14 row-level constraints — and the DDL is compiled
for the PostgreSQL dialect, which catches types or expressions the target
database cannot express. Behavior against a live PostgreSQL arrives with the
migration workflow (issue #6).
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

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

# §14: tables carrying row-level CHECK constraints, with the count the doc lists.
EXPECTED_CHECK_COUNTS = {
    "organization_invitation": 1,
    "key_envelope": 3,
    "asset": 1,
    "domain_verification_challenge": 1,
    "file_upload": 3,
    "scan_job": 13,
    "scan_task": 6,
    "statement_response": 1,
    "report": 2,
    "api_key": 1,
    "audit_event": 2,
}


def test_table_inventory_matches_the_doc() -> None:
    """Every documented table exists and nothing undocumented crept in."""
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_every_table_has_a_uuid_primary_key_named_id() -> None:
    """§1: primary keys are UUIDv7 values in a column called `id`."""
    for table in Base.metadata.tables.values():
        pk = list(table.primary_key.columns)
        assert len(pk) == 1, table.name
        assert pk[0].name == "id", table.name
        assert isinstance(pk[0].type, sa.Uuid), table.name


def test_timestamps_are_timezone_aware() -> None:
    """§1: timestamps use UTC timestamptz."""
    for table in Base.metadata.tables.values():
        for column in table.columns:
            if isinstance(column.type, sa.DateTime):
                assert column.type.timezone, f"{table.name}.{column.name}"


def test_section_14_check_constraints_are_present() -> None:
    """Each §14 table carries exactly the number of CHECKs the doc lists."""
    for table_name, expected in EXPECTED_CHECK_COUNTS.items():
        table = Base.metadata.tables[table_name]
        checks = [
            c for c in table.constraints if isinstance(c, sa.CheckConstraint)
        ]
        assert len(checks) == expected, table_name


def test_partial_unique_indexes_are_present() -> None:
    """§14: the three uniqueness rules that need a partial or expression index."""
    expected = {
        "organization_invitation": "uq_organization_invitation_live_email",
        "key_envelope": "uq_key_envelope_organization_scope",
    }
    for table_name, index_name in expected.items():
        table = Base.metadata.tables[table_name]
        index = next(i for i in table.indexes if i.name == index_name)
        assert index.unique
        assert index.dialect_options["postgresql"]["where"] is not None

    responses = Base.metadata.tables["statement_response"]
    partial_uniques = {
        i.name for i in responses.indexes if i.unique
    }
    assert partial_uniques == {
        "uq_statement_response_account_level",
        "uq_statement_response_contextual",
    }


def test_ddl_compiles_for_postgresql() -> None:
    """Every table's CREATE TABLE renders on the PostgreSQL dialect."""
    dialect = postgresql.dialect()
    for table in Base.metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=dialect))
        assert table.name in ddl
