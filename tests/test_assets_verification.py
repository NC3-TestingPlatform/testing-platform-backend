"""Unit tests for the assets verification slice (B6a / US #82).

The repository is exercised by compiling the statements it builds and asserting
their shape: the conflict target, the columns a replacement resets, and that
every timestamp comes from the database clock.

None of that proves behaviour. Whether the conflict target matches the live
unique constraint, whether the upsert holds under real concurrency, and whether
the policy actually hides another organization's rows are all questions only a
real database answers — `tests/test_verification_postgres.py`, still to be
written (task #271), owns them. Until it exists this file's guarantees stop at
"the statement is shaped as intended".
"""

import uuid
from datetime import timedelta
from unittest.mock import MagicMock

from sqlalchemy.dialects import postgresql
from uuid6 import uuid7

from nc3_testing_platform.core import enums
from nc3_testing_platform.domains.assets import repository

ASSET_ID = uuid7()
ORG_ID = uuid7()
USER_ID = uuid7()
TTL = timedelta(days=7)


# --- repository --------------------------------------------------------------


def _upsert(db: MagicMock, **overrides: object) -> object:
    kwargs: dict[str, object] = {
        "asset_id": ASSET_ID,
        "organization_id": ORG_ID,
        "requested_scope": enums.VerificationScope.ZONE,
        "record_name": "_nc3-verify.example.lu",
        "token": "a-token",
        "ttl": TTL,
        "requested_by_user_id": USER_ID,
    }
    kwargs.update(overrides)
    return repository.upsert_challenge(db, **kwargs)  # type: ignore[arg-type]


def _upsert_sql(**overrides: object) -> str:
    """Compile the statement `upsert_challenge` builds, without executing it."""
    db = MagicMock()
    _upsert(db, **overrides)
    statement = db.scalars.call_args.args[0]
    return str(statement.compile(dialect=postgresql.dialect()))


def _update_set_clause(sql: str) -> str:
    """Just the ``DO UPDATE SET`` assignments.

    Cutting at RETURNING matters: that clause names every column of the table,
    so an assertion over the remainder of the statement would be satisfied by
    the returned columns and prove nothing about what the upsert writes.
    """
    after_conflict = sql.split("DO UPDATE", 1)[1]
    return after_conflict.split("RETURNING", 1)[0]


def test_repository_upsert_challenge_conflicts_on_asset_id() -> None:
    """Replacement is the same statement as creation, keyed on the unique column.

    A read-then-write would let two concurrent requests race, the loser raising
    a unique violation on a path whose contract is "creating a challenge
    replaces the existing one".
    """
    sql = _upsert_sql()
    assert "INSERT INTO domain_verification_challenge" in sql
    assert "ON CONFLICT (asset_id) DO UPDATE" in sql


def test_repository_upsert_challenge_resets_the_previous_attempt() -> None:
    """A fresh token has never been checked, so prior attempt state must go.

    `last_recheck_at` and `failure_code` describe one attempt; carrying them
    onto a replacement would report the old challenge's failure against the new
    one, which is what the UI reads as the current state.
    """
    update_clause = _update_set_clause(_upsert_sql())
    assert "last_recheck_at" in update_clause
    assert "failure_code" in update_clause
    assert "verification_token" in update_clause
    assert "token_expires_at" in update_clause


def test_repository_upsert_challenge_takes_its_clock_from_the_database() -> None:
    """Expiry must be comparable with every other stamp on the row.

    An application-side `datetime.now()` would drift from the database clock
    that `token_expires_at > now()` is later compared against.
    """
    assert "now()" in _upsert_sql()


def test_repository_upsert_challenge_is_txt_only() -> None:
    """TXT is the only v4.0 verification method; it is not caller input."""
    db = MagicMock()
    _upsert(db, requested_scope=enums.VerificationScope.EXACT)
    params = db.scalars.call_args.args[0].compile().params
    assert params["record_type"] is enums.DnsRecordType.TXT


def test_repository_upsert_challenge_returns_the_row() -> None:
    """The caller needs the stored row, not a rowcount: the token is in it."""
    db = MagicMock()
    sentinel = object()
    db.scalars.return_value.one.return_value = sentinel
    returned = _upsert(db)
    assert returned is sentinel
    sql = str(db.scalars.call_args.args[0].compile(dialect=postgresql.dialect()))
    assert "RETURNING" in sql


def test_repository_reads_are_scoped_by_the_asset_not_the_organization() -> None:
    """RLS scopes the read; the query must not also filter on organization.

    An application-side org predicate would look like defence in depth and is
    not: it hides a missing RLS context behind application code, so a bug in
    the context would stop being visible.
    """
    db = MagicMock()
    repository.challenge_for(db, ASSET_ID)
    sql = str(db.scalars.call_args.args[0].compile(dialect=postgresql.dialect()))
    assert "asset_id" in sql
    assert "organization_id" not in sql.split("WHERE", 1)[1]


def test_repository_proof_lookup_is_by_asset() -> None:
    """Presence of the row is the verified status; there is no status column."""
    db = MagicMock()
    repository.proof_for(db, ASSET_ID)
    sql = str(db.scalars.call_args.args[0].compile(dialect=postgresql.dialect()))
    assert "FROM domain_verification" in sql
    assert "asset_id" in sql


def test_repository_asset_lookup_always_queries_the_database() -> None:
    """Never `Session.get`: a cached hit would skip re-evaluating the policy.

    `get` consults the identity map first, so a row loaded before a mid-request
    commit — after which `SET LOCAL` is gone until re-asserted — would be
    returned without the policy ever running again. Fail-closed depends on the
    statement actually reaching PostgreSQL.
    """
    db = MagicMock()
    asset_id = uuid.UUID(int=1)
    repository.asset_for(db, asset_id)
    db.get.assert_not_called()
    sql = str(db.scalars.call_args.args[0].compile(dialect=postgresql.dialect()))
    assert "FROM asset" in sql


def test_repository_upsert_challenge_never_reassigns_the_organization() -> None:
    """`organization_id` must not appear in the DO UPDATE clause.

    It is caller-supplied per call rather than re-derived from the asset, so
    folding it into the update set — an easy "for consistency" refactor —
    would open a path to rewriting an existing challenge's tenant.
    """
    assert "organization_id" not in _update_set_clause(_upsert_sql())
