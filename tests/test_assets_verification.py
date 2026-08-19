"""Unit tests for the assets verification slice (B6a / US #82).

The repository is exercised by compiling the statements it builds and asserting
their shape: the conflict target, the columns a replacement resets, and that
every timestamp comes from the database clock.

None of that proves behaviour. Whether the conflict target matches the live
unique constraint, whether the upsert holds under real concurrency, and whether
the policy actually hides another organization's rows are all questions only a
real database answers — `tests/test_verification_postgres.py` owns them, and it
found a stale-token bug none of this could see. This file's guarantees stop at
"the statement is shaped as intended".
"""

import logging
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql
from uuid6 import uuid7

from nc3_testing_platform.core import api_db, enums, security
from nc3_testing_platform.domains.assets import dependencies as assets_dependencies
from nc3_testing_platform.domains.assets import repository, service
from nc3_testing_platform.main import app

ASSET_ID = uuid7()
ORG_ID = uuid7()
USER_ID = uuid7()
TTL = timedelta(days=7)
_NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)


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


# --- service -----------------------------------------------------------------


def _asset(asset_type: enums.AssetType = enums.AssetType.DOMAIN) -> SimpleNamespace:
    return SimpleNamespace(id=ASSET_ID, value="example.lu", asset_type=asset_type)


def _challenge(
    *,
    scope: enums.VerificationScope = enums.VerificationScope.EXACT,
    expires_in: timedelta = timedelta(days=7),
) -> SimpleNamespace:
    """A challenge row shaped enough for the status computation."""
    return SimpleNamespace(
        requested_scope=scope, token_expires_at=_NOW + expires_in
    )


def _proof() -> SimpleNamespace:
    return SimpleNamespace(
        verified_scope=enums.VerificationScope.EXACT, verified_at=_NOW
    )


def _clock_db() -> MagicMock:
    """A session mock whose `select now()` answers a fixed instant."""
    db = MagicMock()
    db.execute.return_value.scalar_one.return_value = _NOW
    return db


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    asset: object | None,
    proof: object | None = None,
    challenge: object | None = None,
) -> list[dict[str, object]]:
    """Point the service at fixed repository answers; record upsert calls."""
    upserts: list[dict[str, object]] = []
    monkeypatch.setattr(service.repository, "asset_for", lambda db, aid: asset)
    monkeypatch.setattr(service.repository, "proof_for", lambda db, aid: proof)
    monkeypatch.setattr(service.repository, "challenge_for", lambda db, aid: challenge)
    monkeypatch.setattr(
        service.repository,
        "upsert_challenge",
        lambda db, **kw: upserts.append(kw)
        or SimpleNamespace(
            **kw, token_expires_at=_NOW + timedelta(days=7)
        ),
    )
    return upserts


def test_service_read_state_refuses_an_invisible_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absent and another organization's are one answer, by design."""
    _wire(monkeypatch, asset=None)
    with pytest.raises(service.AssetNotFoundError):
        service.read_state(MagicMock(), ASSET_ID)


def test_service_read_state_distinguishes_never_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No proof and no challenge is `404`, not an empty verification object."""
    _wire(monkeypatch, asset=_asset())
    with pytest.raises(service.VerificationNotStartedError):
        service.read_state(MagicMock(), ASSET_ID)


def test_service_read_state_returns_a_proof_and_a_challenge_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both rows are the state: a verified asset may be re-proving in parallel."""
    proof, challenge = _proof(), _challenge()
    _wire(monkeypatch, asset=_asset(), proof=proof, challenge=challenge)
    state = service.read_state(_clock_db(), ASSET_ID)
    assert (state.proof, state.challenge) == (proof, challenge)


def test_service_start_challenge_refuses_a_non_domain_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The asset_type rule is cross-table, so the schema cannot hold it."""
    _wire(monkeypatch, asset=_asset(asset_type="ip"))  # type: ignore[arg-type]
    with pytest.raises(service.NotADomainAssetError):
        service.start_challenge(
            MagicMock(),
            asset_id=ASSET_ID,
            organization_id=ORG_ID,
            user_id=USER_ID,
            requested_scope=enums.VerificationScope.ZONE,
        )


def test_service_start_challenge_builds_the_record_name_and_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The user is handed a name to publish, so the write must be durable first."""
    upserts = _wire(monkeypatch, asset=_asset())
    db = _clock_db()
    state = service.start_challenge(
        db,
        asset_id=ASSET_ID,
        organization_id=ORG_ID,
        user_id=USER_ID,
        requested_scope=enums.VerificationScope.ZONE,
    )
    assert upserts[0]["record_name"] == "_nc3-verify.example.lu"
    assert upserts[0]["requested_scope"] is enums.VerificationScope.ZONE
    # A real generated token reached the repository, not a placeholder.
    assert isinstance(upserts[0]["token"], str) and upserts[0]["token"]
    assert state.challenge is not None
    db.commit.assert_called_once()


def test_service_start_challenge_is_allowed_while_a_proof_stands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Widening must not withdraw coverage the user still holds.

    The standing proof comes back alongside the new challenge, which is what
    lets the response keep reporting `verified` while DNS is being edited.
    """
    proof = _proof()
    _wire(monkeypatch, asset=_asset(), proof=proof)
    state = service.start_challenge(
        _clock_db(),
        asset_id=ASSET_ID,
        organization_id=ORG_ID,
        user_id=USER_ID,
        requested_scope=enums.VerificationScope.ZONE,
    )
    assert state.proof is proof
    assert state.challenge is not None


def test_service_never_logs_the_token(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The token is the credential the caller is about to publish.

    Asserted rather than left to discipline: one careless `%s` or an
    `exception()` on this path would put it in shared logs, which the PII rules
    forbid domains from reaching, let alone credentials.
    """
    _wire(monkeypatch, asset=_asset())
    monkeypatch.setattr(service.verification, "generate_token", lambda: "S3CRET-TOKEN")
    with caplog.at_level(logging.DEBUG, logger="nc3_testing_platform.domains.assets"):
        service.start_challenge(
            _clock_db(),
            asset_id=ASSET_ID,
            organization_id=ORG_ID,
            user_id=USER_ID,
            requested_scope=enums.VerificationScope.EXACT,
        )
    assert "S3CRET-TOKEN" not in caplog.text


def test_service_regenerate_refuses_a_verified_asset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replacing the token would discard a working proof for nothing."""
    _wire(monkeypatch, asset=_asset(), proof=_proof(), challenge=_challenge())
    with pytest.raises(service.AlreadyVerifiedError):
        service.regenerate_token(
            MagicMock(), asset_id=ASSET_ID, organization_id=ORG_ID, user_id=USER_ID
        )


def test_service_regenerate_refuses_when_no_challenge_stands(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """There is nothing to replace; the caller wants `POST .../verification`."""
    _wire(monkeypatch, asset=_asset())
    with pytest.raises(service.VerificationNotStartedError):
        service.regenerate_token(
            MagicMock(), asset_id=ASSET_ID, organization_id=ORG_ID, user_id=USER_ID
        )


def test_service_regenerate_keeps_the_existing_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A retry must not quietly change coverage.

    Silently widening while replacing a token would be a privilege change
    disguised as a retry; widening is `start_challenge`, where scope is explicit.
    """
    existing = _challenge()
    upserts = _wire(monkeypatch, asset=_asset(), challenge=existing)
    fresh = service.regenerate_token(
        _clock_db(), asset_id=ASSET_ID, organization_id=ORG_ID, user_id=USER_ID
    )
    assert upserts[0]["requested_scope"] is enums.VerificationScope.EXACT
    # A fresh token, not the stalled one being replaced.
    assert isinstance(upserts[0]["token"], str) and upserts[0]["token"]
    assert fresh.challenge is not None


# --- router: gate composition ------------------------------------------------
#
# The smoke suite is gate-blind and exempts these operations, and the service
# tests never reach the router, so without this section the wiring
# `dependencies=[OrgAdminRequired, MfaAssuranceRequired, ChallengeRateLimited]`
# is asserted nowhere. Reordering or dropping one would regress silently.

_VERIFY_URL = f"/api/v1/assets/{ASSET_ID}/verification"


def _identity(
    role: enums.OrganizationRole = enums.OrganizationRole.ORGANIZATION_ADMIN,
    *,
    assured: bool = True,
) -> security.AuthenticatedSession:
    return security.AuthenticatedSession(
        session_id=uuid7(),
        user_id=USER_ID,
        organization_id=ORG_ID,
        mfa_enrolled=True,
        mfa_verified_at=_NOW if assured else None,
        observed_at=_NOW,
        organization_role=role,
    )


@pytest.fixture
def gated_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """A client over the real app, with the session and DB dependencies stubbed.

    The gates themselves are NOT overridden — that is the point: they run
    against whatever identity `require_session` is made to return.
    """
    consumed: list[str] = []

    async def _record(key: str, *, limit: int, window_seconds: int) -> None:
        consumed.append(key)

    monkeypatch.setattr(assets_dependencies, "enforce_rate_limit", _record)
    app.dependency_overrides[api_db.app_session] = lambda: MagicMock()
    app.dependency_overrides[api_db.auth_session] = lambda: MagicMock()
    with TestClient(app) as test_client:
        test_client.rate_limit_keys = consumed  # type: ignore[attr-defined]
        yield test_client
    app.dependency_overrides.clear()


def _as(identity: security.AuthenticatedSession) -> None:
    app.dependency_overrides[security.require_session] = lambda: identity


def test_router_create_refuses_a_member_before_spending_rate_budget(
    gated_client: TestClient,
) -> None:
    """A non-admin gets 403, and must not burn the organization's budget.

    Ordering matters: if the rate limit ran first, any authenticated member
    could exhaust an admin's budget for an asset they are not allowed to touch.
    """
    _as(_identity(enums.OrganizationRole.MEMBER))
    response = gated_client.post(_VERIFY_URL, json={"requested_scope": "zone"})
    assert response.status_code == 403
    assert response.json()["type"].endswith("org-role-required")
    assert gated_client.rate_limit_keys == []  # type: ignore[attr-defined]


def test_router_create_refuses_stale_mfa_before_spending_rate_budget(
    gated_client: TestClient,
) -> None:
    """An admin without current assurance gets 403, budget untouched."""
    _as(_identity(assured=False))
    response = gated_client.post(_VERIFY_URL, json={"requested_scope": "zone"})
    assert response.status_code == 403
    assert response.json()["type"].endswith("mfa-stepup-required")
    assert gated_client.rate_limit_keys == []  # type: ignore[attr-defined]


def test_router_token_regeneration_carries_the_same_gates(
    gated_client: TestClient,
) -> None:
    """The token endpoint is gated identically; a member cannot reach it."""
    _as(_identity(enums.OrganizationRole.MEMBER))
    response = gated_client.post(f"{_VERIFY_URL}/token")
    assert response.status_code == 403
    assert gated_client.rate_limit_keys == []  # type: ignore[attr-defined]


def test_router_get_is_readable_by_a_member(
    gated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading state is member-level: only the writes are admin acts (IDR-016).

    Also pins that the read consumes no rate-limit budget.
    """
    _as(_identity(enums.OrganizationRole.MEMBER))
    monkeypatch.setattr(
        service,
        "read_state",
        lambda db, aid: service.VerificationState(
            status=enums.VerificationStatus.EXPIRED, proof=None, challenge=None
        ),
    )
    response = gated_client.get(_VERIFY_URL)
    assert response.status_code == 200
    assert gated_client.rate_limit_keys == []  # type: ignore[attr-defined]


def test_router_token_bearing_responses_are_not_cacheable(
    gated_client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The body carries a token the caller is about to publish.

    A shared proxy or browser disk cache keeping it would outlive the reason it
    was shown; the feed-token endpoints already take this treatment.
    """
    _as(_identity())
    monkeypatch.setattr(
        service,
        "read_state",
        lambda db, aid: service.VerificationState(
            status=enums.VerificationStatus.PENDING,
            proof=None,
            # A row-shaped stand-in: the mapper only reads scalar attributes,
            # and building a real ORM instance would need a session.
            challenge=SimpleNamespace(  # type: ignore[arg-type]
                id=uuid7(),
                requested_scope=enums.VerificationScope.ZONE,
                record_type=enums.DnsRecordType.TXT,
                record_name="_nc3-verify.example.lu",
                verification_token="a-token",
                token_expires_at=_NOW + timedelta(days=7),
                requested_by_user_id=USER_ID,
                requested_at=_NOW,
                last_recheck_at=None,
                failure_code=None,
            ),
        ),
    )
    response = gated_client.get(_VERIFY_URL)
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["challenge"]["verification_token"] == "a-token"
