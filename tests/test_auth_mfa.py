"""Unit tests for the MFA slice of the auth domain (B4 / US #80).

Same boundaries as `test_auth_flow.py`: the service runs against
monkeypatched repository functions with real crypto under a synthetic master
key; the router runs behind dependency overrides; TOTP time steps are
injected, never slept on. The live-PostgreSQL counterpart is
`tests/test_auth_postgres.py` (`pytest -m postgres`).
"""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError
from uuid6 import uuid7

from nc3_testing_platform.core import api_db, crypto, redis_utils, security
from nc3_testing_platform.core.enums import OrganizationRole
from nc3_testing_platform.core.errors import (
    PROBLEM_TYPE_PREFIX,
    ProblemException,
)
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.domains.auth import service, totp
from nc3_testing_platform.domains.auth.schemas import MfaVerifySubmission
from nc3_testing_platform.main import app

TEST_KEY_HEX = "cd" * 32
NOW = datetime(2026, 8, 19, 12, 0, tzinfo=UTC)
PASSWORD = SecretStr("correct horse battery")
USER_ID = uuid7()
SESSION_ID = uuid7()


@pytest.fixture(autouse=True)
def master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every MFA test runs with a synthetic deployment master key."""
    monkeypatch.setattr(settings, "app_encryption_master_key", TEST_KEY_HEX)


@pytest.fixture(autouse=True)
def no_rate_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep every test off any real Redis: the gate allows by default."""

    async def _allow(
        key: str, *, limit: int, window_seconds: int, client: Any = None
    ) -> Any:
        return redis_utils.RateLimitDecision(
            allowed=True, limit=limit, remaining=limit, reset_seconds=window_seconds
        )

    monkeypatch.setattr(redis_utils, "consume", _allow)


# --- fakes and wiring ---------------------------------------------------------


def _wire_kek(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """A user KEK, its envelope, and the encrypted credential, repository-wired."""
    kek = crypto.generate_key()
    wrapped = crypto.wrap_key(kek, aad=b"key_envelope.wrapped_kek")
    envelope = SimpleNamespace(
        wrapped_kek=wrapped.ciphertext, wrapping_nonce=wrapped.nonce
    )
    hashed = service._hasher.hash(PASSWORD.get_secret_value())
    credential = SimpleNamespace(
        password_ciphertext=crypto.encrypt(
            hashed.encode("ascii"), kek, aad=b"user_credential.password"
        )
    )
    monkeypatch.setattr(service.repository, "user_envelope", lambda db, uid: envelope)
    monkeypatch.setattr(
        service.repository, "credential_for", lambda db, uid: credential
    )
    return kek


def _mfa_row(
    kek: bytes, *, confirmed: bool = True, **overrides: Any
) -> tuple[SimpleNamespace, bytes]:
    """A user_mfa row fake plus its plaintext seed."""
    secret = totp.generate_secret()
    row = SimpleNamespace(
        user_id=USER_ID,
        totp_secret_ciphertext=crypto.encrypt(
            secret, kek, aad=b"user_mfa.totp_secret"
        ),
        confirmed_at=NOW - timedelta(days=1) if confirmed else None,
        last_used_step=None,
        failed_count=0,
        lockout_count=0,
        locked_until=None,
    )
    for name, value in overrides.items():
        setattr(row, name, value)
    return row, secret


def _code(secret: bytes, offset: int = 0) -> tuple[str, int]:
    """The valid TOTP code at NOW shifted by ``offset`` steps."""
    step = totp.step_at(NOW.timestamp()) + offset
    return totp.code_at(secret, step), step


def _db() -> MagicMock:
    """A session mock whose clock query answers NOW."""
    db = MagicMock()
    db.execute.return_value.scalar_one.return_value = NOW
    return db


def _wire_user(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    user = SimpleNamespace(
        id=USER_ID,
        organization_id=uuid7(),
        email="admin@example.lu",
        display_name="Admin",
        organization_role=OrganizationRole.ORGANIZATION_ADMIN,
    )
    monkeypatch.setattr(service.repository, "user_by_id", lambda db, uid: user)
    return user


# --- totp primitives ----------------------------------------------------------


def test_totp_window_accepts_one_step_of_skew() -> None:
    """±1 step verifies; ±2 does not."""
    secret = totp.generate_secret()
    code, step = _code(secret)
    assert totp.matching_step(secret, code, at_step=step) == step
    assert totp.matching_step(secret, code, at_step=step + 1) == step
    assert totp.matching_step(secret, code, at_step=step - 1) == step
    assert totp.matching_step(secret, code, at_step=step + 2) is None
    assert totp.matching_step(secret, code, at_step=step - 2) is None


def test_recovery_codes_format_and_normalization() -> None:
    """Ten formatted codes; hashing forgives separators and case."""
    codes = totp.generate_recovery_codes()
    assert len(codes) == totp.RECOVERY_CODE_COUNT
    assert all(len(code) == 19 and code.count("-") == 3 for code in codes)
    assert totp.hash_recovery_code(codes[0]) == totp.hash_recovery_code(
        codes[0].upper().replace("-", " ")
    )


# --- enrollment ---------------------------------------------------------------


def test_enroll_requires_the_current_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stolen session alone cannot plant a factor."""
    _wire_kek(monkeypatch)
    with pytest.raises(service.WrongCurrentPasswordError):
        service.enroll_mfa(
            _db(), user_id=USER_ID, password=SecretStr("wrong horse battery!")
        )


def test_enroll_refuses_a_confirmed_factor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Re-enrollment over a confirmed factor answers a conflict."""
    kek = _wire_kek(monkeypatch)
    row, _ = _mfa_row(kek, confirmed=True)
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: row)
    with pytest.raises(service.MfaAlreadyEnrolledError):
        service.enroll_mfa(_db(), user_id=USER_ID, password=PASSWORD)


def test_enroll_returns_provisioning_material(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fresh enrollment stores an encrypted seed and returns the URI once."""
    _wire_kek(monkeypatch)
    _wire_user(monkeypatch)
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: None)
    db = _db()
    enrollment = service.enroll_mfa(db, user_id=USER_ID, password=PASSWORD)
    added = [call.args[0] for call in db.add.call_args_list]
    assert [type(obj).__name__ for obj in added] == ["UserMfa"]
    assert added[0].totp_secret_ciphertext is not None
    assert enrollment.otpauth_uri.startswith("otpauth://totp/")
    assert "admin%40example.lu" in enrollment.otpauth_uri


def test_enroll_restart_replaces_the_unconfirmed_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Restarting an unconfirmed enrollment mints a new seed and resets state."""
    kek = _wire_kek(monkeypatch)
    _wire_user(monkeypatch)
    row, _ = _mfa_row(kek, confirmed=False, last_used_step=7, failed_count=3)
    old_ciphertext = row.totp_secret_ciphertext
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: row)
    service.enroll_mfa(_db(), user_id=USER_ID, password=PASSWORD)
    assert row.totp_secret_ciphertext != old_ciphertext
    assert row.last_used_step is None
    assert row.failed_count == 0


# --- confirmation -------------------------------------------------------------


def test_confirm_wrong_code_counts_and_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure counter persists even though the request fails."""
    kek = _wire_kek(monkeypatch)
    row, _ = _mfa_row(kek, confirmed=False)
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: row)
    wrong_code, _ = _code(totp.generate_secret())
    db = _db()
    with pytest.raises(service.InvalidMfaCodeError):
        service.confirm_mfa(
            db, user_id=USER_ID, session_id=SESSION_ID, code=wrong_code
        )
    assert row.failed_count == 1
    db.commit.assert_called_once()


def test_confirm_activates_stamps_and_mints_codes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Success assures the calling session, revokes the rest, mints the set."""
    kek = _wire_kek(monkeypatch)
    row, secret = _mfa_row(kek, confirmed=False)
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: row)
    stamped: list[uuid.UUID] = []
    kept: list[uuid.UUID] = []
    inserted: list[bytes] = []
    monkeypatch.setattr(
        service.repository,
        "stamp_session_assurance",
        lambda db, sid: stamped.append(sid) or True,
    )
    monkeypatch.setattr(
        service.repository,
        "revoke_other_sessions",
        lambda db, uid, *, keep_session_id: kept.append(keep_session_id),
    )
    monkeypatch.setattr(
        service.repository, "burn_recovery_codes", lambda db, uid: None
    )
    monkeypatch.setattr(
        service.repository,
        "insert_recovery_codes",
        lambda db, uid, hashes: inserted.extend(hashes),
    )
    code, step = _code(secret)
    codes = service.confirm_mfa(
        _db(), user_id=USER_ID, session_id=SESSION_ID, code=code
    )
    assert len(codes) == totp.RECOVERY_CODE_COUNT
    assert row.confirmed_at == NOW
    assert row.last_used_step == step
    assert stamped == [SESSION_ID]
    assert kept == [SESSION_ID]
    assert inserted == [totp.hash_recovery_code(c) for c in codes]


def test_confirm_refuses_when_the_session_was_revoked_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A miss on the guarded stamp UPDATE fails closed, not silently."""
    kek = _wire_kek(monkeypatch)
    row, secret = _mfa_row(kek, confirmed=False)
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: row)
    monkeypatch.setattr(
        service.repository, "stamp_session_assurance", lambda db, sid: False
    )
    code, _ = _code(secret)
    with pytest.raises(service.SessionRevokedError):
        service.confirm_mfa(
            _db(), user_id=USER_ID, session_id=SESSION_ID, code=code
        )


# --- verification -------------------------------------------------------------


def _wire_confirmed(
    monkeypatch: pytest.MonkeyPatch, **overrides: Any
) -> tuple[SimpleNamespace, bytes]:
    kek = _wire_kek(monkeypatch)
    row, secret = _mfa_row(kek, confirmed=True, **overrides)
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: row)
    return row, secret


def test_verify_accepts_one_step_of_skew_and_refreshes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A previous-step code passes; an assured session refreshes in place."""
    row, secret = _wire_confirmed(monkeypatch)
    stamped: list[uuid.UUID] = []
    monkeypatch.setattr(
        service.repository,
        "stamp_session_assurance",
        lambda db, sid: stamped.append(sid) or True,
    )
    code, step = _code(secret, offset=-1)
    result = service.verify_mfa(
        _db(),
        user_id=USER_ID,
        session_id=SESSION_ID,
        pending=False,
        totp_code=code,
    )
    assert result is None
    assert stamped == [SESSION_ID]
    assert row.last_used_step == step


def test_verify_stepup_refuses_when_the_session_was_revoked_concurrently(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A miss on the guarded stamp UPDATE fails closed, not silently."""
    row, secret = _wire_confirmed(monkeypatch)
    monkeypatch.setattr(
        service.repository, "stamp_session_assurance", lambda db, sid: False
    )
    code, _ = _code(secret)
    with pytest.raises(service.SessionRevokedError):
        service.verify_mfa(
            _db(),
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending=False,
            totp_code=code,
        )


def test_verify_refuses_a_replayed_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid code at an already-spent step is one indistinguishable refusal."""
    row, secret = _wire_confirmed(monkeypatch)
    code, step = _code(secret)
    row.last_used_step = step
    db = _db()
    with pytest.raises(service.InvalidMfaCodeError):
        service.verify_mfa(
            db,
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending=False,
            totp_code=code,
        )
    assert row.failed_count == 1


def test_verify_pending_rotates_the_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The pending→assured transition mints a fresh, assured session row."""
    row, secret = _wire_confirmed(monkeypatch)
    _wire_user(monkeypatch)
    revoked: list[uuid.UUID] = []
    monkeypatch.setattr(
        service.repository, "revoke_session", lambda db, sid: revoked.append(sid)
    )
    code, _ = _code(secret)
    result = service.verify_mfa(
        _db(),
        user_id=USER_ID,
        session_id=SESSION_ID,
        pending=True,
        totp_code=code,
    )
    assert result is not None
    assert revoked == [SESSION_ID]
    assert result.session.mfa_verified_at == NOW
    assert result.token


def test_verify_lockout_escalates_and_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The lockout doubles per consecutive lockout and stops at the cap."""
    row, secret = _wire_confirmed(monkeypatch)
    wrong_code, _ = _code(totp.generate_secret())

    def _fail() -> None:
        with pytest.raises(service.InvalidMfaCodeError):
            service.verify_mfa(
                _db(),
                user_id=USER_ID,
                session_id=SESSION_ID,
                pending=False,
                totp_code=wrong_code,
            )

    row.failed_count = settings.auth_mfa_failed_threshold - 1
    _fail()
    assert row.lockout_count == 1
    assert row.locked_until == NOW + timedelta(
        seconds=settings.auth_mfa_lockout_base_seconds
    )

    row.locked_until = None
    row.failed_count = settings.auth_mfa_failed_threshold - 1
    _fail()
    assert row.lockout_count == 2
    assert row.locked_until == NOW + timedelta(
        seconds=2 * settings.auth_mfa_lockout_base_seconds
    )

    row.locked_until = None
    row.failed_count = settings.auth_mfa_failed_threshold - 1
    row.lockout_count = 40
    _fail()
    assert row.locked_until == NOW + timedelta(
        seconds=settings.auth_mfa_lockout_cap_seconds
    )


def test_verify_while_locked_answers_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A standing lockout refuses even a valid code, with the horizon."""
    row, secret = _wire_confirmed(
        monkeypatch, locked_until=NOW + timedelta(seconds=60)
    )
    code, _ = _code(secret)
    with pytest.raises(service.MfaLockedError) as excinfo:
        service.verify_mfa(
            _db(),
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending=False,
            totp_code=code,
        )
    assert excinfo.value.retry_after_seconds == 61


def test_verify_recovery_code_spends_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The repository's conditional UPDATE outcome decides; a miss counts."""
    row, _ = _wire_confirmed(monkeypatch)
    monkeypatch.setattr(
        service.repository, "stamp_session_assurance", lambda db, sid: True
    )
    monkeypatch.setattr(
        service.repository, "unused_recovery_code_count", lambda db, uid: 9
    )
    outcomes = iter([True, False])
    monkeypatch.setattr(
        service.repository,
        "consume_recovery_code",
        lambda db, uid, code_hash: next(outcomes),
    )
    recovery = SecretStr("aaaa-bbbb-cccc-dddd")
    assert (
        service.verify_mfa(
            _db(),
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending=False,
            recovery_code=recovery,
        )
        is None
    )
    with pytest.raises(service.InvalidMfaCodeError):
        service.verify_mfa(
            _db(),
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending=False,
            recovery_code=recovery,
        )
    assert row.failed_count == 1


def test_verify_unenrolled_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """No confirmed factor, nothing to verify against."""
    monkeypatch.setattr(service.repository, "mfa_for", lambda db, uid: None)
    with pytest.raises(service.MfaNotEnrolledError):
        service.verify_mfa(
            _db(),
            user_id=USER_ID,
            session_id=SESSION_ID,
            pending=False,
            totp_code="000000",
        )


# --- disable and regeneration ---------------------------------------------------


def test_disable_soft_revokes_and_rotates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The row survives with nulls; the codes are superseded; sessions rotate."""
    row, secret = _wire_confirmed(monkeypatch)
    _wire_user(monkeypatch)
    burned: list[uuid.UUID] = []
    monkeypatch.setattr(
        service.repository, "burn_recovery_codes", lambda db, uid: burned.append(uid)
    )
    monkeypatch.setattr(
        service.repository,
        "revoke_other_sessions",
        lambda db, uid, *, keep_session_id: None,
    )
    monkeypatch.setattr(service.repository, "revoke_session", lambda db, sid: None)
    code, _ = _code(secret)
    result = service.disable_mfa(
        _db(),
        user_id=USER_ID,
        current_session_id=SESSION_ID,
        password=PASSWORD,
        totp_code=code,
    )
    assert row.totp_secret_ciphertext is None
    assert row.confirmed_at is None
    assert burned == [USER_ID]
    assert result.session.mfa_verified_at is None


def test_regenerate_requires_password_and_replaces_the_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The wrong password burns nothing; success supersedes the old set."""
    _wire_confirmed(monkeypatch)
    burned: list[uuid.UUID] = []
    inserted: list[bytes] = []
    monkeypatch.setattr(
        service.repository, "burn_recovery_codes", lambda db, uid: burned.append(uid)
    )
    monkeypatch.setattr(
        service.repository,
        "insert_recovery_codes",
        lambda db, uid, hashes: inserted.extend(hashes),
    )
    with pytest.raises(service.WrongCurrentPasswordError):
        service.regenerate_recovery_codes(
            _db(), user_id=USER_ID, password=SecretStr("wrong horse battery!")
        )
    assert burned == []
    codes = service.regenerate_recovery_codes(
        _db(), user_id=USER_ID, password=PASSWORD
    )
    assert burned == [USER_ID]
    assert inserted == [totp.hash_recovery_code(c) for c in codes]


# --- the assurance gate and pending refusal (core/security.py) ----------------


def _identity(**overrides: Any) -> security.AuthenticatedSession:
    fields: dict[str, Any] = {
        "session_id": SESSION_ID,
        "user_id": USER_ID,
        "organization_id": uuid7(),
        "mfa_enrolled": True,
        "mfa_verified_at": NOW - timedelta(seconds=60),
        "observed_at": NOW,
    }
    fields.update(overrides)
    return security.AuthenticatedSession(**fields)


def test_assurance_gate_requires_enrollment() -> None:
    """An unenrolled user is hard-refused at MFA-mandatory operations."""
    with pytest.raises(ProblemException) as excinfo:
        security.require_current_mfa_assurance(_identity(mfa_enrolled=False))
    assert excinfo.value.status_code == 403
    assert (
        excinfo.value.problem_type
        == f"{PROBLEM_TYPE_PREFIX}mfa-enrollment-required"
    )


def test_assurance_gate_refuses_stale_assurance() -> None:
    """Assurance older than the max age demands a step-up."""
    stale = NOW - timedelta(
        seconds=settings.auth_mfa_assurance_max_age_seconds + 1
    )
    with pytest.raises(ProblemException) as excinfo:
        security.require_current_mfa_assurance(_identity(mfa_verified_at=stale))
    assert excinfo.value.status_code == 403
    assert excinfo.value.problem_type == f"{PROBLEM_TYPE_PREFIX}mfa-stepup-required"


def test_assurance_gate_passes_fresh_assurance() -> None:
    """Fresh assurance passes the identity through unchanged."""
    identity = _identity()
    assert security.require_current_mfa_assurance(identity) is identity


def _session_db(state: SimpleNamespace) -> MagicMock:
    """A db mock: the bootstrap row first, then the in-policy MFA state."""
    row = SimpleNamespace(
        session_id=SESSION_ID,
        user_id=USER_ID,
        organization_id=uuid7(),
        session_created_at=NOW,
        last_seen_at=NOW,
        revoked_at=None,
        user_disabled_at=None,
        observed_at=NOW,
    )
    db = MagicMock()
    db.execute.return_value.one_or_none.return_value = row
    db.execute.return_value.one.return_value = state
    return db


def test_require_session_refuses_a_pending_session_and_keeps_the_cookie() -> None:
    """Enrolled + unverified answers `mfa-required` without clearing anything."""
    db = _session_db(SimpleNamespace(mfa_verified_at=None, mfa_enrolled=True))
    with pytest.raises(ProblemException) as excinfo:
        security.require_session("token", db)
    assert excinfo.value.status_code == 401
    assert excinfo.value.problem_type == f"{PROBLEM_TYPE_PREFIX}mfa-required"
    assert excinfo.value.headers is None


def test_pending_dependency_accepts_a_pending_session() -> None:
    """The pending variant resolves the same session require_session refuses."""
    db = _session_db(SimpleNamespace(mfa_verified_at=None, mfa_enrolled=True))
    resolved = security.require_pending_or_current_session("token", db)
    assert resolved.mfa_enrolled is True
    assert resolved.mfa_verified_at is None


def test_pending_session_acceptance_is_pinned() -> None:
    """Exactly three operations accept a pending session — no silent spread."""

    def _uses(dependant: Any, fn: Any) -> bool:
        if dependant.call is fn:
            return True
        return any(_uses(dep, fn) for dep in dependant.dependencies)

    def _api_routes(router: Any) -> Any:
        # Router inclusion is deferred: `app.routes` holds _IncludedRouter
        # wrappers, so the APIRoutes (with router-local paths) are reached
        # through `original_router`.
        for route in router.routes:
            if isinstance(route, APIRoute):
                yield route
            elif hasattr(route, "original_router"):
                yield from _api_routes(route.original_router)

    accepting = {
        (route.path, method)
        for route in _api_routes(app.router)
        for method in route.methods
        # Starlette registers an implicit HEAD beside every GET.
        if method != "HEAD"
        and _uses(route.dependant, security.require_pending_or_current_session)
    }
    assert accepting == {
        ("/auth/mfa/verify", "POST"),
        ("/auth/logout", "POST"),
        ("/auth/session", "GET"),
    }


# --- router --------------------------------------------------------------------


FAKE_USER: Any = SimpleNamespace(
    id=USER_ID,
    organization_id=uuid7(),
    email="admin@example.lu",
    display_name="Admin",
    organization_role=OrganizationRole.ORGANIZATION_ADMIN,
)


def _fake_session(assured: bool) -> Any:
    return SimpleNamespace(
        id=SESSION_ID,
        created_at=NOW,
        last_seen_at=NOW,
        mfa_verified_at=NOW if assured else None,
    )


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Any:
    """A TestClient with a mock DB; MFA status defaults to enrolled."""
    monkeypatch.setattr(service, "mfa_status", lambda db, user_id: (True, 10))
    app.dependency_overrides[api_db.auth_session] = lambda: MagicMock()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _authenticate(pending: bool) -> None:
    identity = _identity(mfa_verified_at=None if pending else NOW)
    app.dependency_overrides[security.require_session] = lambda: identity
    app.dependency_overrides[security.require_pending_or_current_session] = (
        lambda: identity
    )


def test_verify_submission_requires_exactly_one_code() -> None:
    """Neither and both code forms are schema-refused."""
    with pytest.raises(ValidationError):
        MfaVerifySubmission()
    with pytest.raises(ValidationError):
        MfaVerifySubmission(
            totp_code="123456", recovery_code=SecretStr("aaaa-bbbb-cccc-dddd")
        )


def test_login_pending_withholds_the_profile(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A correct password against an enrolled account reveals nothing new."""
    monkeypatch.setattr(
        service,
        "login",
        lambda db, *, email, password: service.LoginResult(
            token="pending-token", user=FAKE_USER, session=_fake_session(False)
        ),
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.lu", "password": "correct horse battery"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["mfa_required"] is True
    assert body["display_name"] is None
    assert body["organization_role"] is None
    assert body["recovery_codes_remaining"] == 10


def test_verify_endpoint_rotates_the_cookie_when_pending(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Completing login sets the fresh cookie and reveals the profile."""
    _authenticate(pending=True)
    monkeypatch.setattr(
        service,
        "verify_mfa",
        lambda db, **kwargs: service.LoginResult(
            token="assured-token", user=FAKE_USER, session=_fake_session(True)
        ),
    )
    response = client.post(
        "/api/v1/auth/mfa/verify", json={"totp_code": "123456"}
    )
    assert response.status_code == 200
    assert "assured-token" in response.headers["set-cookie"]
    body = response.json()
    assert body["mfa_required"] is False
    assert body["organization_role"] == "organization_admin"


def test_verify_endpoint_maps_lockout_to_429(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The MFA lockout surfaces as 429 with Retry-After."""
    _authenticate(pending=True)

    def _raise(db: Any, **kwargs: Any) -> Any:
        raise service.MfaLockedError(42)

    monkeypatch.setattr(service, "verify_mfa", _raise)
    response = client.post(
        "/api/v1/auth/mfa/verify", json={"totp_code": "123456"}
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "42"


def test_verify_endpoint_maps_concurrent_revoke_to_401_and_clears_cookie(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A step-up race with a revoke answers 401, same as any dead session."""
    _authenticate(pending=False)

    def _raise(db: Any, **kwargs: Any) -> Any:
        raise service.SessionRevokedError

    monkeypatch.setattr(service, "verify_mfa", _raise)
    response = client.post(
        "/api/v1/auth/mfa/verify", json={"totp_code": "123456"}
    )
    assert response.status_code == 401
    assert "Max-Age=0" in response.headers["Set-Cookie"]


def test_enroll_endpoint_answers_no_store_and_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Provisioning material is never cacheable; a confirmed factor conflicts."""
    _authenticate(pending=False)
    monkeypatch.setattr(
        service,
        "enroll_mfa",
        lambda db, **kwargs: service.MfaEnrollment(
            secret_base32="A" * 32, otpauth_uri="otpauth://totp/x"
        ),
    )
    response = client.post(
        "/api/v1/auth/mfa/enroll", json={"password": "correct horse battery"}
    )
    assert response.status_code == 201
    assert response.headers["Cache-Control"] == "no-store"

    def _conflict(db: Any, **kwargs: Any) -> Any:
        raise service.MfaAlreadyEnrolledError

    monkeypatch.setattr(service, "enroll_mfa", _conflict)
    response = client.post(
        "/api/v1/auth/mfa/enroll", json={"password": "correct horse battery"}
    )
    assert response.status_code == 409


def test_disable_endpoint_rotates_the_cookie(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disable answers 204 with a rotated session cookie."""
    _authenticate(pending=False)
    monkeypatch.setattr(
        service,
        "disable_mfa",
        lambda db, **kwargs: service.LoginResult(
            token="rotated-token", user=FAKE_USER, session=_fake_session(False)
        ),
    )
    response = client.post(
        "/api/v1/auth/mfa/disable",
        json={"password": "correct horse battery", "totp_code": "123456"},
    )
    assert response.status_code == 204
    assert "rotated-token" in response.headers["set-cookie"]


def test_recovery_codes_endpoint_requires_fresh_assurance(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stale assurance answers the step-up problem type."""
    stale = _identity(
        mfa_verified_at=NOW
        - timedelta(seconds=settings.auth_mfa_assurance_max_age_seconds + 1)
    )
    app.dependency_overrides[security.require_session] = lambda: stale
    response = client.post(
        "/api/v1/auth/mfa/recovery-codes",
        json={"password": "correct horse battery"},
    )
    assert response.status_code == 403
    assert response.json()["type"] == f"{PROBLEM_TYPE_PREFIX}mfa-stepup-required"
