"""Unit tests for the auth domain.

Covers the service state machine, the session dependency, the router's
problem mapping and cookies, the CSRF middleware, and the rate-limit gates.
The database layer is mocked at the repository/session boundary; the
live-PostgreSQL counterpart is `tests/test_auth_postgres.py`
(`pytest -m postgres`).
"""

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import fakeredis
import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy.exc import IntegrityError
from uuid6 import uuid7

from nc3_testing_platform.core import api_db, redis_utils, security
from nc3_testing_platform.core.enums import OrganizationRole
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.domains.auth import service
from nc3_testing_platform.domains.auth.schemas import RegistrationSubmission
from nc3_testing_platform.domains.statements.schemas import (
    StatementResponseSubmission,
)
from nc3_testing_platform.main import app

TEST_KEY_HEX = "ab" * 32
NOW = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
PASSWORD = SecretStr("correct horse battery")


@pytest.fixture(autouse=True)
def master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every auth test runs with a synthetic deployment master key."""
    monkeypatch.setattr(settings, "app_encryption_master_key", TEST_KEY_HEX)


def _registration(**overrides: Any) -> RegistrationSubmission:
    """A valid registration body accepting the seeded terms statement."""
    fields: dict[str, Any] = {
        "email": "admin@example.lu",
        "password": PASSWORD,
        "display_name": "Admin",
        "statement_responses": [
            StatementResponseSubmission(
                statement_key="terms_and_conditions", version="2026-01-15"
            )
        ],
    }
    fields.update(overrides)
    return RegistrationSubmission(**fields)


def _terms_statement() -> SimpleNamespace:
    """The seeded acceptance statement, as the repository would return it."""
    return SimpleNamespace(
        id=uuid7(), statement_key="terms_and_conditions", version="2026-01-15"
    )


# --- registration service ---------------------------------------------------


def test_register_provisions_workspace_admin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One transaction: org + admin user + two envelopes + credential + receipt."""
    db = MagicMock()
    monkeypatch.setattr(
        service.repository,
        "active_acceptance_statements",
        lambda db: [_terms_statement()],
    )
    user = service.register(
        db, _registration(), client_ip="203.0.113.7", user_agent="pytest"
    )
    assert user.organization_role == OrganizationRole.ORGANIZATION_ADMIN
    assert user.email == "admin@example.lu"
    assert user.identity_subject == f"local:{user.id}"
    added = [
        obj for call in db.add_all.call_args_list for obj in call.args[0]
    ] + [call.args[0] for call in db.add.call_args_list]
    names = [type(obj).__name__ for obj in added]
    assert names.count("KeyEnvelope") == 2
    assert "Organization" in names
    assert "UserCredential" in names
    assert "StatementResponse" in names
    # Staged: org, user, envelope/credential, receipts (FK insert order).
    assert db.flush.call_count == 4


def test_register_refuses_missing_consent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Registration without every active acceptance statement is refused."""
    monkeypatch.setattr(
        service.repository,
        "active_acceptance_statements",
        lambda db: [_terms_statement()],
    )
    with pytest.raises(service.ConsentError) as excinfo:
        service.register(
            db=MagicMock(),
            submission=_registration(statement_responses=[]),
            client_ip="203.0.113.7",
            user_agent="pytest",
        )
    assert excinfo.value.missing == [("terms_and_conditions", "2026-01-15")]


def test_register_refuses_unknown_statement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An answer naming a statement that is not active is refused, not dropped."""
    monkeypatch.setattr(
        service.repository, "active_acceptance_statements", lambda db: []
    )
    with pytest.raises(service.ConsentError) as excinfo:
        service.register(
            db=MagicMock(),
            submission=_registration(),
            client_ip="203.0.113.7",
            user_agent="pytest",
        )
    assert excinfo.value.unknown == [("terms_and_conditions", "2026-01-15")]


def test_register_maps_duplicate_email(monkeypatch: pytest.MonkeyPatch) -> None:
    """The unique-index refusal surfaces as EmailTakenError."""
    db = MagicMock()
    # The org flush passes; the app_user flush hits the unique index.
    db.flush.side_effect = [
        None,
        IntegrityError(
            "INSERT", {}, Exception('duplicate key "uq_app_user_email_lower"')
        ),
    ]
    monkeypatch.setattr(
        service.repository,
        "active_acceptance_statements",
        lambda db: [_terms_statement()],
    )
    with pytest.raises(service.EmailTakenError):
        service.register(
            db, _registration(), client_ip="203.0.113.7", user_agent="pytest"
        )


# --- login service ----------------------------------------------------------


def _stored_credential(password: str = PASSWORD.get_secret_value()) -> dict[str, Any]:
    """A user KEK, its envelope row, and the encrypted argon2 hash."""
    from nc3_testing_platform.core import crypto

    kek = crypto.generate_key()
    wrapped = crypto.wrap_key(kek, aad=b"key_envelope.wrapped_kek")
    envelope = SimpleNamespace(
        wrapped_kek=wrapped.ciphertext, wrapping_nonce=wrapped.nonce
    )
    hashed = service._hasher.hash(password)
    ciphertext = crypto.encrypt(
        hashed.encode("ascii"), kek, aad=b"user_credential.password"
    )
    return {"envelope": envelope, "ciphertext": ciphertext}


def _login_row(ciphertext: bytes, **overrides: Any) -> SimpleNamespace:
    """A row in the shape auth_login_lookup returns."""
    row = SimpleNamespace(
        user_id=uuid7(),
        organization_id=uuid7(),
        disabled_at=None,
        password_ciphertext=ciphertext,
        failed_login_count=0,
        locked_until=None,
        observed_at=NOW,
    )
    for name, value in overrides.items():
        setattr(row, name, value)
    return row


def _wire_login(
    monkeypatch: pytest.MonkeyPatch,
    row: SimpleNamespace | None,
    stored: dict[str, Any] | None = None,
    credential: SimpleNamespace | None = None,
) -> None:
    """Point the repository at the given fake rows."""
    monkeypatch.setattr(service.repository, "login_lookup", lambda db, email: row)
    if stored is not None:
        monkeypatch.setattr(
            service.repository, "user_envelope", lambda db, uid: stored["envelope"]
        )
    monkeypatch.setattr(
        service.repository, "credential_for", lambda db, uid: credential
    )
    if row is not None:
        monkeypatch.setattr(
            service.repository,
            "user_by_id",
            lambda db, uid: SimpleNamespace(
                id=row.user_id, organization_id=row.organization_id
            ),
        )


def test_login_unknown_email_is_invalid_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No row answers exactly like a wrong password."""
    _wire_login(monkeypatch, row=None)
    with pytest.raises(service.InvalidCredentialsError):
        service.login(MagicMock(), email="ghost@example.lu", password=PASSWORD)


def test_login_disabled_account_is_invalid_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A disabled account is indistinguishable from a wrong password."""
    stored = _stored_credential()
    row = _login_row(stored["ciphertext"], disabled_at=NOW - timedelta(days=1))
    _wire_login(monkeypatch, row, stored)
    with pytest.raises(service.InvalidCredentialsError):
        service.login(MagicMock(), email="admin@example.lu", password=PASSWORD)


def test_login_locked_account_answers_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A standing lockout reports the remaining seconds."""
    stored = _stored_credential()
    row = _login_row(
        stored["ciphertext"], locked_until=NOW + timedelta(seconds=120)
    )
    _wire_login(monkeypatch, row, stored)
    with pytest.raises(service.AccountLockedError) as excinfo:
        service.login(MagicMock(), email="admin@example.lu", password=PASSWORD)
    assert excinfo.value.retry_after_seconds == 121


def test_login_wrong_password_increments_and_commits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mismatch counts one failure and persists it despite the raised error."""
    stored = _stored_credential()
    credential = SimpleNamespace(failed_login_count=0, locked_until=None)
    row = _login_row(stored["ciphertext"])
    _wire_login(monkeypatch, row, stored, credential)
    db = MagicMock()
    with pytest.raises(service.InvalidCredentialsError):
        service.login(
            db, email="admin@example.lu", password=SecretStr("wrong-password-12")
        )
    assert credential.failed_login_count == 1
    db.commit.assert_called_once()


def test_login_lockout_applies_at_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Nth failure locks the account and resets the counter."""
    stored = _stored_credential()
    credential = SimpleNamespace(
        failed_login_count=settings.auth_lockout_threshold - 1, locked_until=None
    )
    row = _login_row(stored["ciphertext"])
    _wire_login(monkeypatch, row, stored, credential)
    with pytest.raises(service.InvalidCredentialsError):
        service.login(
            MagicMock(),
            email="admin@example.lu",
            password=SecretStr("wrong-password-12"),
        )
    assert credential.locked_until == NOW + timedelta(
        seconds=settings.auth_lockout_seconds
    )
    assert credential.failed_login_count == 0


def test_login_success_resets_counter_and_opens_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A correct password resets the lockout state and mints a hashed session."""
    stored = _stored_credential()
    credential = SimpleNamespace(failed_login_count=3, locked_until=None)
    row = _login_row(stored["ciphertext"])
    _wire_login(monkeypatch, row, stored, credential)
    result = service.login(MagicMock(), email="Admin@Example.lu", password=PASSWORD)
    assert credential.failed_login_count == 0
    assert result.session.token_hash == security.hash_session_token(result.token)
    assert result.session.user_id == row.user_id


# --- session dependency (core/security.py) ----------------------------------


def _bootstrap_row(**overrides: Any) -> SimpleNamespace:
    """A row in the shape auth_session_bootstrap returns."""
    row = SimpleNamespace(
        session_id=uuid7(),
        user_id=uuid7(),
        organization_id=uuid7(),
        session_created_at=NOW - timedelta(minutes=5),
        last_seen_at=NOW - timedelta(minutes=1),
        revoked_at=None,
        user_disabled_at=None,
        observed_at=NOW,
    )
    for name, value in overrides.items():
        setattr(row, name, value)
    return row


def _db_returning(row: SimpleNamespace | None) -> MagicMock:
    """A session mock whose bootstrap query yields the given row."""
    db = MagicMock()
    db.execute.return_value.one_or_none.return_value = row
    return db


def test_require_session_missing_cookie_is_401() -> None:
    """No cookie, no session — and nothing to clear."""
    with pytest.raises(HTTPException) as excinfo:
        security.require_session(None, MagicMock())
    assert excinfo.value.status_code == 401
    assert excinfo.value.headers is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"revoked_at": NOW - timedelta(minutes=1)},
        {"user_disabled_at": NOW - timedelta(days=1)},
        {"last_seen_at": NOW - timedelta(minutes=31)},
        {"session_created_at": NOW - timedelta(hours=9)},
    ],
    ids=["revoked", "disabled", "idle-expired", "absolute-expired"],
)
def test_require_session_refuses_and_clears(overrides: dict[str, Any]) -> None:
    """Revocation, disablement, and both timeouts answer 401 + cookie clear."""
    db = _db_returning(_bootstrap_row(**overrides))
    with pytest.raises(HTTPException) as excinfo:
        security.require_session("token", db)
    assert excinfo.value.status_code == 401
    assert "Max-Age=0" in (excinfo.value.headers or {})["Set-Cookie"]


def test_require_session_happy_path_touches_and_returns() -> None:
    """A live session opens the user arm and refreshes the idle anchor."""
    row = _bootstrap_row()
    db = _db_returning(row)
    resolved = security.require_session("token", db)
    assert resolved.user_id == row.user_id
    assert resolved.organization_id == row.organization_id
    statements = [str(call.args[0]) for call in db.execute.call_args_list]
    assert any("UPDATE user_session SET last_seen_at" in s for s in statements)


# --- router: cookies, problem mapping, CSRF, rate limits ---------------------


FAKE_USER: Any = SimpleNamespace(
    id=uuid7(),
    organization_id=uuid7(),
    email="admin@example.lu",
    display_name="Admin",
    organization_role=OrganizationRole.ORGANIZATION_ADMIN,
)
FAKE_SESSION: Any = SimpleNamespace(
    id=uuid7(),
    created_at=NOW,
    last_seen_at=NOW,
)
FAKE_IDENTITY = security.AuthenticatedSession(
    session_id=FAKE_SESSION.id,
    user_id=FAKE_USER.id,
    organization_id=FAKE_USER.organization_id,
)


@pytest.fixture
def client() -> Any:
    """A TestClient whose DB dependency yields a mock; overrides cleaned up."""
    app.dependency_overrides[api_db.auth_session] = lambda: MagicMock()
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def authenticated(client: TestClient) -> TestClient:
    """The client with the session dependency resolved to a fixed identity."""
    app.dependency_overrides[security.require_session] = lambda: FAKE_IDENTITY
    return client


def test_login_sets_host_cookie(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The session cookie carries the full __Host- attribute set."""
    monkeypatch.setattr(
        service,
        "login",
        lambda db, *, email, password: service.LoginResult(
            token="test-token", user=FAKE_USER, session=FAKE_SESSION
        ),
    )
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.lu", "password": "correct horse battery"},
    )
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith('__Host-session="test-token"') or cookie.startswith(
        "__Host-session=test-token"
    )
    lowered = cookie.lower()
    assert "httponly" in lowered
    assert "secure" in lowered
    assert "samesite=lax" in lowered
    assert "path=/" in lowered
    body = response.json()
    assert body["idle_expires_at"] > body["last_seen_at"]
    assert body["absolute_expires_at"] > body["session_created_at"]


def test_login_maps_invalid_credentials_to_401(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The service's single failure answer stays a single 401 problem."""

    def _raise(db: Any, *, email: str, password: Any) -> Any:
        raise service.InvalidCredentialsError

    monkeypatch.setattr(service, "login", _raise)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.lu", "password": "wrong-password-12"},
    )
    assert response.status_code == 401
    assert response.headers["content-type"] == "application/problem+json"


def test_login_maps_lockout_to_429_with_retry_after(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lockout is a quota answer, not a credential answer."""

    def _raise(db: Any, *, email: str, password: Any) -> Any:
        raise service.AccountLockedError(retry_after_seconds=42)

    monkeypatch.setattr(service, "login", _raise)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.lu", "password": "wrong-password-12"},
    )
    assert response.status_code == 429
    assert response.headers["retry-after"] == "42"


def test_register_maps_email_taken_to_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A duplicate email is a 409 problem, matching the contract idiom."""

    def _raise(db: Any, submission: Any, *, client_ip: str, user_agent: str) -> Any:
        raise service.EmailTakenError

    monkeypatch.setattr(service, "register", _raise)
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@example.lu",
            "password": "correct horse battery",
            "statement_responses": [],
        },
    )
    assert response.status_code == 409
    assert response.headers["content-type"] == "application/problem+json"


def test_register_maps_consent_gap_to_422_with_field_errors(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Consent gaps come out as field-level validation errors."""

    def _raise(db: Any, submission: Any, *, client_ip: str, user_agent: str) -> Any:
        raise service.ConsentError(
            missing=[("terms_and_conditions", "2026-01-15")], unknown=[]
        )

    monkeypatch.setattr(service, "register", _raise)
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "admin@example.lu",
            "password": "correct horse battery",
            "statement_responses": [],
        },
    )
    assert response.status_code == 422
    errors = response.json()["errors"]
    assert errors[0]["name"] == "body.statement_responses"
    assert "terms_and_conditions" in errors[0]["reason"]


def test_logout_revokes_and_clears_cookie(
    authenticated: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Logout is a 204 whose Set-Cookie retires the browser's copy."""
    revoked: list[uuid.UUID] = []
    monkeypatch.setattr(
        service, "logout", lambda db, session_id: revoked.append(session_id)
    )
    response = authenticated.post("/api/v1/auth/logout")
    assert response.status_code == 204
    assert "Max-Age=0" in response.headers["set-cookie"]
    assert revoked == [FAKE_IDENTITY.session_id]


def test_session_endpoint_reports_expiries(
    authenticated: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """GET /auth/session projects the user and the expiry horizon."""
    monkeypatch.setattr(
        service,
        "session_snapshot",
        lambda db, *, user_id, session_id: (FAKE_USER, FAKE_SESSION),
    )
    response = authenticated.get("/api/v1/auth/session")
    assert response.status_code == 200
    body = response.json()
    assert body["user_id"] == str(FAKE_USER.id)
    assert body["organization_role"] == "organization_admin"


def test_password_change_rotates_cookie(
    authenticated: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A password change answers 204 and sets a fresh session cookie."""
    monkeypatch.setattr(
        service,
        "change_password",
        lambda db, **kwargs: service.LoginResult(
            token="rotated-token", user=FAKE_USER, session=FAKE_SESSION
        ),
    )
    response = authenticated.post(
        "/api/v1/auth/password",
        json={
            "current_password": "correct horse battery",
            "new_password": "even more correct horse",
        },
    )
    assert response.status_code == 204
    assert "rotated-token" in response.headers["set-cookie"]


def test_password_change_wrong_current_is_403(
    authenticated: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wrong current password refuses without touching anything."""

    def _raise(db: Any, **kwargs: Any) -> Any:
        raise service.WrongCurrentPasswordError

    monkeypatch.setattr(service, "change_password", _raise)
    response = authenticated.post(
        "/api/v1/auth/password",
        json={
            "current_password": "wrong horse battery!",
            "new_password": "even more correct horse",
        },
    )
    assert response.status_code == 403


# --- CSRF middleware ----------------------------------------------------------


def test_csrf_refuses_foreign_origin(
    authenticated: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cookie-bearing POST from another origin dies in the middleware."""
    monkeypatch.setattr(settings, "auth_public_origin", "https://testing.nc3.lu")
    response = authenticated.post(
        "/api/v1/auth/logout",
        headers={
            "Cookie": "__Host-session=whatever",
            "Origin": "https://evil.example",
        },
    )
    assert response.status_code == 403
    assert response.headers["content-type"] == "application/problem+json"


def test_csrf_allows_own_origin(
    authenticated: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The deployment's own origin passes through to the handler."""
    monkeypatch.setattr(settings, "auth_public_origin", "https://testing.nc3.lu")
    monkeypatch.setattr(service, "logout", lambda db, session_id: None)
    response = authenticated.post(
        "/api/v1/auth/logout",
        headers={
            "Cookie": "__Host-session=whatever",
            "Origin": "https://testing.nc3.lu",
        },
    )
    assert response.status_code == 204


def test_csrf_ignores_cookieless_requests(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Machine-to-machine calls carry no cookie and are never origin-checked."""
    monkeypatch.setattr(settings, "auth_public_origin", "https://testing.nc3.lu")

    def _raise(db: Any, *, email: str, password: Any) -> Any:
        raise service.InvalidCredentialsError

    monkeypatch.setattr(service, "login", _raise)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.lu", "password": "wrong-password-12"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 401  # reached the handler, not the middleware


# --- rate limits ---------------------------------------------------------------


def test_login_rate_limit_answers_429(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Past the per-IP window the login answers 429 with quota headers."""
    monkeypatch.setattr(
        redis_utils, "_client", fakeredis.FakeAsyncRedis(decode_responses=True)
    )
    monkeypatch.setattr(settings, "auth_login_rate_limit", 2)

    def _raise(db: Any, *, email: str, password: Any) -> Any:
        raise service.InvalidCredentialsError

    monkeypatch.setattr(service, "login", _raise)
    body = {"email": "admin@example.lu", "password": "wrong-password-12"}
    for _ in range(2):
        assert client.post("/api/v1/auth/login", json=body).status_code == 401
    response = client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 429
    assert "retry-after" in response.headers
    assert response.headers["ratelimit"].startswith("limit=2")


def test_rate_limit_fails_open_without_redis(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unreachable Redis never blocks login; the DB lockout still stands."""

    async def _broken(*args: Any, **kwargs: Any) -> Any:
        raise ConnectionError("redis down")

    monkeypatch.setattr(redis_utils, "consume", _broken)

    def _raise(db: Any, *, email: str, password: Any) -> Any:
        raise service.InvalidCredentialsError

    monkeypatch.setattr(service, "login", _raise)
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@example.lu", "password": "wrong-password-12"},
    )
    assert response.status_code == 401  # processed, not 429/500
