"""Live-PostgreSQL integration for the auth vertical (B3 / US #79).

Runs the real thing end to end: the FastAPI handlers over a real `nc3_auth`
engine against a database carrying the migrations — registration provisioning,
login and lockout, cookie sessions, and the SECURITY DEFINER lookups. Also
asserts the decision-13 privilege boundary: `nc3_app` (the role the scan
workers hold) has no reach into the credential surface, and the definer
functions have the hardened shape the revision promises.

Marked `postgres` (deselected by default); CI runs it inside the Migration
round trip job after `alembic upgrade head` and the role-credential
bootstrap. Role URLs derive from `DATABASE_URL` with the dev-default
passwords unless `APP_DATABASE_URL` / `AUTH_DATABASE_URL` say otherwise.
"""

import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session, sessionmaker
from uuid6 import uuid7

from nc3_testing_platform.core import api_db, rls
from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.main import app

pytestmark = pytest.mark.postgres

TEST_KEY_HEX = "cd" * 32
PASSWORD = "correct horse battery"
_OWNER_URL = os.getenv("DATABASE_URL")


def _role_url(role: str, env_name: str) -> str:
    """The role's connection URL: explicit env, or derived dev defaults."""
    explicit = os.getenv(env_name)
    if explicit:
        return explicit
    if not _OWNER_URL:
        pytest.skip("DATABASE_URL not set")
    derived = sa.engine.make_url(_OWNER_URL).set(username=role, password=role)
    return derived.render_as_string(hide_password=False)


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """The app over a real nc3_auth engine, with a synthetic master key.

    The base URL is https so the client's jar accepts and replays the
    Secure session cookie. The lazy engine global is reset around the test
    so the monkeypatched URL is the one that builds it.
    """
    if not _OWNER_URL:
        pytest.skip("DATABASE_URL not set")
    monkeypatch.setattr(settings, "app_encryption_master_key", TEST_KEY_HEX)
    monkeypatch.setattr(
        settings, "auth_database_url", _role_url("nc3_auth", "AUTH_DATABASE_URL")
    )
    # Plain assignment, not monkeypatch: monkeypatch's teardown runs after
    # this fixture's post-yield body and would restore (possibly disposed)
    # prior engines over the explicit reset below.
    stale = api_db._auth_engine
    if stale is not None:
        stale.dispose()
    api_db._auth_engine = None
    api_db._auth_factory = None
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client
    engine = api_db._auth_engine
    if engine is not None:
        engine.dispose()
    api_db._auth_engine = None
    api_db._auth_factory = None


def _registration_body(email: str) -> dict[str, Any]:
    """A valid registration payload accepting the seeded terms statement."""
    return {
        "email": email,
        "password": PASSWORD,
        "display_name": "Integration",
        "statement_responses": [
            {"statement_key": "terms_and_conditions", "version": "2026-01-15"}
        ],
    }


def _fresh_email() -> str:
    """A collision-free address; live databases keep rows between runs."""
    return f"user-{uuid7().hex[:12]}@example.lu"


def _register(client: TestClient, email: str) -> dict[str, Any]:
    """Register and return the provisioning result."""
    response = client.post("/api/v1/auth/register", json=_registration_body(email))
    assert response.status_code == 201, response.text
    return response.json()


def test_register_login_session_logout_flow(client: TestClient) -> None:
    """The whole vertical: provision, authenticate, introspect, revoke."""
    email = _fresh_email()
    registered = _register(client, email)
    assert registered["organization_role"] == "organization_admin"
    assert registered["email"] == email

    # Wrong password: uniform 401, no cookie.
    refused = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": "wrong horse battery"},
    )
    assert refused.status_code == 401
    assert "set-cookie" not in refused.headers

    # Right password: cookie lands in the jar and authenticates the session.
    logged_in = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert logged_in.status_code == 200, logged_in.text
    assert logged_in.headers["set-cookie"].startswith("__Host-session=")

    session = client.get("/api/v1/auth/session")
    assert session.status_code == 200, session.text
    assert session.json()["user_id"] == registered["user_id"]

    assert client.post("/api/v1/auth/logout").status_code == 204
    assert client.get("/api/v1/auth/session").status_code == 401


def test_duplicate_email_answers_409(client: TestClient) -> None:
    """The case-insensitive unique index refuses a second registration."""
    email = _fresh_email()
    _register(client, email)
    response = client.post(
        "/api/v1/auth/register", json=_registration_body(email.upper())
    )
    assert response.status_code == 409


def test_registration_without_consent_answers_422(client: TestClient) -> None:
    """The seeded terms statement must be accepted."""
    body = _registration_body(_fresh_email())
    body["statement_responses"] = []
    response = client.post("/api/v1/auth/register", json=body)
    assert response.status_code == 422
    assert "terms_and_conditions" in response.text


def test_lockout_after_repeated_failures(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The durable per-account lockout stands even for the right password."""
    monkeypatch.setattr(settings, "auth_lockout_threshold", 3)
    email = _fresh_email()
    _register(client, email)
    for _ in range(3):
        assert (
            client.post(
                "/api/v1/auth/login",
                json={"email": email, "password": "wrong horse battery"},
            ).status_code
            == 401
        )
    locked = client.post(
        "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
    )
    assert locked.status_code == 429
    assert int(locked.headers["retry-after"]) > 0


def test_password_change_rotates_sessions(client: TestClient) -> None:
    """Old cookies die with the change; the rotated one keeps working."""
    email = _fresh_email()
    _register(client, email)
    assert (
        client.post(
            "/api/v1/auth/login", json={"email": email, "password": PASSWORD}
        ).status_code
        == 200
    )
    old_cookie = client.cookies["__Host-session"]
    changed = client.post(
        "/api/v1/auth/password",
        json={
            "current_password": PASSWORD,
            "new_password": "an even better horse",
        },
    )
    assert changed.status_code == 204, changed.text
    # The rotated cookie authenticates; the pre-change one does not. The
    # stale check clears the jar and sends the old token as a raw header —
    # httpx deprecated per-request cookies.
    assert client.get("/api/v1/auth/session").status_code == 200
    client.cookies.clear()
    stale = client.get(
        "/api/v1/auth/session",
        headers={"Cookie": f"__Host-session={old_cookie}"},
    )
    assert stale.status_code == 401


# --- decision-13 boundary: nc3_app never reaches the credential surface -----


@pytest.fixture
def app_role_session() -> Iterator[Session]:
    """A session as nc3_app — the role the scan workers hold."""
    engine = sa.create_engine(_role_url("nc3_app", "APP_DATABASE_URL"))
    factory = sessionmaker(bind=engine)
    session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def test_nc3_app_has_no_privilege_on_auth_tables(
    app_role_session: Session,
) -> None:
    """SELECT on the credential tables is refused at the grant layer."""
    for table in ("user_credential", "user_session"):
        with pytest.raises(ProgrammingError) as excinfo:
            app_role_session.execute(sa.text(f"SELECT count(*) FROM {table}"))
        assert "permission denied" in str(excinfo.value)
        app_role_session.rollback()


def test_nc3_app_cannot_execute_the_definer_lookups(
    app_role_session: Session,
) -> None:
    """A compromised worker gets no account-enumeration oracle."""
    with pytest.raises(ProgrammingError) as excinfo:
        app_role_session.execute(
            sa.text("SELECT * FROM public.auth_login_lookup('a@b.lu')")
        )
    assert "permission denied" in str(excinfo.value)
    app_role_session.rollback()


def test_cross_user_isolation_on_credential_rows(client: TestClient) -> None:
    """Under user A's RLS arm, user B's credential rows vanish."""
    email_a, email_b = _fresh_email(), _fresh_email()
    user_a = uuid.UUID(_register(client, email_a)["user_id"])
    user_b = uuid.UUID(_register(client, email_b)["user_id"])
    engine = sa.create_engine(_role_url("nc3_auth", "AUTH_DATABASE_URL"))
    factory = sessionmaker(bind=engine)
    session = factory()
    try:
        rls.set_user_context(session, user_a)
        rows = session.execute(
            sa.text(
                "SELECT count(*) FROM user_credential WHERE user_id = :other"
            ),
            {"other": user_b},
        ).scalar_one()
        assert rows == 0
        own = session.execute(
            sa.text("SELECT count(*) FROM user_credential WHERE user_id = :own"),
            {"own": user_a},
        ).scalar_one()
        assert own == 1
    finally:
        session.close()
        engine.dispose()


def test_definer_functions_have_the_hardened_shape() -> None:
    """Owner, pinned search_path, and no PUBLIC or nc3_app EXECUTE."""
    if not _OWNER_URL:
        pytest.skip("DATABASE_URL not set")
    engine = sa.create_engine(_OWNER_URL)
    try:
        with engine.connect() as connection:
            for signature in (
                "public.auth_login_lookup(text)",
                "public.auth_session_bootstrap(bytea)",
            ):
                owner, is_definer, config = connection.execute(
                    sa.text(
                        "SELECT pg_get_userbyid(proowner), prosecdef, proconfig "
                        "FROM pg_proc WHERE oid = CAST(:sig AS regprocedure)"
                    ),
                    {"sig": signature},
                ).one()
                assert owner == "nc3_auth_definer", signature
                assert is_definer, signature
                assert any(
                    entry.startswith("search_path=") for entry in config or []
                ), signature
                for role in ("nc3_app", "app_platform"):
                    granted = connection.execute(
                        sa.text(
                            "SELECT has_function_privilege(:role, "
                            "CAST(:sig AS regprocedure), 'EXECUTE')"
                        ),
                        {"role": role, "sig": signature},
                    ).scalar_one()
                    assert not granted, f"{role} can execute {signature}"
    finally:
        engine.dispose()
