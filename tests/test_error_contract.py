"""Tests that every error leaves the application as an RFC 9457 problem detail."""

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from nc3_testing_platform.core.errors import (
    PROBLEM_MEDIA_TYPE,
    PROBLEM_TYPE_PREFIX,
    ProblemException,
    problem_type_uri,
    register_exception_handlers,
)
from nc3_testing_platform.main import app as platform_app

_LEAKED_TEXT = "connection string nobody outside may read"


@pytest.fixture(scope="module")
def client() -> TestClient:
    """An app carrying only the error handlers, one failing route, and one 404."""
    app = FastAPI()
    register_exception_handlers(app)

    @app.get("/unhandled")
    async def unhandled() -> None:
        """Fails the way a real handler fails."""
        raise RuntimeError(_LEAKED_TEXT)

    @app.get("/missing")
    async def missing() -> None:
        """Answers the way a declared 404 answers."""
        raise HTTPException(status_code=404, detail="No such thing.")

    @app.get("/unbuilt")
    async def unbuilt() -> None:
        """Fails the way a reached implementation seam fails."""
        raise NotImplementedError

    @app.get("/typed")
    async def typed() -> None:
        """Refuses the way a machine-branchable refusal refuses."""
        raise ProblemException(
            status_code=401,
            detail="The session lacks its second factor.",
            problem_type=problem_type_uri("mfa-required"),
        )

    return TestClient(app, raise_server_exceptions=False)


def test_unhandled_exception_answers_problem_json(client: TestClient) -> None:
    """An exception no handler expected still satisfies the declared error contract."""
    response = client.get("/unhandled")

    assert response.status_code == 500
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE
    assert response.json() == {
        "type": "about:blank",
        "title": "Internal Server Error",
        "status": 500,
        "instance": "http://testserver/unhandled",
    }


def test_unhandled_exception_leaks_nothing(client: TestClient) -> None:
    """The exception text stays in the server log and never reaches the client."""
    assert _LEAKED_TEXT not in client.get("/unhandled").text


def test_http_exception_answers_problem_json(client: TestClient) -> None:
    """A raised HTTPException carries its own detail through the same shape."""
    response = client.get("/missing")

    assert response.status_code == 404
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE
    assert response.json()["detail"] == "No such thing."


def test_unimplemented_seam_answers_501_problem_json(client: TestClient) -> None:
    """A reached `NotImplementedError` seam answers `501` as a problem detail."""
    response = client.get("/unbuilt")

    assert response.status_code == 501
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE
    assert response.json()["status"] == 501


def test_problem_exception_carries_its_type(client: TestClient) -> None:
    """A `ProblemException` surfaces its `type` URN; everything else is unchanged."""
    response = client.get("/typed")

    assert response.status_code == 401
    assert response.headers["content-type"] == PROBLEM_MEDIA_TYPE
    body = response.json()
    assert body["type"] == f"{PROBLEM_TYPE_PREFIX}mfa-required"
    assert body["detail"] == "The session lacks its second factor."


def test_plain_http_exception_keeps_the_default_type(client: TestClient) -> None:
    """A plain `HTTPException` still answers the `about:blank` default."""
    assert client.get("/missing").json()["type"] == "about:blank"


def test_gates_declare_without_enforcing() -> None:
    """A credential-less call to a gated operation is served by the live mock.

    Gates publish security requirements and enforce nothing; this inverts to a `401` assertion when credential verification is wired.
    """
    client = TestClient(platform_app)
    response = client.post(
        "/api/v1/api-keys", json={"name": "ci", "scope": "read_only"}
    )

    assert response.status_code == 201
