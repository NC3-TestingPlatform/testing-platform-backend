"""Tests that every error leaves the application as an RFC 9457 problem detail."""

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from nc3_testing_platform.core.errors import (
    PROBLEM_MEDIA_TYPE,
    register_exception_handlers,
)

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
