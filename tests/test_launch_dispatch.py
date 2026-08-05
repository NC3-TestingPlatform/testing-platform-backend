"""Tests the media type that selects the `POST /scans` request schema."""

import pytest
from fastapi.testclient import TestClient

from nc3_testing_platform.main import app

JSON_SPELLINGS = [
    "application/json",
    "application/JSON",
    "Application/Json",
    "application/json; charset=utf-8",
    "APPLICATION/JSON; charset=UTF-8",
]


@pytest.fixture(scope="module")
def client() -> TestClient:
    """The live mock application."""
    return TestClient(app)


@pytest.mark.parametrize("content_type", JSON_SPELLINGS)
def test_json_media_type_is_case_insensitive(
    client: TestClient, content_type: str
) -> None:
    """Every spelling selects the domain-launch schema, so the empty body fails validation rather than the media type."""
    response = client.post("/api/v1/scans", content=b"{}", headers={"content-type": content_type})

    assert response.status_code == 422


def test_unknown_media_type_is_rejected(client: TestClient) -> None:
    """A media type that selects no launch schema answers 415."""
    response = client.post(
        "/api/v1/scans", content=b"<xml/>", headers={"content-type": "application/xml"}
    )

    assert response.status_code == 415
