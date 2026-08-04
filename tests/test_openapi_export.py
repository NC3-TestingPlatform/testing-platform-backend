"""Tests the OpenAPI document generation."""

from pathlib import Path
from typing import Any

import pytest
from openapi_spec_validator import validate

from nc3_testing_platform.main import app
from nc3_testing_platform.tools.export_openapi import DEST, render

DECLARED_COMPONENTS = (
    "AssetScanLaunch",
    "GuestScanLaunch",
    "FileScanLaunch",
    "ScanTaskEvent",
    "ScanJobEvent",
    "ScanHeartbeatEvent",
    "ScanEndEvent",
)

ANONYMOUS_OPERATIONS = {
    ("/api/v1/scans", "post"),
    ("/api/v1/scans/{scan_id}", "get"),
    ("/api/v1/scans/{scan_id}/results", "get"),
    ("/api/v1/scans/{scan_id}/events", "get"),
    ("/api/v1/statements", "get"),
    ("/api/v1/invitations/{token}", "get"),
    ("/api/v1/feeds/{token}", "get"),
}

_METHODS = ("get", "post", "put", "patch", "delete")


@pytest.fixture(scope="module")
def spec() -> dict[str, Any]:
    """Returns the freshly generated document."""
    return app.openapi()


def test_spec_is_valid_openapi(spec: dict[str, Any]) -> None:
    """The generated document passes OpenAPI schema validation."""
    validate(spec)


def test_spec_declares_openapi_3_1(spec: dict[str, Any]) -> None:
    """The document declares OpenAPI 3.1."""
    assert spec["openapi"].startswith("3.1")


def test_committed_spec_matches_generated(spec: dict[str, Any]) -> None:
    """`api/openapi.json` is byte-identical to what `export-openapi` writes."""
    assert Path(DEST).read_text(encoding="utf-8") == render(spec), (
        "api/openapi.json is stale — run 'make export-openapi'"
    )


def test_declared_components_are_published(spec: dict[str, Any]) -> None:
    """Every schema registered in `main` reaches the contract."""
    published = spec["components"]["schemas"].keys()
    assert set(DECLARED_COMPONENTS) <= set(published)


def _accepts_anonymous(operation: dict[str, Any]) -> bool:
    """Reports whether an operation may be called without credentials.

    An absent `security` key and a requirement list containing an empty object both
    mean anonymous; the second is OpenAPI's form for optional authentication.
    """
    security = operation.get("security")
    if security is None:
        return True
    return any(not requirement for requirement in security)


def test_anonymous_operations_are_exactly_the_documented_set(
    spec: dict[str, Any],
) -> None:
    """Only the seven operations named in api-design §1 accept an anonymous caller."""
    anonymous = {
        (path, method)
        for path, item in spec["paths"].items()
        for method, operation in item.items()
        if method in _METHODS and _accepts_anonymous(operation)
        if path.startswith("/api/v1")
    }
    assert anonymous == ANONYMOUS_OPERATIONS


def test_error_responses_use_problem_details(spec: dict[str, Any]) -> None:
    """Error responses carry `application/problem+json`, per RFC 9457."""
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            if method not in _METHODS:
                continue
            for status, response in operation["responses"].items():
                if not status.startswith(("4", "5")):
                    continue
                content = response.get("content")
                assert content, f"{method.upper()} {path} {status} declares no body"
                assert "application/problem+json" in content, (
                    f"{method.upper()} {path} {status} is not problem+json"
                )
