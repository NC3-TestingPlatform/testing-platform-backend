"""Smoke tests every operation of the live mock against the committed contract.

Cases are handwritten; coverage tests prove they span the OpenAPI inventory, every declared request media type, and every `oneOf` request variant.
A `422` fails any case: it means the request never reached the handler.
Gates enforce nothing in this phase, so cases send no credentials — except the authenticated launch, whose `Authorization` header selects the request variant.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from defusedxml import ElementTree
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

from nc3_testing_platform.domains.api_keys.router import _KEY_ID
from nc3_testing_platform.domains.assets.examples import _FEED_ID
from nc3_testing_platform.domains.notifications.router import _NOTIFICATION_ID
from nc3_testing_platform.domains.org.router import _INVITATION_ID
from nc3_testing_platform.domains.scans.examples import (
    _FINDING_HSTS,
    ASSET_ID,
    JOB_ID,
    USER_ID,
)
from nc3_testing_platform.domains.schedules.router import _SCHEDULE_ID
from nc3_testing_platform.main import app

# An in-process TestClient buffers each response completely before yielding it,
# so a stream that never terminates hangs before any byte reaches the test.
pytestmark = pytest.mark.timeout(30)

SPEC: dict[str, Any] = json.loads(Path("api/openapi.json").read_text(encoding="utf-8"))

_METHODS = ("get", "post", "put", "patch", "delete")

_CLAIM_TOKEN = "9xK2mQ7pL4vR8nT1jH5gF3dS6aW0zYbUcElOnAiKrXs"

# Size sanity for the buffered stream body; the module timeout bounds a hang.
_MAX_STREAM_BYTES = 65536

PATH_VALUES: dict[str, str] = {
    "scan_id": str(JOB_ID),
    "asset_id": str(ASSET_ID),
    "feed_id": str(_FEED_ID),
    "schedule_id": str(_SCHEDULE_ID),
    "finding_id": str(_FINDING_HSTS),
    "notification_id": str(_NOTIFICATION_ID),
    "user_id": str(USER_ID),
    "invitation_id": str(_INVITATION_ID),
    "key_id": str(_KEY_ID),
}


@dataclass(frozen=True)
class Case:
    """One request against one operation variant.

    Attributes:
        method: Lowercase HTTP method, spelled as in the OpenAPI document.
        path: Templated path, spelled as in the OpenAPI document.
        variant: Display label distinguishing multiple cases for one operation.
        json_body: JSON payload; present exactly when the case sends `application/json`.
        files: Multipart parts; present exactly when the case sends `multipart/form-data`.
        path_values: Per-case overrides of `PATH_VALUES`.
        headers: Request headers; the authenticated launch selects its variant here.
    """

    method: str
    path: str
    variant: str = "default"
    json_body: dict[str, Any] | list[Any] | None = None
    files: dict[str, tuple[str, bytes, str]] | None = None
    path_values: dict[str, str] | None = None
    headers: dict[str, str] | None = None


CASES: tuple[Case, ...] = (
    Case(
        "post",
        "/api/v1/scans",
        "authenticated-json",
        json_body={"asset_id": str(ASSET_ID), "modules": ["email", "web"]},
        headers={"Authorization": "Bearer sample-token"},
    ),
    Case(
        "post",
        "/api/v1/scans",
        "guest-json",
        json_body={"target": "example.lu", "modules": ["email"]},
    ),
    Case(
        "post",
        "/api/v1/scans",
        "multipart",
        files={"file": ("sample.pdf", b"%PDF-1.4 sample", "application/pdf")},
    ),
    Case("get", "/api/v1/scans"),
    Case("get", "/api/v1/scans/{scan_id}"),
    Case("delete", "/api/v1/scans/{scan_id}"),
    Case("get", "/api/v1/scans/{scan_id}/results"),
    Case("get", "/api/v1/scans/{scan_id}/events"),
    Case("post", "/api/v1/scans/{scan_id}/cancel"),
    Case(
        "post",
        "/api/v1/scans/{scan_id}/claim",
        json_body={"claim_token": _CLAIM_TOKEN},
    ),
    Case("post", "/api/v1/scans/{scan_id}/retention/extend"),
    Case("get", "/api/v1/assets"),
    Case("post", "/api/v1/assets", json_body={"value": "example.lu"}),
    Case("get", "/api/v1/assets/{asset_id}"),
    Case(
        "patch",
        "/api/v1/assets/{asset_id}",
        json_body={"regression_alerts_enabled": True},
    ),
    Case("delete", "/api/v1/assets/{asset_id}"),
    Case("get", "/api/v1/assets/{asset_id}/scans"),
    Case("get", "/api/v1/assets/{asset_id}/verification"),
    Case(
        "post",
        "/api/v1/assets/{asset_id}/verification",
        json_body={"requested_scope": "zone"},
    ),
    Case("post", "/api/v1/assets/{asset_id}/verification/checks"),
    Case("post", "/api/v1/assets/{asset_id}/verification/token"),
    Case("get", "/api/v1/assets/{asset_id}/feeds"),
    Case("post", "/api/v1/assets/{asset_id}/feeds", json_body={"format": "atom"}),
    Case("post", "/api/v1/assets/{asset_id}/feeds/{feed_id}/revoke"),
    Case(
        "get",
        "/api/v1/feeds/{token}",
        path_values={"token": "fd_9xK2mQ7pL4vR8nT1"},
    ),
    Case("get", "/api/v1/schedules"),
    Case(
        "post",
        "/api/v1/schedules",
        json_body={
            "asset_id": str(ASSET_ID),
            "modules": ["email"],
            "recurrence_rule": "FREQ=WEEKLY;BYDAY=MO",
            "timezone": "Europe/Luxembourg",
        },
    ),
    Case("get", "/api/v1/schedules/{schedule_id}"),
    Case("patch", "/api/v1/schedules/{schedule_id}", json_body={"enabled": False}),
    Case("delete", "/api/v1/schedules/{schedule_id}"),
    Case("get", "/api/v1/findings"),
    Case("get", "/api/v1/findings/{finding_id}"),
    Case(
        "post",
        "/api/v1/reports",
        json_body={
            "tier": "executive",
            "format": "pdf",
            "source_scan_job_id": str(JOB_ID),
        },
    ),
    Case("get", "/api/v1/reports"),
    Case("get", "/api/v1/notifications"),
    Case("post", "/api/v1/notifications/read-all"),
    Case("post", "/api/v1/notifications/{notification_id}/read"),
    Case("get", "/api/v1/notifications/webhook"),
    Case(
        "put",
        "/api/v1/notifications/webhook",
        json_body={
            "endpoint_url": "https://siem.example.lu/hook",
            "signing_secret": "0123456789abcdef0123456789abcdef",
        },
    ),
    Case("delete", "/api/v1/notifications/webhook"),
    Case("delete", "/api/v1/notifications/{notification_id}"),
    Case("get", "/api/v1/account"),
    Case("patch", "/api/v1/account", json_body={"email_notifications_enabled": True}),
    Case("get", "/api/v1/org/members"),
    Case(
        "patch",
        "/api/v1/org/members/{user_id}",
        json_body={"organization_role": "member"},
    ),
    Case("post", "/api/v1/org/members/{user_id}/disable"),
    Case("post", "/api/v1/org/members/{user_id}/enable"),
    Case("get", "/api/v1/org/invitations"),
    Case(
        "post",
        "/api/v1/org/invitations",
        json_body={"email": "new.member@example.lu"},
    ),
    Case("delete", "/api/v1/org/invitations/{invitation_id}"),
    Case(
        "get",
        "/api/v1/invitations/{token}",
        path_values={"token": "inv_5gF3dS6aW0zYbUcE"},
    ),
    Case(
        "post",
        "/api/v1/invitations/{token}/acceptance",
        path_values={"token": "inv_5gF3dS6aW0zYbUcE"},
    ),
    Case("get", "/api/v1/api-keys"),
    Case("post", "/api/v1/api-keys", json_body={"name": "ci", "scope": "read_only"}),
    Case(
        "post",
        "/api/v1/api-keys/{key_id}/revoke",
        json_body={"revocation_reason": "Rotated"},
    ),
    Case("get", "/api/v1/statements"),
    Case(
        "post",
        "/api/v1/statement-responses",
        json_body={"statement_key": "terms_and_conditions", "version": "1.0.0"},
    ),
    Case("get", "/api/v1/statement-responses"),
    Case("get", "/api/v1/admin/audit-events"),
    Case("get", "/healthz"),
    Case("get", "/readyz"),
)

_REGISTRY = Registry().with_resource(
    "urn:spec", Resource(contents=SPEC, specification=DRAFT202012)
)


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Provides one client for the whole surface."""
    return TestClient(app)


def _pointer_segment(raw: str) -> str:
    """Escapes one JSON-pointer segment per RFC 6901."""
    return raw.replace("~", "~0").replace("/", "~1")


def _operation(case: Case) -> dict[str, Any]:
    """Returns the OpenAPI operation object of a case."""
    return SPEC["paths"][case.path][case.method]


def _declared_success(case: Case) -> int:
    """Returns the lowest 2xx status a case's operation declares."""
    codes = sorted(
        int(code)
        for code in _operation(case)["responses"]
        if code.startswith("2")
    )
    return codes[0]


def _url(case: Case) -> str:
    """Substitutes fixture values into a case's templated path."""
    url = case.path
    values = {**PATH_VALUES, **(case.path_values or {})}
    for name, value in values.items():
        url = url.replace("{" + name + "}", value)
    return url


def _success_content(case: Case) -> dict[str, Any]:
    """Returns the declared content map of a case's success response."""
    return _operation(case)["responses"][str(_declared_success(case))].get(
        "content", {}
    )


def _validate_against_declared_schema(case: Case, body: Any) -> None:
    """Validates a JSON body against the schema its operation declares."""
    schema = _success_content(case).get("application/json", {}).get("schema")
    if schema is None:
        return
    pointer = (
        f"urn:spec#/paths/{_pointer_segment(case.path)}"
        f"/{case.method}/responses/{_declared_success(case)}"
        "/content/application~1json/schema"
    )
    Draft202012Validator({"$ref": pointer}, registry=_REGISTRY).validate(body)


def _request_media_type(case: Case) -> str | None:
    """Returns the request media type a case sends, or None for a bodiless case."""
    if case.files is not None:
        return "multipart/form-data"
    if case.json_body is not None:
        return "application/json"
    return None


def test_cases_cover_every_operation() -> None:
    """The handwritten case set spans the complete OpenAPI inventory."""
    inventory = {
        (method, path)
        for path, item in SPEC["paths"].items()
        for method in item
        if method in _METHODS
    }
    covered = {(case.method, case.path) for case in CASES}
    assert covered == inventory


def test_cases_cover_every_request_media_type() -> None:
    """Every declared request media type of every operation has a case sending it."""
    for path, item in SPEC["paths"].items():
        for method, operation in item.items():
            if method not in _METHODS:
                continue
            declared = set(operation.get("requestBody", {}).get("content", {}))
            sent = {
                _request_media_type(case)
                for case in CASES
                if (case.method, case.path) == (method, path)
            }
            missing = declared - sent
            assert not missing, f"{method.upper()} {path} has no case sending {missing}"


def test_cases_cover_every_json_request_variant() -> None:
    """A `oneOf` JSON request body has at least one case per branch."""
    for path, item in SPEC["paths"].items():
        for method, operation in item.items():
            if method not in _METHODS:
                continue
            schema = (
                operation.get("requestBody", {})
                .get("content", {})
                .get("application/json", {})
                .get("schema", {})
            )
            branches = len(schema.get("oneOf", []))
            if branches < 2:
                continue
            json_bodies = [
                case.json_body
                for case in CASES
                if (case.method, case.path) == (method, path)
                and case.json_body is not None
            ]
            for index in range(branches):
                pointer = (
                    f"urn:spec#/paths/{_pointer_segment(path)}/{method}"
                    "/requestBody/content/application~1json/schema"
                    f"/oneOf/{index}"
                )
                validator = Draft202012Validator(
                    {"$ref": pointer}, registry=_REGISTRY
                )
                assert any(validator.is_valid(body) for body in json_bodies), (
                    f"{method.upper()} {path}: no JSON case matches "
                    f"`oneOf` branch {index}"
                )


@pytest.mark.parametrize(
    "case", CASES, ids=lambda case: f"{case.method.upper()} {case.path} [{case.variant}]"
)
def test_operation_answers_its_declared_success(case: Case, client: TestClient) -> None:
    """Each operation serves its declared success status with a conforming body."""
    if "text/event-stream" in _success_content(case):
        _assert_stream_ends(client, _url(case))
        return

    response = client.request(
        case.method.upper(),
        _url(case),
        json=case.json_body,
        files=case.files,
        headers=case.headers,
    )

    assert response.status_code != 422, f"request never reached the handler: {response.text}"
    assert response.status_code == _declared_success(case), response.text[:500]

    if response.status_code == 204:
        assert response.content == b""
        return

    content_type = response.headers.get("content-type", "").split(";")[0]
    declared = _success_content(case)
    if declared:
        assert content_type in declared, (
            f"served {content_type!r}, declared {sorted(declared)}"
        )
    if content_type == "application/json":
        _validate_against_declared_schema(case, response.json())
    elif content_type.endswith("xml"):
        ElementTree.fromstring(response.text)
    else:
        assert response.content


def _assert_stream_ends(client: TestClient, url: str) -> None:
    """Reads the SSE body to exhaustion and requires the terminal `end` event."""
    response = client.get(url)

    assert response.status_code == 200
    assert response.headers["content-type"].split(";")[0] == "text/event-stream"
    assert response.headers["cache-control"] == "no-store"
    assert len(response.content) <= _MAX_STREAM_BYTES
    frames = [frame for frame in response.text.split("\n\n") if frame.strip()]
    assert frames[-1].splitlines()[0] == "event: end", (
        "stream did not terminate with the `end` event"
    )
