"""Tests the favicon route and the self-hosted, branded documentation pages.

The point of registering `/docs` and `/redoc` by hand is the platform icon; the
cost is owning the behaviour FastAPI's built-ins provided, so these tests pin
both — the branding, and the `root_path` prefixing and OAuth2 redirect page a
handwritten registration is free to forget.
"""

import pytest
from fastapi.testclient import TestClient

from nc3_testing_platform.core.docs import (
    DOCS_URL,
    FAVICON_MEDIA_TYPE,
    FAVICON_PATH,
    FAVICON_URL,
    REDOC_URL,
    SWAGGER_OAUTH2_REDIRECT_URL,
)
from nc3_testing_platform.main import app

# The default FastAPI ships in the documentation HTML. Nothing the platform
# serves may reach out to it: it is a third-party request from an authenticated
# origin, and an outage there would break the page's icon.
_FASTAPI_HOST = "fastapi.tiangolo.com"

# The `root_path` a reverse proxy that mounts the API under a sub-path sets.
_MOUNT_PREFIX = "/testing-platform"

_ICO_MAGIC = b"\x00\x00\x01\x00"


@pytest.fixture(scope="module")
def client() -> TestClient:
    """The platform app, served from the origin root."""
    return TestClient(app)


@pytest.fixture(scope="module")
def mounted_client() -> TestClient:
    """The platform app as a proxy mounting it under a sub-path presents it."""
    return TestClient(app, root_path=_MOUNT_PREFIX)


def test_favicon_is_the_committed_icon(client: TestClient) -> None:
    """The route serves the icon shipped in the package, declared as an ICO."""
    response = client.get(FAVICON_URL)

    assert response.status_code == 200
    assert response.headers["content-type"] == FAVICON_MEDIA_TYPE
    assert response.content == FAVICON_PATH.read_bytes()


def test_committed_icon_is_a_real_ico() -> None:
    """The asset is an ICO container, not a PNG renamed.

    A renamed PNG is served happily and then ignored by the browsers that read
    the declared type rather than sniffing.
    """
    assert FAVICON_PATH.read_bytes().startswith(_ICO_MAGIC)


def test_favicon_is_cacheable(client: TestClient) -> None:
    """The icon carries a cache lifetime, so it is not re-fetched per page view."""
    response = client.get(FAVICON_URL)

    assert "max-age=" in response.headers["cache-control"]


@pytest.mark.parametrize("url", [DOCS_URL, REDOC_URL])
def test_documentation_page_uses_the_platform_favicon(
    client: TestClient, url: str
) -> None:
    """Both pages point at the local icon and at no external one."""
    response = client.get(url)

    assert response.status_code == 200
    assert f'href="{FAVICON_URL}"' in response.text
    assert _FASTAPI_HOST not in response.text


@pytest.mark.parametrize("url", [DOCS_URL, REDOC_URL])
def test_documentation_page_survives_being_mounted_under_a_prefix(
    mounted_client: TestClient, url: str
) -> None:
    """Behind a proxy, both the icon and the document are addressed through `root_path`.

    Unprefixed, the page would ask the proxy's own root for them and render
    without an icon and without a specification.
    """
    response = mounted_client.get(url)

    assert response.status_code == 200
    assert f'href="{_MOUNT_PREFIX}{FAVICON_URL}"' in response.text
    assert f"{_MOUNT_PREFIX}{app.openapi_url}" in response.text


def test_swagger_oauth2_redirect_page_is_registered(client: TestClient) -> None:
    """The page Swagger UI's "Authorize" flow returns through still answers.

    FastAPI registers it only alongside its own `/docs`; switching that off
    drops it unless it is registered by hand, and the failure surfaces only
    mid-login.
    """
    response = client.get(SWAGGER_OAUTH2_REDIRECT_URL)

    assert response.status_code == 200
    assert "oauth2" in response.text


def test_swagger_ui_declares_the_redirect_page_it_registers(
    client: TestClient,
) -> None:
    """The URL the page hands to Swagger UI is the one that is served."""
    response = client.get(DOCS_URL)

    assert f"'{SWAGGER_OAUTH2_REDIRECT_URL}'" in response.text


def test_documentation_routes_stay_out_of_the_contract() -> None:
    """No documentation route reaches the OpenAPI document."""
    paths = app.openapi()["paths"]

    for url in (FAVICON_URL, DOCS_URL, REDOC_URL, SWAGGER_OAUTH2_REDIRECT_URL):
        assert url not in paths
