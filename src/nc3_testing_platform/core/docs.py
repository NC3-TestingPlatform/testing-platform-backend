"""The browser-facing pages: the platform favicon and the API documentation.

FastAPI's built-in `/docs` and `/redoc` routes write
`https://fastapi.tiangolo.com/img/favicon.png` into their HTML and the
constructor exposes no way to change it, so `main` switches the built-ins off
and this module registers them again with the platform's own icon, served from
this package rather than fetched from a third party.

Registering the pages by hand means owning what the built-ins did for free:
prefixing every URL with `root_path`, so both pages keep working when a proxy
mounts the API under a sub-path, and the Swagger OAuth2 redirect page the
"Authorize" flow hands control back to.

Both pages still load the Swagger UI and ReDoc bundles from cdn.jsdelivr.net —
FastAPI's default. Vendoring those is a separate change with its own trade-off.

None of these routes reach the OpenAPI document (`include_in_schema=False`):
they are the documentation surface, not part of the API contract.
"""

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.openapi.docs import (
    get_redoc_html,
    get_swagger_ui_html,
    get_swagger_ui_oauth2_redirect_html,
)
from fastapi.responses import FileResponse, HTMLResponse

# `parents[1]` is the package root: this module sits one level down, in `core`.
FAVICON_PATH = Path(__file__).resolve().parents[1] / "static" / "favicon.ico"
FAVICON_URL = "/favicon.ico"
FAVICON_MEDIA_TYPE = "image/vnd.microsoft.icon"

DOCS_URL = "/docs"
REDOC_URL = "/redoc"
# FastAPI's own default path, kept so a Swagger OAuth2 client registered
# against the built-in route needs no new redirect URI.
SWAGGER_OAUTH2_REDIRECT_URL = "/docs/oauth2-redirect"

# The icon changes only with a rebrand and a stale tab icon harms nobody, so a
# day of caching spares the app one request per documentation page view.
_FAVICON_CACHE_CONTROL = "public, max-age=86400"


def register_docs(app: FastAPI) -> None:
    """Registers the favicon and the branded documentation pages on `app`.

    The app must be constructed with `docs_url=None` and `redoc_url=None`:
    FastAPI registers its own routes from the constructor, so they would
    otherwise be matched first and these would never be reached.

    Args:
        app: The application to register the routes on.

    Raises:
        ValueError: If the app publishes no OpenAPI document, leaving the
            documentation pages nothing to render.
    """
    openapi_url = app.openapi_url
    if not openapi_url:
        raise ValueError("The documentation pages need an openapi_url to render.")

    @app.get(FAVICON_URL, include_in_schema=False)
    async def favicon() -> FileResponse:
        """The platform icon, for the documentation pages and for browsers that ask unprompted."""
        return FileResponse(
            FAVICON_PATH,
            media_type=FAVICON_MEDIA_TYPE,
            headers={"Cache-Control": _FAVICON_CACHE_CONTROL},
        )

    @app.get(DOCS_URL, include_in_schema=False)
    async def swagger_ui(request: Request) -> HTMLResponse:
        """Swagger UI, branded, at FastAPI's default path."""
        prefix = request.scope.get("root_path", "").rstrip("/")
        return get_swagger_ui_html(
            openapi_url=f"{prefix}{openapi_url}",
            title=f"{app.title} - Swagger UI",
            oauth2_redirect_url=f"{prefix}{SWAGGER_OAUTH2_REDIRECT_URL}",
            swagger_favicon_url=f"{prefix}{FAVICON_URL}",
        )

    @app.get(SWAGGER_OAUTH2_REDIRECT_URL, include_in_schema=False)
    async def swagger_ui_oauth2_redirect() -> HTMLResponse:
        """Hands an authorization-code response from the provider back to Swagger UI."""
        return get_swagger_ui_oauth2_redirect_html()

    @app.get(REDOC_URL, include_in_schema=False)
    async def redoc(request: Request) -> HTMLResponse:
        """ReDoc, branded, at FastAPI's default path."""
        prefix = request.scope.get("root_path", "").rstrip("/")
        return get_redoc_html(
            openapi_url=f"{prefix}{openapi_url}",
            title=f"{app.title} - ReDoc",
            redoc_favicon_url=f"{prefix}{FAVICON_URL}",
        )
