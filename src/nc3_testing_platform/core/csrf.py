"""Origin-check middleware: IDR-010's origin-validation CSRF arm (B3 / US #79).

A state-changing request that carries the session cookie must come from the
deployment's own browser origin (``AUTH_PUBLIC_ORIGIN``). SameSite=Lax on the
cookie already blocks the classic cross-site POST; this check refuses what
Lax cannot see — sibling subdomains, downgraded agents — and costs one header
comparison. An empty setting disables it (non-browser and development use).

Pure ASGI on purpose: the middleware never wraps or buffers the response, so
the SSE progress route streams through untouched. Requests without the
session cookie pass unchecked — API keys are machine-to-machine and carry no
cookie, and the anonymous auth operations have nothing to forge yet.
"""

from http import HTTPStatus

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from nc3_testing_platform.core.errors import ProblemDetail, ProblemResponse
from nc3_testing_platform.core.security import SESSION_COOKIE_NAME
from nc3_testing_platform.core.settings import settings

_STATE_CHANGING = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class OriginCheckMiddleware:
    """Refuse cookie-bearing state changes from a foreign origin."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Pass the request through, or answer 403 problem+json in place."""
        if scope["type"] != "http" or scope["method"] not in _STATE_CHANGING:
            await self.app(scope, receive, send)
            return
        allowed = settings.auth_public_origin.rstrip("/")
        if not allowed:
            await self.app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if f"{SESSION_COOKIE_NAME}=" not in headers.get("cookie", ""):
            await self.app(scope, receive, send)
            return
        origin = headers.get("origin")
        if origin is not None:
            permitted = origin.rstrip("/") == allowed
        else:
            # Older agents omit Origin on same-origin POSTs; Referer is the
            # fallback signal. Neither header present means no browser
            # context to judge — refuse, because the cookie says browser.
            referer = headers.get("referer", "")
            permitted = referer.startswith(f"{allowed}/")
        if permitted:
            await self.app(scope, receive, send)
            return
        problem = ProblemDetail(
            title=HTTPStatus.FORBIDDEN.phrase,
            status=HTTPStatus.FORBIDDEN,
            detail="Cross-origin state-changing request refused (origin check).",
        )
        response = ProblemResponse(
            status_code=HTTPStatus.FORBIDDEN,
            content=problem.model_dump(mode="json", exclude_none=True),
        )
        await response(scope, receive, send)
