"""Body validation for the launch operation.

`POST /scans` accepts three request schemas on one path, selected by media type
and — inside JSON — by the caller's access state. FastAPI derives one body model
per operation from type hints, so it cannot make that choice; this dependency does
it and hands the handler an already-validated object.

Failures raise `RequestValidationError`, FastAPI's own validation exception, so
they travel through the handler registered in `app.core.errors` and come out as
`application/problem+json` with the same field-level `errors` array as every other
endpoint. Raising `HTTPException` here would produce a second, differently-shaped
validation error for one operation.
"""

from typing import Annotated, Any

from fastapi import Depends, HTTPException, Query, Request, status
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ValidationError

from nc3_testing_platform.core.security import ApiKeyAuth, OidcAuth
from nc3_testing_platform.domains.scans.schemas import (
    CLAIM_TOKEN_PATTERN,
    AssetScanLaunch,
    FileScanLaunch,
    GuestScanLaunch,
)

JSON_MEDIA_TYPE = "application/json"
MULTIPART_MEDIA_TYPE = "multipart/form-data"

# Read access to a guest scan, for a caller who has no account yet.
#
# A query parameter rather than a header because one of the three operations it
# covers is an SSE stream, and `EventSource` cannot set headers. Using the same
# transport on all three keeps one rule for the client.
#
# Reading does not spend the token. Only the claim does, because after the scan is
# attributed to an organization the account is the credential and the token has
# nothing left to authorize.
ScanAccessToken = Annotated[
    str | None,
    Query(
        alias="claim_token",
        pattern=CLAIM_TOKEN_PATTERN,
        description=(
            "One-time token returned by an unauthenticated launch. Required to read "
            "a guest scan that has not been claimed; ignored when the caller is "
            "authenticated and owns the scan. Reading does not consume it."
        ),
    ),
]

# `FileScanLaunch` is documentation-only — its `file` field is the OpenAPI 3.1
# encoding of a binary part, not a runtime string — so a multipart launch is
# validated against the form rather than through the model.
ScanLaunch = AssetScanLaunch | GuestScanLaunch | FileScanLaunch


class ResolvedLaunch(BaseModel):
    """A validated launch request plus the access state that selected it.

    Both are needed downstream and neither implies the other: a file launch can be
    anonymous, in which case it is a guest job that carries a claim token, so
    `isinstance(body, FileScanLaunch)` alone cannot tell an owned scan from a
    claimable one.
    """

    body: ScanLaunch
    authenticated: bool


def _invalid(loc: tuple[str, ...], message: str) -> RequestValidationError:
    """One validation error in the shape FastAPI's handler expects."""
    return RequestValidationError(
        [{"type": "value_error", "loc": loc, "msg": message, "input": None}]
    )


def _from_pydantic(exc: ValidationError) -> RequestValidationError:
    """Re-raise a model validation failure as a request validation failure.

    Pydantic reports locations relative to the model; the contract reports them
    relative to the request, so each one is prefixed with `body`.
    """
    return RequestValidationError(
        [{**error, "loc": ("body", *error["loc"])} for error in exc.errors()]
    )


def _validate(model: type[BaseModel], payload: dict[str, Any]) -> Any:
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise _from_pydantic(exc) from exc


async def resolve_launch_body(
    request: Request,
    oidc: OidcAuth,
    key: ApiKeyAuth,
) -> ResolvedLaunch:
    """Select the request schema, validate against it, and return the result.

    The media type selects a domain or file launch, while the caller’s access state
    selects the authenticated or guest domain variant. If the caller sends a field
    from the wrong access state, validation identifies the correct field.
    """
    media_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    authenticated = bool(oidc or key)

    if media_type == MULTIPART_MEDIA_TYPE:
        form = await request.form()
        if "file" not in form:
            raise _invalid(("body", "file"), "A file part is required.")
        return ResolvedLaunch(
            body=FileScanLaunch(file=str(form["file"])), authenticated=authenticated
        )

    if media_type != JSON_MEDIA_TYPE:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail=(
                f"Unsupported media type {media_type!r}. Use {JSON_MEDIA_TYPE} for "
                f"a domain scan or {MULTIPART_MEDIA_TYPE} for a file scan."
            ),
        )

    try:
        payload = await request.json()
    except ValueError as exc:
        raise _invalid(("body",), "Body is not valid JSON.") from exc

    if not isinstance(payload, dict):
        raise _invalid(("body",), "Body must be a JSON object.")

    if authenticated:
        if "target" in payload:
            raise _invalid(
                ("body", "target"),
                "An authenticated launch carries `asset_id`, not `target`.",
            )
        return ResolvedLaunch(
            body=_validate(AssetScanLaunch, payload), authenticated=True
        )

    if "asset_id" in payload:
        raise _invalid(
            ("body", "asset_id"),
            "An unauthenticated launch carries `target`, not `asset_id`.",
        )
    return ResolvedLaunch(body=_validate(GuestScanLaunch, payload), authenticated=False)


# Route dependency. Yields a validated launch request together with the access
# state that selected its schema.
ScanLaunchBody = Annotated[ResolvedLaunch, Depends(resolve_launch_body)]
