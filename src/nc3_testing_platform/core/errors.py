"""RFC 9457 `application/problem+json` error contract.

Every error response references `ProblemDetail`. Handlers emit it at runtime with
the correct media type; a custom OpenAPI pass relabels the documented media type
to `application/problem+json` while keeping the schema `$ref`'d in components.
"""

import json
from collections.abc import Iterator
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

PROBLEM_MEDIA_TYPE = "application/problem+json"
_PROBLEM_REF = "#/components/schemas/ProblemDetail"
_VALIDATION_REF = "#/components/schemas/HTTPValidationError"
_FASTAPI_VALIDATION_SCHEMAS = ("HTTPValidationError", "ValidationError")


class FieldError(BaseModel):
    """One field-level validation error (RFC 9457 extension member)."""

    name: str = Field(
        description="Dotted path to the offending field, e.g. `body.email`."
    )
    reason: str


class ProblemDetail(BaseModel):
    """RFC 9457 problem detail."""

    type: str = Field(
        default="about:blank",
        description="URI reference identifying the problem type.",
    )
    title: str = Field(description="Short, human-readable summary of the problem type.")
    status: int = Field(description="HTTP status code.")
    detail: str | None = Field(
        default=None, description="Human-readable explanation for this occurrence."
    )
    instance: str | None = Field(
        default=None, description="URI reference identifying this occurrence."
    )
    errors: list[FieldError] | None = Field(
        default=None, description="Field-level validation errors (extension)."
    )


class ProblemResponse(JSONResponse):
    """JSON response that carries the `application/problem+json` media type."""

    media_type = PROBLEM_MEDIA_TYPE


def problem_responses(*status_codes: int) -> dict[int | str, dict]:
    """Build an OpenAPI `responses` map where each code references `ProblemDetail`.

    Attach to a route via ``responses=problem_responses(404, 409)``. The default
    media type is rewritten to `application/problem+json` by :func:`configure_openapi`.
    """
    return {
        code: {
            "model": ProblemDetail,
            "description": HTTPStatus(code).phrase,
            "content": {PROBLEM_MEDIA_TYPE: {}},
        }
        for code in status_codes
    }


async def _http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> ProblemResponse:
    problem = ProblemDetail(
        title=HTTPStatus(exc.status_code).phrase,
        status=exc.status_code,
        detail=exc.detail if isinstance(exc.detail, str) else None,
        instance=str(request.url),
    )
    return ProblemResponse(
        status_code=exc.status_code,
        content=problem.model_dump(mode="json", exclude_none=True),
        headers=getattr(exc, "headers", None),
    )


async def _validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> ProblemResponse:
    errors = [
        FieldError(name=".".join(str(part) for part in err["loc"]), reason=err["msg"])
        for err in exc.errors()
    ]
    problem = ProblemDetail(
        title=HTTPStatus.UNPROCESSABLE_ENTITY.phrase,
        status=HTTPStatus.UNPROCESSABLE_ENTITY,
        detail="Request validation failed.",
        instance=str(request.url),
        errors=errors,
    )
    return ProblemResponse(
        status_code=HTTPStatus.UNPROCESSABLE_ENTITY,
        content=problem.model_dump(mode="json", exclude_none=True),
    )


async def _not_implemented_handler(
    request: Request, exc: NotImplementedError
) -> ProblemResponse:
    """Answers `501` for a seam that is reachable but not yet implemented.

    Functions belonging to a later development phase raise `NotImplementedError` at their seam.
    A call that reaches one is a known, deliberate gap, answered as `501 Not Implemented` rather than as a `500` fault.
    """
    problem = ProblemDetail(
        title=HTTPStatus.NOT_IMPLEMENTED.phrase,
        status=HTTPStatus.NOT_IMPLEMENTED,
        detail="This behavior is not implemented.",
        instance=str(request.url),
    )
    return ProblemResponse(
        status_code=HTTPStatus.NOT_IMPLEMENTED,
        content=problem.model_dump(mode="json", exclude_none=True),
    )


async def _unhandled_exception_handler(
    request: Request, exc: Exception
) -> ProblemResponse:
    # No `detail`: the exception text is for the server log, never for the client.
    problem = ProblemDetail(
        title=HTTPStatus.INTERNAL_SERVER_ERROR.phrase,
        status=HTTPStatus.INTERNAL_SERVER_ERROR,
        instance=str(request.url),
    )
    return ProblemResponse(
        status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
        content=problem.model_dump(mode="json", exclude_none=True),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Route HTTP, validation, and unhandled errors through the problem+json handlers."""
    # `exc` annotations are narrower (more precise), which trips pyright's contravariance check.
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(RequestValidationError, _validation_exception_handler)  # pyright: ignore[reportArgumentType]
    app.add_exception_handler(NotImplementedError, _not_implemented_handler)  # pyright: ignore[reportArgumentType]
    # Starlette re-raises after this handler responds, so the traceback still reaches the server log.
    app.add_exception_handler(Exception, _unhandled_exception_handler)


def _responses(schema: dict) -> Iterator[dict]:
    """Every response object in the document."""
    for path_item in schema.get("paths", {}).values():
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            for response in operation.get("responses", {}).values():
                if isinstance(response, dict):
                    yield response


def _relabel_problem_media_type(schema: dict) -> None:
    """In-place: move ProblemDetail error bodies from application/json to problem+json."""
    for response in _responses(schema):
        content = response.get("content")
        if not content:
            continue
        json_body = content.get("application/json")
        if json_body and json_body.get("schema", {}).get("$ref") == _PROBLEM_REF:
            content[PROBLEM_MEDIA_TYPE] = content.pop("application/json")


def _replace_default_validation_body(schema: dict) -> None:
    """In-place: restate FastAPI's generated 422 body as a problem detail.

    Without this the contract claims two different error shapes — problem+json for
    every error we declare, and FastAPI's `HTTPValidationError` for validation
    failures — and a generated client would need branches for both.
    """
    for response in _responses(schema):
        content = response.get("content")
        if not content:
            continue
        json_body = content.get("application/json")
        if json_body and json_body.get("schema", {}).get("$ref") == _VALIDATION_REF:
            content.pop("application/json")
            content[PROBLEM_MEDIA_TYPE] = {"schema": {"$ref": _PROBLEM_REF}}
            response["description"] = HTTPStatus.UNPROCESSABLE_ENTITY.phrase


def _prune_unreferenced_schemas(schema: dict, names: tuple[str, ...]) -> None:
    """Drop component schemas that nothing references anymore.

    After the HTTP 422 response bodies are rewritten to problem+json, FastAPI's
    validation models are referenced by nothing; left in place, they become dead
    types in every generated client.
    `HTTPValidationError` holds the only reference to `ValidationError`, so it
    must be removed first — only then does `ValidationError` count as unreferenced.
    """
    components = schema.get("components", {}).get("schemas")
    if not components:
        return
    for name in names:
        if name not in components:
            continue
        remaining = {
            "paths": schema.get("paths", {}),
            "schemas": {k: v for k, v in components.items() if k != name},
        }
        if f'"#/components/schemas/{name}"' not in json.dumps(remaining):
            del components[name]


def configure_openapi(app: FastAPI) -> None:
    """Custom OpenAPI generator that emits problem+json for error bodies."""
    default_openapi = app.openapi

    def openapi() -> dict:
        schema = default_openapi()  # FastAPI caches into app.openapi_schema
        # Each pass is idempotent: no application/json body carries a ProblemDetail
        # or HTTPValidationError reference, so re-running is a no-op.
        _relabel_problem_media_type(schema)
        _replace_default_validation_body(schema)
        _prune_unreferenced_schemas(schema, _FASTAPI_VALIDATION_SCHEMAS)
        return schema

    app.openapi = openapi
