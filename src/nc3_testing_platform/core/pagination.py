"""Cursor-based pagination.

Cursors stay stable when rows are inserted between page reads; offsets skip or
repeat rows.

Pagination is exposed as a dependency (`CursorPage`) rather than a query-model, so
it composes with per-endpoint filters. (A `Annotated[Model, Query()]` param
stops expanding once other scalar query params sit alongside it.)

    @router.get("")
    async def list_things(page: CursorPage, status: Status | None = None) -> Page[Thing]:
        ...
"""

from typing import Annotated

from fastapi import Depends, Query
from pydantic import BaseModel, Field


class CursorParams(BaseModel):
    """Resolved cursor and limit for a paginated list request."""

    cursor: str | None = None
    limit: int = 50


def cursor_params(
    cursor: Annotated[
        str | None,
        Query(
            description="Opaque cursor returned as `next_cursor` by the previous page."
        ),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Max items per page.")] = 50,
) -> CursorParams:
    """Resolves the `cursor` and `limit` query parameters into `CursorParams`."""
    return CursorParams(cursor=cursor, limit=limit)


# Route dependency: injects resolved `CursorParams` and documents `cursor` + `limit`.
CursorPage = Annotated[CursorParams, Depends(cursor_params)]


class Page[T](BaseModel):
    """One page of a cursor-paginated list."""

    items: list[T]
    next_cursor: str | None = Field(
        default=None,
        description="Cursor for the next page; `null` when there are no more results.",
    )
