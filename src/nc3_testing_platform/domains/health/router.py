"""Liveness and readiness probes.

Mounted at the root rather than under `/api/v1`: an orchestrator probing a pod
should not have to know the API version, and these must keep answering across a
version bump.
"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["health"])


class HealthStatus(BaseModel):
    """Probe result."""

    status: str


@router.get("/healthz", summary="Liveness probe")
async def healthz() -> HealthStatus:
    """The process is up. Says nothing about dependencies."""
    return HealthStatus(status="ok")


@router.get("/readyz", summary="Readiness probe")
async def readyz() -> HealthStatus:
    """The process is ready to serve traffic."""
    return HealthStatus(status="ready")
