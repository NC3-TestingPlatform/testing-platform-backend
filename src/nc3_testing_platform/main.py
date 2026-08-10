"""Application assembly.

Domains are mounted under `/api/v1`.
"""

from fastapi import APIRouter, FastAPI

from nc3_testing_platform.core.errors import (
    configure_openapi,
    register_exception_handlers,
)
from nc3_testing_platform.core.openapi import register_component_schemas
from nc3_testing_platform.domains.admin.router import router as admin_router
from nc3_testing_platform.domains.api_keys.router import router as api_keys_router
from nc3_testing_platform.domains.assets.router import public_feed_router
from nc3_testing_platform.domains.assets.router import router as assets_router
from nc3_testing_platform.domains.findings.router import router as findings_router
from nc3_testing_platform.domains.health.router import router as health_router
from nc3_testing_platform.domains.notifications.router import account_router
from nc3_testing_platform.domains.notifications.router import (
    router as notifications_router,
)
from nc3_testing_platform.domains.org.router import invitation_router
from nc3_testing_platform.domains.org.router import router as org_router
from nc3_testing_platform.domains.reports.router import router as reports_router
from nc3_testing_platform.domains.scans.router import router as scans_router
from nc3_testing_platform.domains.scans.schemas import (
    AssetScanLaunch,
    FileScanLaunch,
    GuestScanLaunch,
    ScanEndEvent,
    ScanHeartbeatEvent,
    ScanJobEvent,
    ScanTaskEvent,
)
from nc3_testing_platform.domains.schedules.router import router as schedules_router
from nc3_testing_platform.domains.statements.router import router as statements_router

app = FastAPI(
    title="NC3 Testing Platform API",
    version="4.0.1",
    summary="v4.0 backend MVP for the NC3 Testing Platform.",
    openapi_url="/api/v1/openapi.json",
    docs_url="/docs",
)

register_exception_handlers(app)
configure_openapi(app)

# Referenced only from handwritten schema — the launch variants from the
# media-type-dispatched request body on `POST /scans`, and the event payloads from
# the `text/event-stream` response — so FastAPI's own pass never sees them.
register_component_schemas(
    app,
    AssetScanLaunch,
    GuestScanLaunch,
    FileScanLaunch,
    ScanTaskEvent,
    ScanJobEvent,
    ScanHeartbeatEvent,
    ScanEndEvent,
)

api_v1 = APIRouter(prefix="/api/v1")
api_v1.include_router(scans_router)
api_v1.include_router(assets_router)
api_v1.include_router(public_feed_router)
api_v1.include_router(schedules_router)
api_v1.include_router(findings_router)
api_v1.include_router(reports_router)
api_v1.include_router(notifications_router)
api_v1.include_router(account_router)
api_v1.include_router(org_router)
api_v1.include_router(invitation_router)
api_v1.include_router(api_keys_router)
api_v1.include_router(statements_router)
api_v1.include_router(admin_router)

app.include_router(api_v1)
app.include_router(health_router)
