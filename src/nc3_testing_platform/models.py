"""One import that loads every table of the v4 data model onto `Base.metadata`.

Model modules register their tables as an import side effect, so anything that
needs the complete schema — Alembic autogenerate (issue #6), metadata tests, a
future `create_all` in tooling — imports this module instead of guessing which
domains define tables.
"""

from nc3_testing_platform.core.db import Base
from nc3_testing_platform.domains.admin import models as admin_models
from nc3_testing_platform.domains.api_keys import models as api_keys_models
from nc3_testing_platform.domains.assets import models as assets_models
from nc3_testing_platform.domains.findings import models as findings_models
from nc3_testing_platform.domains.notifications import models as notifications_models
from nc3_testing_platform.domains.org import models as org_models
from nc3_testing_platform.domains.reports import models as reports_models
from nc3_testing_platform.domains.scans import models as scans_models
from nc3_testing_platform.domains.schedules import models as schedules_models
from nc3_testing_platform.domains.statements import models as statements_models

__all__ = [
    "Base",
    "admin_models",
    "api_keys_models",
    "assets_models",
    "findings_models",
    "notifications_models",
    "org_models",
    "reports_models",
    "scans_models",
    "schedules_models",
    "statements_models",
]
