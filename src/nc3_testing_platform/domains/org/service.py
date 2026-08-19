"""Organization lifecycle: promoting a workspace to a named organization.

The first service in this domain. Promotion lives here rather than in the assets
repository because naming an organization is an organization concern (IDR-016),
and the next story that touches org identity will look for it here.

Everything runs in-policy under the organization context the request asserted, so
`organization`'s `tenant_rows` predicate (`id = app.current_org`) is what confines
the update to the caller's own tenant. The statement does not need — and must not
have — a wider reach than that.
"""

import logging
import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Session

from nc3_testing_platform.domains.org.models import Organization

logger = logging.getLogger("nc3_testing_platform.domains.org")


def name_organization_if_unnamed(
    db: Session, *, organization_id: uuid.UUID, value: str
) -> bool:
    """Name the organization after `value`, unless it already has a settled name.

    One conditional atomic UPDATE, never read-then-write: two verifications
    completing at the same time would otherwise both see a null `named_at` and the
    second would overwrite the first organization name. The `WHERE named_at IS
    NULL` arm makes the promotion idempotent, and the rowcount is the answer —
    the same idiom as `domains/auth/repository`'s conditional updates.

    A false return is the ordinary case, not a failure: every verification after
    the first finds the name already settled.

    :returns: Whether this call is the one that named the organization.
    """
    result = db.execute(
        sa.update(Organization)
        .where(Organization.id == organization_id, Organization.named_at.is_(None))
        .values(name=value, named_at=sa.func.now())
    )
    named = result.rowcount == 1
    if named:
        # B7 audit call site: workspace promoted to a named organization.
        logger.info("organization %s named by domain verification", organization_id)
    return named
