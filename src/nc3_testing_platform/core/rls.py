"""Per-transaction RLS context: the GUCs the row policies read.

IDR-012 names three GUCs — ``app.current_org``, ``app.current_user`` and
``app.current_job`` — and mandates ``SET LOCAL`` semantics so a pooled
connection can never leak a tenant context: ``set_config(..., is_local =>
true)`` dies with the enclosing transaction. Each helper here joins the
session's current transaction (SQLAlchemy autobegin opens one on the first
statement), so the context evaporates at commit or rollback — a session that
keeps working past its commit runs context-free, and the policies then deny
with an empty result, never an error.

Every helper sets all three GUCs, clearing the two that are not its arm: two
contexts stacked in one transaction must not leave a residual arm from the
first one satisfying a policy the second never asserted.

``None`` is serialised as the empty string because a GUC cannot hold NULL —
``set_config(name, NULL, true)`` keeps the *previous* value, which is exactly
the leak this module exists to prevent. The policy predicates unwrap it with
``NULLIF(current_setting(name, true), '')::uuid``, so both "never set" (NULL)
and "cleared" ('') deny identically.

Platform-queue workers connect as the ``app_platform`` role, whose per-duty
policies read no GUC — they call none of this (docs/database-roles.md).
"""

import logging
import uuid

import sqlalchemy as sa
from sqlalchemy.orm import Session

logger = logging.getLogger("nc3_testing_platform.core.rls")

ORG_GUC = "app.current_org"
USER_GUC = "app.current_user"
JOB_GUC = "app.current_job"

_SET_CONFIG = sa.text("SELECT set_config(:name, :value, true)")


def _set(session: Session, name: str, value: uuid.UUID | None) -> None:
    session.execute(
        _SET_CONFIG, {"name": name, "value": "" if value is None else str(value)}
    )


def set_org_context(
    session: Session, org_id: uuid.UUID, user_id: uuid.UUID | None = None
) -> None:
    """Assert an organization context (optionally with the acting user).

    :param session: The session whose current transaction carries the context.
    :param org_id: The organization the caller is authenticated into.
    :param user_id: The acting user, when a user arm should also open
        (user-owned tables); omit for worker writes that act for the org only.
    :raises ValueError: If ``org_id`` is ``None`` — an org context without an
        org is a bug at the call site, not a guest context.
    """
    if org_id is None:
        raise ValueError("org_id is required; use set_guest_job_context for guests")
    _set(session, ORG_GUC, org_id)
    _set(session, USER_GUC, user_id)
    _set(session, JOB_GUC, None)


def set_user_context(session: Session, user_id: uuid.UUID) -> None:
    """Assert a user-only context (user-owned rows; no org arm).

    :param session: The session whose current transaction carries the context.
    :param user_id: The authenticated user.
    :raises ValueError: If ``user_id`` is ``None``.
    """
    if user_id is None:
        raise ValueError("user_id is required")
    _set(session, ORG_GUC, None)
    _set(session, USER_GUC, user_id)
    _set(session, JOB_GUC, None)


def set_guest_job_context(session: Session, job_id: uuid.UUID) -> None:
    """Assert the guest arm: only rows of this one scan job are reachable.

    Set exclusively from a validated guest job — at creation (the id is
    client-generated, so the context can precede the INSERT) or after the
    claim token verified (IDR-012).

    :param session: The session whose current transaction carries the context.
    :param job_id: The guest ``scan_job.id``.
    :raises ValueError: If ``job_id`` is ``None``.
    """
    if job_id is None:
        raise ValueError("job_id is required")
    _set(session, ORG_GUC, None)
    _set(session, USER_GUC, None)
    _set(session, JOB_GUC, job_id)
