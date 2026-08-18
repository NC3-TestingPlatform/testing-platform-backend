"""The RLS context helpers emit exactly the GUCs the row policies read.

No live database here (repo convention): a recording stand-in captures what
each helper executes, and the assertions pin the contract the policies depend
on — parameterised ``set_config(..., true)``, every helper writing all three
GUCs, and ``None`` serialised as the empty string (a GUC cannot hold NULL;
`NULLIF(..., '')` in the policies makes '' deny like never-set). The live
behaviour — deny on missing context, no leak across pooled transactions — is
the isolation suite's job (`tests/test_org_isolation.py`, `-m postgres`).
"""

import uuid

import pytest

from nc3_testing_platform.core import rls


class RecordingSession:
    """Stands in for an ORM session: records (sql, params) per execute."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str]]] = []

    def execute(self, statement: object, params: dict[str, str]) -> None:
        """Record the statement and its parameters instead of running them."""
        self.calls.append((str(statement), dict(params)))


def _gucs(session: RecordingSession) -> dict[str, str]:
    """The final value each GUC was set to, by name."""
    return {params["name"]: params["value"] for _, params in session.calls}


def test_every_statement_is_parameterised_set_config_local() -> None:
    """The emitted SQL is the one parameterised, transaction-local form."""
    session = RecordingSession()
    rls.set_org_context(session, uuid.uuid4())  # type: ignore[arg-type]
    for sql, params in session.calls:
        assert sql == "SELECT set_config(:name, :value, true)"
        assert set(params) == {"name", "value"}


def test_org_context_sets_org_and_clears_the_rest() -> None:
    """An org-only context opens the org arm and closes user and guest arms."""
    session = RecordingSession()
    org = uuid.uuid4()
    rls.set_org_context(session, org)  # type: ignore[arg-type]
    assert _gucs(session) == {
        rls.ORG_GUC: str(org),
        rls.USER_GUC: "",
        rls.JOB_GUC: "",
    }


def test_org_context_with_acting_user_sets_both_arms() -> None:
    """Org + user opens both arms; the guest arm stays closed."""
    session = RecordingSession()
    org, user = uuid.uuid4(), uuid.uuid4()
    rls.set_org_context(session, org, user_id=user)  # type: ignore[arg-type]
    assert _gucs(session) == {
        rls.ORG_GUC: str(org),
        rls.USER_GUC: str(user),
        rls.JOB_GUC: "",
    }


def test_user_context_sets_only_the_user_arm() -> None:
    """A user-only context never carries an org or guest arm."""
    session = RecordingSession()
    user = uuid.uuid4()
    rls.set_user_context(session, user)  # type: ignore[arg-type]
    assert _gucs(session) == {
        rls.ORG_GUC: "",
        rls.USER_GUC: str(user),
        rls.JOB_GUC: "",
    }


def test_guest_context_sets_only_the_job_arm() -> None:
    """The guest arm carries the job id and nothing else."""
    session = RecordingSession()
    job = uuid.uuid4()
    rls.set_guest_job_context(session, job)  # type: ignore[arg-type]
    assert _gucs(session) == {
        rls.ORG_GUC: "",
        rls.USER_GUC: "",
        rls.JOB_GUC: str(job),
    }


def test_stacked_contexts_leave_no_residual_arm() -> None:
    """A second context in the same transaction fully replaces the first."""
    session = RecordingSession()
    rls.set_org_context(session, uuid.uuid4(), user_id=uuid.uuid4())  # type: ignore[arg-type]
    job = uuid.uuid4()
    rls.set_guest_job_context(session, job)  # type: ignore[arg-type]
    assert _gucs(session) == {
        rls.ORG_GUC: "",
        rls.USER_GUC: "",
        rls.JOB_GUC: str(job),
    }


@pytest.mark.parametrize(
    ("helper", "message"),
    [
        (rls.set_org_context, "org_id is required"),
        (rls.set_user_context, "user_id is required"),
        (rls.set_guest_job_context, "job_id is required"),
    ],
)
def test_a_missing_principal_raises_instead_of_denying_everything(
    helper: object, message: str
) -> None:
    """Passing None is a call-site bug and fails loud, not fail-closed-quietly."""
    session = RecordingSession()
    with pytest.raises(ValueError, match=message):
        helper(session, None)  # type: ignore[operator]
    assert session.calls == []
