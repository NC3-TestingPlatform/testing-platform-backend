"""Versioned declarations and their immutable receipts.

One pair of shapes covers every declaration the platform needs: account-level
acceptance of Terms, AUP, and the privacy notice, and per-launch attestation of
permission to scan a target. Receipts follow the consent-record structure of
ISO/IEC 29184:2020 and ISO/IEC TS 27560:2023.

Acceptance and attestation share the receipt shape but remain distinct acts, which
is what `response_kind` records — the user either agreed to something or asserted
a fact, and a compliance record has to be able to say which.

MVP: Nothing in the v4.0 executable-test catalog is classified intrusive, so no
v4.0 launch requires a per-launch declaration. The launch field exists and is optional.

A receipt never carries actor evidence on the wire. Identity, IP address, and user
agent are encrypted at rest, so that erasing the user renders them unreadable without
deleting the receipt.
"""

from pydantic import BaseModel, Field

from nc3_testing_platform.core.enums import StatementResponseKind
from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp


class StatementResponseSubmission(BaseModel):
    """A client's answer to one statement, identified by key and version.

    The version is explicit, so the receipt records the exact text that was shown,
    not whichever version happened to be current.
    """

    statement_key: str = Field(
        description="Namespaced statement identifier, e.g. `scan_target_permission`.",
        examples=["terms_and_conditions"],
    )
    version: str = Field(
        description="Exact version answered, as returned by `GET /statements`.",
        examples=["2026-01-15"],
    )


class Statement(BaseSchema):
    """One currently active versioned statement.

    Active means `effective_at` has passed and the statement is not retired.
    """

    id: ResourceId
    statement_key: str
    version: str
    response_kind: StatementResponseKind
    required_context_type: str | None = Field(
        default=None,
        description=(
            "Null for an account-level statement. `scan_job` for a per-launch one, "
            "whose response must be bound to the launch it belongs to."
        ),
    )
    content_hash: str = Field(
        description="Hash of the exact text, so a receipt can prove what was shown."
    )
    content_uri: str | None = None
    effective_at: Timestamp


class StatementResponseReceipt(BaseSchema):
    """Proof that a statement was answered.

    Immutable: a correction is a new statement version and a new response, never an
    edit. Actor evidence is deliberately absent from this representation.
    """

    id: ResourceId
    statement_id: ResourceId
    statement_key: str = Field(
        description=(
            "Statement identifier, restated so a receipt readback needs no join "
            "against retired statement versions."
        ),
    )
    version: str = Field(description="Exact version answered.")
    responded_at: Timestamp
    context_type: str | None = Field(
        default=None, description="Null for an account-level response."
    )
    context_id: ResourceId | None = Field(
        default=None,
        description="The bound resource — a ScanJob for a per-launch response.",
    )
