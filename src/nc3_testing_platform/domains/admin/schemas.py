"""Platform-administrator view of the audit log.

An audit row never names a user in the clear. Identity, IP address, and user agent
live inside `payload_encrypted`, sealed with a per-event key that is itself wrapped
by a per-user key. Erasing a user deletes that per-user key, at which point the
payload becomes permanently unreadable while the row and its hash chain stay
intact — the log remains provably unbroken without retaining the person.

The ciphertext and wrapping fields are returned even though v4.0 never decrypts
them, because `entry_hash` is computed over them. Withholding them would leave a
reader unable to verify the chain they were given.
"""

from typing import Any

from pydantic import Field

from nc3_testing_platform.core.schemas import BaseSchema, ResourceId, Timestamp


class AuditEvent(BaseSchema):
    """One append-only audit entry."""

    id: ResourceId
    organization_id: ResourceId | None = Field(
        default=None, description="Null for platform-chain events."
    )
    chain_id: str = Field(
        description=(
            "Organization or platform chain this entry belongs to. Never a per-user "
            "chain: chain membership would itself be a user identifier."
        )
    )
    sequence_number: int = Field(
        description="Position within the chain. Unique with `chain_id`."
    )
    event_type: str = Field(
        description="Namespaced event type. Vocabulary is code-owned.",
        examples=["asset.verification.succeeded"],
    )
    subject_type: str | None = Field(
        default=None, description="Resource category. Never identifies a user."
    )
    subject_id: ResourceId | None = Field(
        default=None, description="Non-user resource this event concerns."
    )
    # `detail` has no fixed schema; contents are per-event-type and code-owned.
    detail: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Operational values only — status, counts, resource identifiers. "
            "Identity, email, addresses, and domains never appear here."
        ),
    )
    payload_encrypted: str | None = Field(
        default=None,
        description=(
            "Base64 ciphertext of the sensitive detail. Not decrypted by v4.0; "
            "returned so the hash chain can be verified."
        ),
    )
    wrapped_dek: str | None = Field(
        default=None, description="Base64 per-event key, wrapped by the user key."
    )
    envelope_id: ResourceId | None = Field(
        default=None,
        description=(
            "Opaque key-envelope reference. Carries no foreign key and encodes no "
            "user identifier; deleting the envelope is what shreds the payload."
        ),
    )
    encryption_metadata: dict[str, Any] | None = Field(
        default=None, description="Algorithm and nonce metadata for the payload."
    )
    occurred_at: Timestamp
    previous_hash: str | None = Field(
        default=None, description="Null for the first entry in a chain."
    )
    entry_hash: str = Field(
        description=(
            "Covers `previous_hash` and the whole stored entry, ciphertext and "
            "envelope reference included, so swapping either breaks the chain."
        )
    )
    retention_until: Timestamp = Field(
        description="Twenty-four months after the event by default."
    )
