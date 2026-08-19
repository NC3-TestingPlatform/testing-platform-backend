"""SQLAlchemy models for platform-local credentials and sessions (B3 / US #79).

Both tables are user-owned RLS rows (`user_id = app.current_user`) granted to
the `nc3_auth` role alone: `app_user` rows are visible org-wide for member
management, so credential material cannot live there (IDR-012). The password
hash is stored encrypted under the user-scope KEK (`key_envelope`,
IDR-011/017), so user erasure crypto-shreds it even out of backups. The
session token is stored as a plain SHA-256 hash — it must stay an index key
for the pre-context SECURITY DEFINER bootstrap, is not reversible, and dies
with the account by hard delete.
"""

import uuid
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from nc3_testing_platform.core.db import Base, uuid_pk


class UserCredential(Base):
    """argon2id password material and lockout state, one row per user.

    `password_ciphertext` is AES-256-GCM (`nonce || ct`, `core/crypto.py`)
    over the argon2id hash string, under the user-scope KEK. The lockout
    counter and `locked_until` implement the per-account arm of the
    brute-force requirement; the per-IP arm lives in Redis and is
    deliberately independent.
    """

    __tablename__ = "user_credential"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="CASCADE"), unique=True
    )
    password_ciphertext: Mapped[bytes]
    failed_login_count: Mapped[int] = mapped_column(server_default=sa.text("0"))
    locked_until: Mapped[datetime | None]
    password_updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now()
    )
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )


class UserSession(Base):
    """One server-side browser session (IDR-010).

    Timeouts are enforced by the application against these stamps
    (`core/security.py`): `created_at` anchors the absolute cap,
    `last_seen_at` the idle cap. Logout and password change set
    `revoked_at`; rows are never reused after it.
    """

    __tablename__ = "user_session"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="CASCADE"), index=True
    )
    token_hash: Mapped[bytes] = mapped_column(unique=True)
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    last_seen_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    revoked_at: Mapped[datetime | None]
    # Current MFA assurance lives here, never as a User boolean (§13.6).
    mfa_verified_at: Mapped[datetime | None]


class UserMfa(Base):
    """TOTP factor state, one row per user (B4 / US #80).

    `totp_secret_ciphertext` is AES-256-GCM (`nonce || ct`, `core/crypto.py`)
    over the raw RFC 6238 seed, under the user-scope KEK — user erasure
    crypto-shreds it like the password hash. Disable is a soft-revoke that
    nulls the seed and `confirmed_at`: `nc3_auth` holds no DELETE here.
    `failed_count`/`lockout_count`/`locked_until` implement the MFA-specific
    escalating lockout; `last_used_step` refuses TOTP replay inside the
    acceptance window.
    """

    __tablename__ = "user_mfa"

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="CASCADE"), unique=True
    )
    totp_secret_ciphertext: Mapped[bytes | None]
    confirmed_at: Mapped[datetime | None]
    last_used_step: Mapped[int | None] = mapped_column(sa.BigInteger())
    failed_count: Mapped[int] = mapped_column(server_default=sa.text("0"))
    lockout_count: Mapped[int] = mapped_column(server_default=sa.text("0"))
    locked_until: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
    updated_at: Mapped[datetime] = mapped_column(
        server_default=sa.func.now(), onupdate=sa.func.now()
    )


class MfaRecoveryCode(Base):
    """One single-use recovery code, stored as its SHA-256 (B4 / US #80).

    A hash, not a KDF: the codes are 80-bit random index keys like session
    tokens, not passwords — 2^80 preimage work is unaffected by hash speed.
    `used_at` burns a spent code, `superseded_at` burns a regenerated set;
    rows are never deleted in-band (no DELETE grant) — hard deletion belongs
    to the erasure story. The unique constraint is per user, not global: a
    global index would refuse one user's INSERT against another tenant's row,
    a cross-tenant existence oracle under FORCE RLS.
    """

    __tablename__ = "mfa_recovery_code"
    __table_args__ = (sa.UniqueConstraint("user_id", "code_hash"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        sa.ForeignKey("app_user.id", ondelete="CASCADE"), index=True
    )
    code_hash: Mapped[bytes]
    used_at: Mapped[datetime | None]
    superseded_at: Mapped[datetime | None]
    created_at: Mapped[datetime] = mapped_column(server_default=sa.func.now())
