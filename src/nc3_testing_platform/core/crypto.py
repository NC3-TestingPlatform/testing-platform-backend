"""Application-layer envelope encryption (IDR-011/IDR-017, data-model §1.2).

Two levels: the deployment master key — a mounted secret, never stored — wraps
one random KEK per `key_envelope` row; data is encrypted under the unwrapped
scope KEK, or under a per-record DEK itself wrapped by the KEK where a table
stores a `wrapped_dek` column (data-model §3.5, §12.1). AES-256-GCM throughout.

Blob layout: :func:`encrypt` returns ``nonce || ciphertext`` so a stored blob
is self-contained; `key_envelope` alone keeps its nonce in a column of its own
because the schema says so (§3.3), which is what the :class:`WrappedKey` shape
carries. AAD binds every ciphertext to its purpose — a blob lifted from one
column can never be replayed into another.

Settings are read at call time, never bound at import, so tests can
monkeypatch ``settings.app_encryption_master_key``.
"""

import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from nc3_testing_platform.core.settings import settings

ENVELOPE_ALGORITHM = "AES-256-GCM"
_NONCE_BYTES = 12
_KEY_BYTES = 32


class MasterKeyUnavailableError(RuntimeError):
    """The deployment master key is not configured.

    Raised instead of any fallback: an operation that needs the key must fail
    loudly (a logged 500), never degrade to plaintext.
    """


class DecryptionError(RuntimeError):
    """Authenticated decryption failed: wrong key, wrong AAD, or tampering."""


def master_key() -> bytes:
    """The deployment master key, decoded from settings.

    :raises MasterKeyUnavailableError: When ``APP_ENCRYPTION_MASTER_KEY`` is
        unset. Format and length were already validated at process start
        (`core/settings.py`), so no re-validation happens here.
    """
    if not settings.app_encryption_master_key:
        raise MasterKeyUnavailableError(
            "APP_ENCRYPTION_MASTER_KEY is not configured; refusing to operate "
            "on encrypted identity material."
        )
    return bytes.fromhex(settings.app_encryption_master_key)


def generate_key() -> bytes:
    """A fresh random 256-bit key, for a scope KEK or a per-record DEK."""
    return secrets.token_bytes(_KEY_BYTES)


@dataclass(frozen=True)
class WrappedKey:
    """A key encrypted under the master key, in `key_envelope` column shape."""

    ciphertext: bytes
    nonce: bytes
    algorithm: str
    master_key_version: str


def wrap_key(key: bytes, *, aad: bytes) -> WrappedKey:
    """Encrypt ``key`` under the master key.

    :param key: The KEK (or DEK) to wrap.
    :param aad: Purpose tag, e.g. ``b"key_envelope"`` — must match at unwrap.
    """
    nonce = secrets.token_bytes(_NONCE_BYTES)
    ciphertext = AESGCM(master_key()).encrypt(nonce, key, aad)
    return WrappedKey(
        ciphertext=ciphertext,
        nonce=nonce,
        algorithm=ENVELOPE_ALGORITHM,
        master_key_version=settings.app_encryption_master_key_version,
    )


def unwrap_key(ciphertext: bytes, nonce: bytes, *, aad: bytes) -> bytes:
    """Recover a wrapped key.

    :raises DecryptionError: On tampering, a wrong master key, or a wrong AAD.
    """
    try:
        return AESGCM(master_key()).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("Key unwrap failed authentication.") from exc


def encrypt(plaintext: bytes, key: bytes, *, aad: bytes) -> bytes:
    """Encrypt ``plaintext`` under ``key``; returns ``nonce || ciphertext``."""
    nonce = secrets.token_bytes(_NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(blob: bytes, key: bytes, *, aad: bytes) -> bytes:
    """Decrypt a ``nonce || ciphertext`` blob produced by :func:`encrypt`.

    :raises DecryptionError: On a truncated blob, tampering, a wrong key, or
        a wrong AAD.
    """
    if len(blob) <= _NONCE_BYTES:
        raise DecryptionError("Ciphertext is shorter than its nonce.")
    try:
        return AESGCM(key).decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], aad)
    except InvalidTag as exc:
        raise DecryptionError("Decryption failed authentication.") from exc
