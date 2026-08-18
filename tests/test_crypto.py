"""Unit tests for the envelope-encryption primitives (core/crypto.py)."""

import pytest

from nc3_testing_platform.core import crypto
from nc3_testing_platform.core.settings import settings

TEST_KEY_HEX = "ab" * 32


@pytest.fixture
def master_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Configure a synthetic 256-bit master key for the test."""
    monkeypatch.setattr(settings, "app_encryption_master_key", TEST_KEY_HEX)
    monkeypatch.setattr(settings, "app_encryption_master_key_version", "test-1")


def test_wrap_unwrap_round_trip(master_key: None) -> None:
    """A wrapped KEK unwraps to itself under the same AAD."""
    kek = crypto.generate_key()
    wrapped = crypto.wrap_key(kek, aad=b"key_envelope.wrapped_kek")
    assert wrapped.algorithm == crypto.ENVELOPE_ALGORITHM
    assert wrapped.master_key_version == "test-1"
    assert (
        crypto.unwrap_key(
            wrapped.ciphertext, wrapped.nonce, aad=b"key_envelope.wrapped_kek"
        )
        == kek
    )


def test_unwrap_refuses_wrong_aad(master_key: None) -> None:
    """A ciphertext never opens under another purpose tag."""
    kek = crypto.generate_key()
    wrapped = crypto.wrap_key(kek, aad=b"purpose-a")
    with pytest.raises(crypto.DecryptionError):
        crypto.unwrap_key(wrapped.ciphertext, wrapped.nonce, aad=b"purpose-b")


def test_encrypt_decrypt_round_trip(master_key: None) -> None:
    """nonce||ct blobs decrypt to the original plaintext."""
    key = crypto.generate_key()
    blob = crypto.encrypt(b"argon2id$...", key, aad=b"user_credential.password")
    assert crypto.decrypt(blob, key, aad=b"user_credential.password") == b"argon2id$..."


def test_decrypt_refuses_tampering(master_key: None) -> None:
    """One flipped bit fails GCM authentication."""
    key = crypto.generate_key()
    blob = bytearray(crypto.encrypt(b"secret", key, aad=b"t"))
    blob[-1] ^= 0x01
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(bytes(blob), key, aad=b"t")


def test_decrypt_refuses_truncated_blob(master_key: None) -> None:
    """A blob shorter than its nonce is refused before AESGCM sees it."""
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(b"short", crypto.generate_key(), aad=b"t")


def test_missing_master_key_refuses_loudly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No key means a raised error — never a plaintext or derived fallback."""
    monkeypatch.setattr(settings, "app_encryption_master_key", "")
    with pytest.raises(crypto.MasterKeyUnavailableError):
        crypto.wrap_key(crypto.generate_key(), aad=b"t")
