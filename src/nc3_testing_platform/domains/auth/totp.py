"""Pure TOTP and recovery-code primitives (B4 / US #80).

No I/O and no database: `service.py` owns state and time; these functions
own the RFC 6238 math and the code formats, so tests inject time steps
directly instead of sleeping.
"""

import hashlib
import secrets
from base64 import b32encode

from cryptography.hazmat.primitives.hashes import SHA1
from cryptography.hazmat.primitives.twofactor import InvalidToken
from cryptography.hazmat.primitives.twofactor.totp import TOTP

# RFC 6238 defaults. SHA1 is deliberate, not a legacy oversight: it is the
# algorithm real authenticator apps interoperate on, and TOTP uses HMAC-SHA1
# where collision attacks do not apply.
_TOTP_DIGITS = 6
TOTP_STEP_SECONDS = 30
_SECRET_BYTES = 20  # 160 bits, the RFC 4226 recommended seed length

RECOVERY_CODE_COUNT = 10
_RECOVERY_CODE_BYTES = 10  # 80 bits → 16 base32 characters


def generate_secret() -> bytes:
    """A fresh random 160-bit TOTP seed."""
    return secrets.token_bytes(_SECRET_BYTES)


def secret_base32(secret: bytes) -> str:
    """The seed in the base32 form authenticator apps take as manual entry."""
    return b32encode(secret).decode("ascii")


def _totp(secret: bytes) -> TOTP:
    return TOTP(secret, _TOTP_DIGITS, SHA1(), TOTP_STEP_SECONDS)


def provisioning_uri(secret: bytes, *, account_name: str, issuer: str) -> str:
    """The `otpauth://totp/...` URI, built and quoted by the library."""
    return _totp(secret).get_provisioning_uri(account_name, issuer)


def step_at(seconds: float) -> int:
    """The TOTP time step containing the instant ``seconds`` (epoch)."""
    return int(seconds) // TOTP_STEP_SECONDS


def matching_step(secret: bytes, code: str, *, at_step: int) -> int | None:
    """The step within ±1 of ``at_step`` that ``code`` matches, or ``None``.

    ``TOTP.verify`` compares in constant time; the loop widens acceptance to
    one step of clock skew either way. The caller enforces replay refusal
    against the stored last-used step.
    """
    totp = _totp(secret)
    for step in (at_step - 1, at_step, at_step + 1):
        try:
            totp.verify(code.encode("ascii"), step * TOTP_STEP_SECONDS)
        except InvalidToken:
            continue
        return step
    return None


def generate_recovery_codes() -> list[str]:
    """A fresh set of one-time codes, formatted ``xxxx-xxxx-xxxx-xxxx``."""
    codes = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = (
            b32encode(secrets.token_bytes(_RECOVERY_CODE_BYTES))
            .decode("ascii")
            .lower()
        )
        codes.append("-".join(raw[i : i + 4] for i in range(0, 16, 4)))
    return codes


def hash_recovery_code(code: str) -> bytes:
    """The stored form of a recovery code: SHA-256 of its normalized text.

    A hash, not a KDF: the codes are 80-bit random values, so 2^80 preimage
    work dwarfs any lockout budget and is unaffected by hash speed — a slow
    KDF protects low-entropy passwords, not index keys. Same convention as
    `hash_session_token`. Normalization forgives separators and case.
    """
    normalized = code.replace("-", "").replace(" ", "").lower()
    return hashlib.sha256(normalized.encode("ascii", errors="replace")).digest()
