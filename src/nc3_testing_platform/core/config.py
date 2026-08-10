"""Values that a deployment can change without a code change.

Environment values are parsed and bounded once, at import — which is process
start — so a misconfigured deployment fails immediately with a readable error
instead of crashing on first use, or worse: a negative retention extension
would silently move `purge_at` backwards.
"""

import os
from datetime import timedelta


def _positive_int(name: str, default: int) -> int:
    """Read an integer environment setting that must be at least 1.

    A missing or empty value means the default; anything else must parse and
    pass the bound, or the process refuses to start.
    """
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    try:
        value = int(raw)
    except ValueError:
        raise RuntimeError(
            f"{name} must be an integer number of days, got {raw!r}."
        ) from None
    if value < 1:
        raise RuntimeError(f"{name} must be at least 1, got {value}.")
    return value


# How long a domain-verification challenge stays answerable; a verification that already succeeded is unaffected.
# Seven days: long enough for a DNS change to clear a ticketing process, short enough that an abandoned challenge does not sit open forever.
VERIFICATION_TOKEN_TTL = timedelta(days=_positive_int("VERIFICATION_TOKEN_TTL_DAYS", 7))

# Vendor prefix in the DNS challenge record name, giving `_<prefix>-verify.<domain>`.
# A generic name like `_verify` would collide when a domain owner verifies with two providers that both chose it.
# Set before issuing the first challenge: a later change breaks every challenge in flight and every record already-verified domains have published.
VERIFICATION_RECORD_PREFIX = os.getenv("VERIFICATION_RECORD_PREFIX", "nc3")

# How far one retention extension moves a scan's `purge_at`.
# Data-protection policy varies by jurisdiction, so it stays out of the contract.
RETENTION_EXTENSION = timedelta(days=_positive_int("RETENTION_EXTENSION_DAYS", 365))


def verification_record_name(domain: str) -> str:
    """The DNS name at which a domain's challenge token must be published."""
    return f"_{VERIFICATION_RECORD_PREFIX}-verify.{domain}"
