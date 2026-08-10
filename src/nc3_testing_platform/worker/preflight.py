"""Startup checks for worker images.

Each egress queue maps to the external binaries its engines shell out to. The
check runs at worker start (see `app._preflight`) and exits the process with a
readable list of what is missing — the alternative, tool auto-detection with
silent skipping, produces scans that look complete and are not (US #78 ADR).

The registry names what the *current* image is expected to carry. Engine
binaries (nmap, subfinder and friends) join their queue's list in the same
commit that installs them into that queue's Dockerfile stage, so image and
check cannot drift apart.
"""

import re
import shutil
import subprocess
import sys

REQUIRED_BINARIES: dict[str, tuple[str, ...]] = {
    # chainvalidator/mailvalidator/headersvalidator/quantumvalidator need an
    # openssl >= 3.5 binary once integrated; the image installs it already.
    "non-intrusive-scan": ("openssl",),
    # subdomainenum/portscanner/tlsvalidator add nmap and the Go tools here
    # when the engine-integration ticket lands them in the image.
    "intrusive-scan": ("openssl",),
    "file-analysis": (),
    "platform": (),
}

# Binaries whose mere presence is not enough: the post-quantum checks need the
# openssl 3.5 group syntax, and an older binary would pass a which() test while
# producing quietly incomplete scans.
MINIMUM_VERSIONS: dict[str, tuple[int, int]] = {
    "openssl": (3, 5),
}


def _reported_version(binary: str) -> tuple[int, int] | None:
    """The (major, minor) the binary reports for `<binary> version`, else None."""
    try:
        output = subprocess.run(
            [binary, "version"], capture_output=True, text=True, timeout=10, check=True
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"(\d+)\.(\d+)", output)
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def run_preflight(queue: str) -> None:
    """Verify the binaries the given queue's engines require, or die loudly.

    An unknown or empty queue name fails too: a worker that cannot say which
    egress profile it serves is misconfigured, not exempt.
    """
    if queue not in REQUIRED_BINARIES:
        sys.exit(
            f"preflight: WORKER_QUEUE={queue!r} is not a known egress queue "
            f"(expected one of {', '.join(sorted(REQUIRED_BINARIES))})."
        )
    missing = [b for b in REQUIRED_BINARIES[queue] if shutil.which(b) is None]
    if missing:
        sys.exit(
            f"preflight: queue {queue!r} requires binaries not on PATH: "
            f"{', '.join(missing)}. The image is incomplete; refusing to start."
        )
    for binary in REQUIRED_BINARIES[queue]:
        minimum = MINIMUM_VERSIONS.get(binary)
        if minimum is None:
            continue
        found = _reported_version(binary)
        if found is None or found < minimum:
            wanted = ".".join(str(part) for part in minimum)
            got = ".".join(str(part) for part in found) if found else "unreadable"
            sys.exit(
                f"preflight: queue {queue!r} requires {binary} >= {wanted}, "
                f"the image carries {got}. Refusing to start."
            )


if __name__ == "__main__":
    import os

    run_preflight(os.getenv("WORKER_QUEUE", ""))
    print("preflight: ok")
