"""A test-only engine that shells out to a grandchild, then stalls.

Kept out of the shipped package on purpose: it spawns a detached ``sleep``
and blocks, which has no place in an installed module. It exists solely for
the runner's process-group-kill regression test — the spawn child inherits
the parent's ``sys.path`` (multiprocessing spawn propagates it), so this
module is importable by entry string ``grandchild_engine:assess`` inside the
child the runner starts.
"""

import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class _Report:
    domain: str


def assess(
    domain: str,
    *,
    timeout: float = 5.0,
    pidfile: str,
    progress_cb: Callable[[str], None] | None = None,
) -> _Report:
    """Spawn a long ``sleep`` grandchild, record its PID, then block.

    :param domain: Ignored beyond being echoed; keeps the engine signature.
    :param timeout: Ignored; present for signature parity.
    :param pidfile: Path the spawned grandchild's PID is written to, so the
        test can assert it dies when the runner kills the process group.
    :param progress_cb: Optional; emits one line before stalling.
    """
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
    with open(pidfile, "w", encoding="utf-8") as handle:
        handle.write(str(child.pid))
        handle.flush()
    if progress_cb is not None:
        progress_cb(f"spawned grandchild for {domain}")
    time.sleep(300)
    return _Report(domain=domain)  # pragma: no cover - the runner kills us first
