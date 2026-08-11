"""A miniature engine for the no-op module, in the real engines' shape.

`assess()` copies the convention every NC3 engine follows —
``assess(target, *, ..., timeout: float, progress_cb) -> report`` with a
plain-dataclass report — so the no-op module can exercise the *whole*
execution path: child-process import, callback marshalling, ``asdict()``
report transfer. The `delay` knob exists so tests (and the curious) can
watch the runner's budget kill a compliant engine; `fail` exists to watch
a child-side `ValueError` cross the pipe.
"""

import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

STEPS = ("Validating input", "Doing nothing, thoroughly", "Composing the result")


@dataclass(frozen=True)
class NoopReport:
    """The engine report: plain data, exactly what `asdict()` was made for."""

    domain: str
    steps: tuple[str, ...]
    timeout: float
    verdict: str = "nothing to report"


def assess(
    domain: str,
    *,
    timeout: float = 5.0,
    delay: float = 0.0,
    fail: bool = False,
    spawn_child_pidfile: str | None = None,
    progress_cb: Callable[[str], None] | None = None,
) -> NoopReport:
    """Inspect *domain* by doing nothing to it, loudly.

    :param domain: Target domain; must be non-empty.
    :param timeout: Per-probe timeout in seconds — accepted and echoed into
        the report, as there is no probe to time out.
    :param delay: Seconds to sleep mid-run, so a caller can watch the
        runner's budget enforcement work.
    :param fail: Raise ``ValueError`` after the first progress line, so a
        caller can watch a child-side error being marshalled.
    :param spawn_child_pidfile: If set, shell out to a long-lived ``sleep``
        subprocess (a stand-in for the binaries real engines spawn), write
        its PID to this path, and stall — so a test can prove the runner's
        budget kill reaches the whole process group, not just this child.
    :param progress_cb: Optional callable invoked with a short status string
        before each step.
    :returns: A fully populated :class:`NoopReport`.
    :raises ValueError: If *domain* is empty or *fail* was requested.
    """
    if not domain:
        raise ValueError("domain must be non-empty.")
    if spawn_child_pidfile is not None:
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(300)"])
        with open(spawn_child_pidfile, "w", encoding="utf-8") as handle:
            handle.write(str(child.pid))
        time.sleep(300)
    for step in STEPS:
        if progress_cb is not None:
            progress_cb(f"{step} for {domain} …")
        if fail:
            raise ValueError("the no-op engine failed on request.")
        if delay:
            time.sleep(delay)
    return NoopReport(domain=domain, steps=STEPS, timeout=timeout)
