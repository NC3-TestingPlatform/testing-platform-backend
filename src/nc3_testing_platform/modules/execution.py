"""The shared engine runner: one killable child process per engine call.

The egress-queues ADR sets the execution model every module uses: the
engine is imported **in a child process** which calls its `assess()`
(import-as-library, no CLI shelling), under a wall-clock budget the parent
enforces by killing the child on overrun. The child streams progress lines
back over a pipe and returns the engine report as a
`dataclasses.asdict()` dict — never a pickled engine object — so the
parent needs nothing from the engine package to receive a result.

Everything crossing the pipe is a JSON string: progress lines, the report,
and child-side errors. That is the marshalling rule made structural — an
engine dataclass that cannot survive ``asdict()`` + JSON is a bug caught
here, not in the database layer.

The child comes from a ``spawn`` context, deliberately: a fresh
interpreter, not a fork of the worker. That keeps the runner correct under
both pools IDR-004 assigns (gevent for the scan queues, prefork for
file-analysis) — forking a gevent-monkey-patched worker would clone its
event loop into the child. Celery's time limits remain a backstop; the
budget here is the engine bound.
"""

import json
import math
import multiprocessing
import multiprocessing.process
import os
import signal
import time
from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, is_dataclass
from importlib import import_module
from logging import getLogger
from multiprocessing.connection import Connection
from typing import Any

from nc3_testing_platform.modules.contract import ProgressEmitter

logger = getLogger(__name__)

# How long a terminated child gets to die before it is killed outright.
_DEFAULT_GRACE = 5.0

# POSIX lets us put the child in its own process group and signal the whole
# group, so an engine that shells out (subfinder, nmap, ffuf …) dies with it.
# Elsewhere we fall back to signalling the child alone.
_POSIX = os.name == "posix"


@dataclass(frozen=True)
class EngineOutcome:
    """What one child-process engine run produced, exactly one way.

    Either `report` is set (the ``asdict()`` dict of the engine's report)
    or the run failed: `timed_out` for a budget kill, `error` carrying the
    child-side exception rendered as ``"Type: message"`` — or both unset
    fields on a child that died without a word, which `error` also names.
    """

    report: Mapping[str, Any] | None = None
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        """Whether the run produced a report."""
        return self.report is not None and self.error is None and not self.timed_out

    def unwrap(self) -> Mapping[str, Any]:
        """The report, or a `RuntimeError` a module runner can let propagate.

        The platform maps the raised message onto the failed task's
        `status_reason`, so it is written for the task view, not a log.
        """
        if self.report is not None and self.ok:
            return self.report
        raise RuntimeError(self.error or "the engine produced no result.")


def _progress_writer(conn: Connection, channel: str) -> Callable[..., None]:
    """A child-side callback of any arity that writes one pipe line per call.

    Mirrors `ProgressEmitter.extra_cb`: positional arguments are stringified
    and joined, ``None`` arguments dropped. A broken pipe is swallowed —
    progress is advisory and must never fail the engine run that emits it.
    """

    def _callback(*args: object) -> None:
        rendered = " ".join(str(arg) for arg in args if arg is not None)
        try:
            conn.send(
                json.dumps(
                    {
                        "kind": "progress",
                        "channel": channel,
                        "message": rendered or channel,
                    }
                )
            )
        except (OSError, ValueError):
            pass

    return _callback


def _child_main(conn: Connection, spec: dict[str, Any]) -> None:
    """The child process: import the engine, call it, marshal the outcome.

    `spec` is plain data (it crosses the spawn boundary): the ``module:attr``
    entry to call, its args/kwargs, and the names of the callback keyword
    arguments to inject as pipe writers. Any exception — import failure, bad
    entry, engine error — is rendered to one error line; the parent never
    unpickles an exception object.
    """
    # A new session makes this child a process-group leader (pgid == pid), so
    # the parent can signal the whole group and take any subprocess the engine
    # spawned with it. Best-effort: a child that cannot detach still runs.
    if _POSIX:
        try:
            os.setsid()
        except OSError:
            pass
    try:
        module_name, _, attr = spec["entry"].partition(":")
        function = getattr(import_module(module_name), attr)
        kwargs = dict(spec["kwargs"])
        for callback_name in spec["callbacks"]:
            channel = callback_name.removesuffix("_cb") or callback_name
            kwargs[callback_name] = _progress_writer(conn, channel)
        report = function(*spec["args"], **kwargs)
        if is_dataclass(report) and not isinstance(report, type):
            payload: Any = asdict(report)
        elif isinstance(report, Mapping):
            payload = dict(report)
        else:
            raise TypeError(
                f"engine returned {type(report).__name__}; a report must be a "
                "dataclass or a mapping."
            )
        # default=str renders what asdict() leaves non-JSON (enums, datetimes)
        # instead of refusing the report over one exotic field.
        conn.send(json.dumps({"kind": "result", "report": payload}, default=str))
    except BaseException as exc:  # the boundary reports failures, never raises
        try:
            conn.send(
                json.dumps(
                    {"kind": "error", "type": type(exc).__name__, "message": str(exc)}
                )
            )
        except (OSError, ValueError):
            # The parent already closed the pipe (e.g. after a budget kill);
            # there is no one to tell. Exit quietly rather than die with a
            # chained traceback.
            pass
    finally:
        conn.close()


def _signal_group(pid: int | None, sig: int) -> None:
    """Signal the child's whole process group on POSIX, else the child alone.

    The child made itself a group leader (`os.setsid`), so its pgid equals
    its pid and one `killpg` reaches every subprocess the engine spawned. A
    group that has already exited (`ProcessLookupError`) is nothing to do.
    """
    if pid is None:
        return
    try:
        if _POSIX:
            os.killpg(pid, sig)
        else:
            os.kill(pid, sig)
    except (ProcessLookupError, OSError):
        pass


def _reap(process: multiprocessing.process.BaseProcess, grace: float) -> None:
    """Terminate the child's group, then kill it, then join: nothing outlives.

    Signalling the process group — not just the runner child — is what makes
    the budget real for engines that shell out; the plain `terminate()`/
    `kill()` fallback covers a child that could not detach and platforms
    without process groups.
    """
    if process.is_alive():
        _signal_group(process.pid, signal.SIGTERM)
        process.terminate()
        process.join(grace)
    if process.is_alive():
        _signal_group(process.pid, signal.SIGKILL)
        process.kill()
    # No group signal after this join: it reaps the child and releases its PID,
    # which the OS may reuse — signalling that PID's group could hit a stranger.
    # The SIGKILL above, sent while the leader was still alive, already took the
    # whole group (grandchildren included) down with it.
    process.join()


def run_engine(
    entry: str,
    *,
    args: tuple[Any, ...] = (),
    kwargs: Mapping[str, Any] | None = None,
    callbacks: tuple[str, ...] = ("progress_cb",),
    budget: float,
    grace: float = _DEFAULT_GRACE,
    progress: ProgressEmitter,
) -> EngineOutcome:
    """Run one engine call in a killable child and return its outcome.

    `entry` is ``"package.module:function"`` — the same shape as an entry
    point — resolved *in the child*, so the worker process never imports the
    engine. `args`/`kwargs` must be plain data; the engine's own ``timeout``
    (per-probe, from `ScanInput.timeout`) travels inside `kwargs` like any
    other parameter. `callbacks` names the callback keyword arguments to
    inject (`progress_cb` for every engine; add subdomainenum's ``debug_cb``
    and friends per module) — each becomes a pipe writer whose lines are
    re-emitted on `progress`, parent-side, as they arrive.

    `budget` is the wall-clock engine bound of the egress ADR: when it
    expires the child is terminated (then killed after `grace`) and the
    outcome says `timed_out` instead of raising, so the module runner
    decides what a timeout means for its task.
    """
    if not math.isfinite(budget) or budget <= 0:
        raise ValueError("`budget` must be a positive, finite number of seconds.")
    spec = {
        "entry": entry,
        "args": list(args),
        "kwargs": dict(kwargs or {}),
        "callbacks": list(callbacks),
    }
    context = multiprocessing.get_context("spawn")
    parent_conn, child_conn = context.Pipe(duplex=False)
    process = context.Process(target=_child_main, args=(child_conn, spec), daemon=True)
    process.start()
    child_conn.close()

    deadline = time.monotonic() + budget
    report: Mapping[str, Any] | None = None
    error: str | None = None
    timed_out = False
    try:
        while report is None and error is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not parent_conn.poll(max(remaining, 0)):
                timed_out = True
                error = f"engine overran its {budget:g}s budget and was killed."
                break
            try:
                message = json.loads(parent_conn.recv())
            except EOFError:
                error = (
                    "engine process exited without a result "
                    f"(exit code {process.exitcode})."
                )
                break
            try:
                kind = message["kind"]
                if kind == "progress":
                    # Delivery is advisory; ProgressEmitter.emit swallows a
                    # failing sink, so a broken sink never fails a healthy run.
                    progress.emit(message["message"], channel=message["channel"])
                elif kind == "result":
                    report = message["report"]
                else:
                    error = f"{message['type']}: {message['message']}"
            except (KeyError, TypeError):
                error = f"engine sent a malformed message: {message!r}"
                break
    finally:
        _reap(process, grace)
        parent_conn.close()
    if error is not None:
        logger.warning("engine %s failed: %s", entry, error)
    return EngineOutcome(report=report, timed_out=timed_out, error=error)
