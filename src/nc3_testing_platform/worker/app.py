"""The Celery application.

Pool policy follows IDR-004 and the egress-queues ADR (Docmost — which
supersede the earlier US #78 Taiga text): the IO-bound scan queues run gevent
pools, file-analysis and platform run prefork. The time limits and child
recycling configured here are prefork-pool semantics — they protect
file-analysis and platform; gevent does not support them. On the scan queues,
per-engine timeout enforcement is the module runner's subprocess timeout +
kill (egress ADR), which lands with the B2b module contract.
"""

from celery import Celery
from celery.signals import worker_init

from nc3_testing_platform.core.settings import settings
from nc3_testing_platform.worker.preflight import run_preflight

# Prefork pools only (file-analysis, platform): a task that overruns the soft
# limit gets SoftTimeLimitExceeded raised inside it and may still write partial
# results; the hard limit, 30 seconds later, kills the process outright. Keep
# the gap: a hard kill loses whatever the task was writing. The gevent scan
# pools ignore these limits — their engines are bounded by the runner's
# subprocess timeout instead.
_SOFT_TIME_LIMIT = settings.scan_task_timeout_seconds
_TIME_LIMIT = _SOFT_TIME_LIMIT + 30

app = Celery(
    "nc3_testing_platform",
    broker=settings.celery_broker_url,
    backend=settings.redis_url,
    include=["nc3_testing_platform.worker.tasks"],
)

app.conf.update(
    # Routing is by task name and owned here. The queues are the egress profiles;
    # the worker consuming each is pinned to it in infra/compose/celery.yml.
    # `scan.run_module`'s row is a default only: dispatch overrides the queue
    # per send from the module's declaration (`Roster.queue_for`), because one
    # task name serves all three module queues and a static route cannot.
    task_routes={
        "scan.dispatch": {"queue": "platform"},
        "scan.run_module": {"queue": "non-intrusive-scan"},
        "scan.reap": {"queue": "platform"},
        "scan.heartbeat": {"queue": "platform"},
    },
    # The reaper and heartbeat sweeps (B8 / US #84); beat runs on the platform
    # image with exactly one replica (infra/compose/celery.yml).
    beat_schedule={
        "scan-reap": {
            "task": "scan.reap",
            "schedule": settings.scan_sweep_interval_seconds,
        },
        "scan-heartbeat": {
            "task": "scan.heartbeat",
            "schedule": settings.scan_heartbeat_interval_seconds,
        },
    },
    # A task someone adds without a route must land on a queue a worker
    # consumes, not on Celery's built-in default that nothing reads.
    task_default_queue="platform",
    task_soft_time_limit=_SOFT_TIME_LIMIT,
    task_time_limit=_TIME_LIMIT,
    # Recycle after native-heavy work: a child that has run engines with C
    # extensions or subprocesses gets replaced instead of accumulating leaks.
    worker_max_tasks_per_child=settings.celery_max_tasks_per_child,
    task_track_started=True,
)


@worker_init.connect
def _preflight(**_kwargs: object) -> None:
    """Fail the worker loudly at startup when its image is missing tools.

    Runs before the pool forks. A worker whose egress profile requires external
    binaries (nmap, the subdomain tools, openssl >= 3.5) must refuse to start
    without them rather than let `detect_tools()`-style silent skipping produce
    quietly incomplete scans (US #78 ADR).
    """
    run_preflight(settings.worker_queue)
