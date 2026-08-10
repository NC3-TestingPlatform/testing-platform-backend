"""The Celery application.

Pool and recycling policy follow the US #78 engine-integration ADR: prefork
(native-heavy engine work must not share a thread's fate), a soft time limit the
task can catch, a hard limit slightly above it so cleanup has room, and child
recycling so leaked native memory dies with the process.
"""

import os

from celery import Celery
from celery.signals import worker_init

from nc3_testing_platform.worker.preflight import run_preflight

# A task that overruns the soft limit gets SoftTimeLimitExceeded raised inside it
# and may still write partial results; the hard limit, 30 seconds later, kills the
# process outright. Keep the gap: a hard kill loses whatever the task was writing.
_SOFT_TIME_LIMIT = int(os.getenv("SCAN_TASK_TIMEOUT_SECONDS", "120"))
_TIME_LIMIT = _SOFT_TIME_LIMIT + 30

app = Celery(
    "nc3_testing_platform",
    broker=os.getenv("CELERY_BROKER_URL", "amqp://rabbitmq:rabbitmq@localhost:5672//"),
    backend=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
    include=["nc3_testing_platform.worker.tasks"],
)

app.conf.update(
    # Routing is by task name and owned here. The queues are the egress profiles;
    # the worker consuming each is pinned to it in infra/compose/celery.yml.
    task_routes={
        "scan.dispatch": {"queue": "platform"},
        "scan.persist": {"queue": "platform"},
        "scan.run_module": {"queue": "non-intrusive-scan"},
    },
    task_soft_time_limit=_SOFT_TIME_LIMIT,
    task_time_limit=_TIME_LIMIT,
    # Recycle after native-heavy work: a child that has run engines with C
    # extensions or subprocesses gets replaced instead of accumulating leaks.
    worker_max_tasks_per_child=int(os.getenv("CELERY_MAX_TASKS_PER_CHILD", "100")),
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
    run_preflight(os.getenv("WORKER_QUEUE", ""))
