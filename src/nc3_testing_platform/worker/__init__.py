"""Celery worker package.

The broker is RabbitMQ and the result backend is Redis; both addresses come
from the environment. Task-to-queue routing is fixed in `app.py` — a task never
selects its own queue, so the egress profile a job runs under is decided here
and not by the module being executed (egress-segregated task queues, US #74).
"""
