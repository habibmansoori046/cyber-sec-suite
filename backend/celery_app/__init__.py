"""Celery configuration — Redis broker, task routing, beat schedule."""

import os
from celery import Celery
from celery.schedules import crontab

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "cybersec",
    broker=REDIS_URL,
    backend=REDIS_URL,
    include=["celery_app.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=600,           # 10 min hard limit per task
    task_soft_time_limit=540,      # 9 min soft limit (for graceful cleanup)
    worker_prefetch_multiplier=1,  # One task at a time per worker slot
    worker_max_tasks_per_child=50, # Restart worker processes after 50 tasks (prevent memory leaks)
    result_expires=3600,           # Results expire after 1 hour
)

# ──── Task routing ────────────────────────────────────────────
celery_app.conf.task_routes = {
    "celery_app.tasks.run_scan_task": {"queue": "scans"},
    "celery_app.tasks.run_yara_scan_task": {"queue": "forensics"},
    "celery_app.tasks.generate_report_task": {"queue": "reports"},
}

# ──── Beat schedule (periodic tasks) ─────────────────────────
celery_app.conf.beat_schedule = {
    "cleanup-old-scan-results": {
        "task": "celery_app.tasks.cleanup_old_results",
        "schedule": crontab(hour=3, minute=0),  # Daily at 3 AM UTC
    },
}
