"""
Celery configuration for background task processing
"""
from celery import Celery
from app.config import settings

# Create Celery instance
celery_app = Celery(
    "malwarr",
    broker=settings.redis_url,
    backend=settings.redis_url,
    include=['app.workers.tasks']
)

# Celery configuration
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3000,  # 50 minutes soft limit
    worker_prefetch_multiplier=4,  # Prefetch more tasks for better throughput
    worker_max_tasks_per_child=50,  # Restart worker after 50 tasks to prevent memory leaks
    task_acks_late=True,  # Acknowledge tasks after completion, not before
    task_reject_on_worker_lost=True,  # Requeue tasks if worker crashes
    # Task routing - prioritize ingestion tasks
    task_routes={
        'ingest_file': {'queue': 'ingestion'},
        'analyze_sample_with_capa': {'queue': 'analysis'},
        'analyze_sample_with_pe': {'queue': 'analysis'},
        'analyze_sample_with_elf': {'queue': 'analysis'},
    },
    # Rate limits to prevent overwhelming the system
    task_annotations={
        'ingest_file': {'rate_limit': '10/s'},  # Max 10 ingestions per second
    },
    # Result expiration
    result_expires=3600,  # Results expire after 1 hour
    # Beat schedule for periodic tasks
    beat_schedule={
        'poll-virustotal-analyses': {
            'task': 'app.workers.tasks.vt_polling_task',
            'schedule': 300.0,  # Run every 5 minutes (300 seconds)
        },
    },
)
