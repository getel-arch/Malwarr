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
    worker_prefetch_multiplier=1,  # Process one task at a time
    worker_max_tasks_per_child=10,  # Restart worker after 10 tasks to prevent memory leaks
)
