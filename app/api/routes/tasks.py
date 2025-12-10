"""Task routes - Celery task monitoring"""
from fastapi import APIRouter, HTTPException
import logging

from app.workers.celery_app import celery_app

router = APIRouter(prefix="/api/v1/tasks", tags=["tasks"])
logger = logging.getLogger(__name__)


@router.get("/running")
async def get_running_tasks():
    """Return currently active/running Celery tasks across workers"""
    try:
        inspector = celery_app.control.inspect()
        active = inspector.active() or {}

        running = []
        for worker, tasks in (active.items() if isinstance(active, dict) else []):
            for t in tasks:
                running.append({
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "args": t.get("args"),
                    "kwargs": t.get("kwargs"),
                    "worker": worker,
                    "started_at": t.get("time_start") or t.get("started"),
                    "delivery_info": t.get("delivery_info"),
                })

        return running
    except Exception as e:
        logger.exception("Error fetching running tasks")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/queue")
async def get_task_queue():
    """Return reserved and scheduled tasks (tasks waiting in queue)"""
    try:
        inspector = celery_app.control.inspect()
        reserved = inspector.reserved() or {}
        scheduled = inspector.scheduled() or {}

        queued = []

        # Reserved tasks are those reserved by workers but not yet active
        for worker, tasks in (reserved.items() if isinstance(reserved, dict) else []):
            for t in tasks:
                queued.append({
                    "id": t.get("id"),
                    "name": t.get("name"),
                    "args": t.get("args"),
                    "kwargs": t.get("kwargs"),
                    "worker": worker,
                    "enqueued_at": t.get("time_start") or None,
                })

        # Scheduled tasks (eta/countdown)
        for worker, tasks in (scheduled.items() if isinstance(scheduled, dict) else []):
            for t in tasks:
                # scheduled entries from celery have 'eta' and 'request'
                request = t.get('request') if isinstance(t, dict) else None
                if request and isinstance(request, dict):
                    queued.append({
                        "id": request.get("id"),
                        "name": request.get("name"),
                        "args": request.get("args"),
                        "kwargs": request.get("kwargs"),
                        "worker": worker,
                        "enqueued_at": t.get("eta") or None,
                    })
                else:
                    queued.append({
                        "id": t.get("id"),
                        "name": t.get("name"),
                        "args": t.get("args"),
                        "kwargs": t.get("kwargs"),
                        "worker": worker,
                        "enqueued_at": t.get("eta") or None,
                    })

        return queued
    except Exception as e:
        logger.exception("Error fetching task queue")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{task_id}")
async def get_task_status(task_id: str):
    """Get the status and result of a specific task by ID"""
    try:
        from celery.result import AsyncResult
        
        result = AsyncResult(task_id, app=celery_app)
        
        response = {
            "task_id": task_id,
            "state": result.state,
            "status": result.status,
        }
        
        # Include result if task is successful
        if result.successful():
            response["result"] = result.result
        
        # Include error info if task failed
        if result.failed():
            response["error"] = str(result.info) if result.info else "Unknown error"
        
        # Include progress info if available
        if result.state == 'PROGRESS':
            response["info"] = result.info
        
        return response
    except Exception as e:
        logger.exception(f"Error fetching task status for {task_id}")
        raise HTTPException(status_code=500, detail=str(e))
