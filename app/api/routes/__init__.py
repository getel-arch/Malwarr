"""API routes package"""
from .system import router as system_router, health_router
from .samples import router as samples_router
from .analysis import router as analysis_router
from .stats import router as stats_router
from .capa_management import router as capa_management_router
from .tasks import router as tasks_router
from .search import router as search_router

__all__ = [
    "system_router",
    "health_router",
    "samples_router",
    "analysis_router",
    "stats_router",
    "capa_management_router",
    "tasks_router",
    "search_router"
]
