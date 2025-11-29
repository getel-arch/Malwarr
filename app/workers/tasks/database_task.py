import logging
from celery import Task
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.storage import FileStorage
from app.analyzers.capa.capa_analyzer import CapaAnalyzer

logger = logging.getLogger(__name__)

class DatabaseTask(Task):
    """Base task that provides database session"""
    _db = None
    _storage = None
    _capa_analyzer = None

    @property
    def db(self) -> Session:
        if self._db is None:
            self._db = SessionLocal()
        return self._db

    @property
    def storage(self) -> FileStorage:
        if self._storage is None:
            self._storage = FileStorage()
        return self._storage

    @property
    def capa_analyzer(self) -> CapaAnalyzer:
        if self._capa_analyzer is None:
            self._capa_analyzer = CapaAnalyzer()
        return self._capa_analyzer

    def after_return(self, *args, **kwargs):
        """Clean up database session after task completes"""
        if self._db is not None:
            self._db.close()
            self._db = None