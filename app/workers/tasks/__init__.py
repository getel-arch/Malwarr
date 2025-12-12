"""Task package exports.

This package exposes the task callables so other modules can import
them via `from app.workers.tasks import analyze_sample_with_pe`.
"""

from .pe_task import analyze_sample_with_pe
from .elf_task import analyze_sample_with_elf
from .capa_task import analyze_sample_with_capa
from .ingestion_task import ingest_file_task
from .vt_task import analyze_sample_with_virustotal
from .strings_task import analyze_sample_with_strings
from .vt_polling_task import poll_pending_virustotal_analyses
from .magika_task import analyze_sample_with_magika

__all__ = [
	"analyze_sample_with_pe",
	"analyze_sample_with_elf",
	"analyze_sample_with_capa",
	"ingest_file_task",
	"analyze_sample_with_virustotal",
	"analyze_sample_with_strings",
	"poll_pending_virustotal_analyses",
	"analyze_sample_with_magika",
]