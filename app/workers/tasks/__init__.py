"""Task package exports.

This package exposes the task callables so other modules can import
them via `from app.workers.tasks import analyze_sample_with_pe`.
"""

from .pe_task import analyze_sample_with_pe
from .elf_task import analyze_sample_with_elf
from .capa_task import analyze_sample_with_capa
from .ingestion_task import ingest_file_task
from .vt_task import analyze_sample_with_virustotal, poll_pending_virustotal_analyses, upload_sample_to_virustotal_task
from .strings_task import analyze_sample_with_strings
from .magika_task import analyze_sample_with_magika
from .archive_task import extract_archive_task

__all__ = [
	"analyze_sample_with_pe",
	"analyze_sample_with_elf",
	"analyze_sample_with_capa",
	"ingest_file_task",
	"analyze_sample_with_virustotal",
	"analyze_sample_with_strings",
	"poll_pending_virustotal_analyses",
	"upload_sample_to_virustotal_task",
	"analyze_sample_with_magika",
	"extract_archive_task",
]