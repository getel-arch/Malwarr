"""Task package exports.

This package exposes the task callables so other modules can import
them via `from app.workers.tasks import analyze_sample_with_pe`.
"""

from .pe_task import analyze_sample_with_pe
from .elf_task import analyze_sample_with_elf
from .capa_task import analyze_sample_with_capa

__all__ = [
	"analyze_sample_with_pe",
	"analyze_sample_with_elf",
	"analyze_sample_with_capa",
]