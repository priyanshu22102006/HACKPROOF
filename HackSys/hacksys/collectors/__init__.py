"""Collectors: each one is a named background thread that writes events."""

from .base import Collector
from .clipboard import ClipboardCollector
from .filesystem import FilesystemCollector
from .git_activity import GitCollector
from .gpg_watch import GpgCollector
from .integrity import IntegrityCollector
from .process_watch import ProcessCollector

__all__ = [
    "Collector",
    "ClipboardCollector",
    "FilesystemCollector",
    "GitCollector",
    "GpgCollector",
    "IntegrityCollector",
    "ProcessCollector",
]
