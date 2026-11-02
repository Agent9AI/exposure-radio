"""Export parsers.

Three formats are supported and all of them go through the same discipline:
size limits before reading, typed cleaning of every retained value, and an
integrity report that says whether the export is complete. Free text fields
(plugin output, descriptions, solutions, banners) are never read.
"""

from __future__ import annotations

import os
from typing import Optional

from ..model import Export, ExportError
from . import nessus, tenable_csv, tenable_json

MAX_EXPORT_BYTES = 512 * 1024 * 1024


def sniff_format(path: str) -> str:
    """Guess the export format from the extension, then the first bytes."""
    lower = path.lower()
    if lower.endswith(".json") or lower.endswith(".ndjson"):
        return "tenable-json"
    if lower.endswith(".nessus") or lower.endswith(".xml"):
        return "nessus"
    if lower.endswith(".csv"):
        return "tenable-csv"
    with open(path, "rb") as handle:
        head = handle.read(512).lstrip()
    if head.startswith(b"[") or head.startswith(b"{"):
        return "tenable-json"
    if head.startswith(b"<"):
        return "nessus"
    return "tenable-csv"


def load_export(path: str, label: str, fmt: Optional[str] = None) -> Export:
    """Parse one export file into an :class:`Export`.

    Raises :class:`ExportError` when the file cannot be read safely and
    :class:`PartialExportError` when it is readable but incomplete.
    """
    if not os.path.isfile(path):
        raise ExportError(f"{label}: no such file: {path}")
    size = os.path.getsize(path)
    if size > MAX_EXPORT_BYTES:
        raise ExportError(f"{label}: export is {size} bytes; the limit is {MAX_EXPORT_BYTES}")
    fmt = fmt or sniff_format(path)
    if fmt == "tenable-json":
        return tenable_json.parse(path, label)
    if fmt == "nessus":
        return nessus.parse(path, label)
    if fmt == "tenable-csv":
        return tenable_csv.parse(path, label)
    raise ExportError(f"{label}: unknown export format {fmt!r}")


__all__ = ["load_export", "sniff_format", "MAX_EXPORT_BYTES"]
