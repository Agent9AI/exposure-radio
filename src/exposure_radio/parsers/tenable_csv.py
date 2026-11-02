"""Tenable CSV export parser (Tenable Vulnerability Management or Nessus CSV).

Column names differ between products and versions, so headers are matched
through an alias table after normalisation (lower case, underscores and dots
become spaces). Free text columns (plugin output, description, synopsis,
solution, see also) are recognised only to be counted; their cells are never
read into the model.
"""

from __future__ import annotations

import csv
import re
from typing import Dict, List, Optional

from ..model import Asset, Export, ExportError, Finding
from ..sanitize import (
    clean_datetime,
    clean_hostname,
    clean_ip,
    clean_name,
    clean_port,
    clean_protocol,
    clean_severity,
    extract_cves,
    to_bool,
    to_float,
    to_int,
)
from .common import FREE_TEXT_FIELDS, clean_tags, derive_asset_id, finalise, finding_sort_key, merge_asset, normalise_state

MAX_FIELD_BYTES = 4 * 1024 * 1024
MAX_ROWS = 2_000_000
MAX_COLUMNS = 256

_ALIASES: Dict[str, str] = {}
for canonical, names in {
    "asset_id": ("asset uuid", "asset id", "uuid", "asset"),
    "hostname": ("host", "hostname", "asset hostname", "host name", "netbios name"),
    "fqdn": ("fqdn", "asset fqdn", "dns name"),
    "ip": ("ip address", "ipv4", "ip", "asset ipv4", "ipv4 address"),
    "plugin_id": ("plugin id", "plugin", "pluginid"),
    "plugin_name": ("plugin name", "name"),
    "severity": ("severity", "risk", "risk factor", "severity id"),
    "cve": ("cve", "cves"),
    "cvss3": ("cvss v3 0 base score", "cvss3 base score", "cvss v3 base score", "cvssv3 base score", "cvss v3.0 base score", "cvss3"),
    "vpr": ("vpr score", "vpr"),
    "port": ("port",),
    "protocol": ("protocol",),
    "state": ("state", "vulnerability state", "status"),
    "first_found": ("first seen", "first found", "first discovered"),
    "last_found": ("last seen", "last found", "last observed"),
    "exploit": ("exploit available", "exploit", "exploitable"),
    "has_patch": ("patch available", "has patch"),
    "scan_completed": ("last scan", "scan completed", "scan end", "scan completed at"),
    "os": ("operating system", "os"),
    "tags": ("asset tags", "tags"),
}.items():
    for alias in names:
        _ALIASES[alias] = canonical

_HEADER_WS = re.compile(r"[\s_.]+")


def _normalise_header(text: str) -> str:
    return _HEADER_WS.sub(" ", text.strip().lower().replace("﻿", "")).strip()


def _map_columns(header: List[str]) -> Dict[str, int]:
    columns: Dict[str, int] = {}
    free_text: List[int] = []
    for index, raw in enumerate(header):
        name = _normalise_header(raw)
        if name in FREE_TEXT_FIELDS:
            free_text.append(index)
            continue
        canonical = _ALIASES.get(name)
        if canonical and canonical not in columns:
            columns[canonical] = index
    columns["__free_text_count__"] = len(free_text)
    return columns


def parse(path: str, label: str) -> Export:
    old_limit = csv.field_size_limit()
    csv.field_size_limit(MAX_FIELD_BYTES)
    export = Export(label=label, source=path, format="tenable-csv")
    stamps: List[str] = []
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as handle:
            reader = csv.reader(handle)
            try:
                header = next(reader)
            except StopIteration:
                raise ExportError(f"{label}: CSV export is empty") from None
            except csv.Error as exc:
                raise ExportError(f"{label}: CSV header unreadable: {exc}") from None
            if len(header) > MAX_COLUMNS:
                raise ExportError(f"{label}: CSV has more than {MAX_COLUMNS} columns")
            columns = _map_columns(header)
            if "plugin_id" not in columns or "severity" not in columns:
                raise ExportError(f"{label}: CSV lacks a plugin id or severity column")
            if not any(k in columns for k in ("asset_id", "hostname", "fqdn", "ip")):
                raise ExportError(f"{label}: CSV lacks any asset identifier column")
            free_text_count = columns.pop("__free_text_count__")
            width = len(header)
            last_short: Optional[int] = None
            row_count = 0
            try:
                for index, row in enumerate(reader):
                    row_count += 1
                    if row_count > MAX_ROWS:
                        raise ExportError(f"{label}: CSV has more than {MAX_ROWS} rows")
                    export.records_seen += 1
                    if len(row) < width:
                        last_short = index
                        export.records_dropped += 1
                        continue
                    last_short = None
                    export.text_fields_discarded += free_text_count
                    finding = _row_to_finding(row, columns, index, label, export, stamps)
                    if finding is None:
                        export.records_dropped += 1
                        continue
                    export.findings.append(finding)
            except csv.Error as exc:
                raise ExportError(f"{label}: CSV row unreadable: {exc}") from None
            if last_short is not None:
                export.integrity.fail("final CSV row is short: the export looks truncated")
    finally:
        csv.field_size_limit(old_limit)
    export.findings.sort(key=finding_sort_key)
    return finalise(export, stamps)


def _cell(row: List[str], columns: Dict[str, int], key: str) -> Optional[str]:
    index = columns.get(key)
    if index is None or index >= len(row):
        return None
    value = row[index]
    return value if value != "" else None


def _row_to_finding(
    row: List[str], columns: Dict[str, int], index: int, label: str, export: Export, stamps: List[str]
) -> Optional[Finding]:
    hostname = clean_hostname(_cell(row, columns, "hostname"))
    fqdn = clean_hostname(_cell(row, columns, "fqdn"))
    ipv4 = clean_ip(_cell(row, columns, "ip"))
    if hostname is None and ipv4 is None:
        # Nessus CSV puts whichever it has in the Host column.
        ipv4 = clean_ip(_cell(row, columns, "hostname"))
    asset_raw = _cell(row, columns, "asset_id")
    asset_id = clean_name(asset_raw)[:64] if asset_raw else derive_asset_id(hostname, fqdn, ipv4)
    if not asset_id:
        return None
    plugin_id = to_int(_cell(row, columns, "plugin_id"), 1, 10**9)
    severity = clean_severity(_cell(row, columns, "severity"))
    if plugin_id is None or severity is None:
        return None
    tags_cell = _cell(row, columns, "tags") or ""
    tags = clean_tags(part.strip() for part in tags_cell.split(",") if part.strip())
    merge_asset(
        export.assets,
        Asset(
            asset_id=asset_id,
            hostname=hostname,
            fqdn=fqdn,
            ipv4=ipv4,
            operating_system=clean_name(_cell(row, columns, "os")) or None,
            tags=tags,
        ),
    )
    stamp = clean_datetime(_cell(row, columns, "scan_completed"))
    if stamp:
        stamps.append(stamp)
    return Finding(
        asset_id=asset_id,
        plugin_id=plugin_id,
        plugin_name=clean_name(_cell(row, columns, "plugin_name")) or f"plugin {plugin_id}",
        severity=severity,
        cves=extract_cves(_cell(row, columns, "cve") or ""),
        port=clean_port(_cell(row, columns, "port")),
        protocol=clean_protocol(_cell(row, columns, "protocol")),
        state=normalise_state(_cell(row, columns, "state")),
        first_found=clean_datetime(_cell(row, columns, "first_found")),
        last_found=clean_datetime(_cell(row, columns, "last_found")),
        cvss3=to_float(_cell(row, columns, "cvss3"), 0.0, 10.0),
        vpr=to_float(_cell(row, columns, "vpr"), 0.0, 10.0),
        exploit_available=to_bool(_cell(row, columns, "exploit")),
        has_patch=to_bool(_cell(row, columns, "has_patch")),
        record_ref=f"{label}:csv#{index}",
    )
