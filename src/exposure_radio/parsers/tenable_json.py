"""Tenable Vulnerability Management export (JSON).

Accepts the record shape produced by the ``/vulns/export`` API: a JSON array
of finding records, each with ``asset``, ``plugin``, ``port``, ``scan``,
``severity`` and ``state`` members. A wrapper object is also accepted::

    {"export": {"status": "FINISHED", "chunks_available": [1, 2],
                "total_chunks": 2},
     "findings": [ ...records... ]}

The wrapper lets a caller pass the export status along with the records so
that an unfinished or short export is held instead of briefed.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from ..model import Asset, Export, ExportError, ExportManifest, Finding, PartialExportError
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

MAX_RECORDS = 2_000_000
MAX_JSON_BYTES = 512 * 1024 * 1024


def _manifest_from(wrapper: Dict[str, Any]) -> ExportManifest:
    meta = wrapper.get("export") or wrapper.get("manifest") or {}
    if not isinstance(meta, dict):
        meta = {}
    status = str(meta.get("status") or wrapper.get("status") or "UNKNOWN")[:32]
    chunks = meta.get("chunks_available")
    present = len(chunks) if isinstance(chunks, list) else to_int(meta.get("chunks_present"), 0, 10**6)
    expected = to_int(meta.get("total_chunks"), 0, 10**6)
    truncated = bool(to_bool(meta.get("truncated")) or to_bool(wrapper.get("truncated")))
    note = clean_name(meta.get("note") or "")
    return ExportManifest(status=status, chunks_expected=expected, chunks_present=present, truncated=truncated, note=note)


def _record_to_finding(
    record: Dict[str, Any], index: int, label: str, export: Export, stamps: List[str]
) -> Optional[Finding]:
    asset_raw = record.get("asset") or {}
    plugin_raw = record.get("plugin") or {}
    port_raw = record.get("port") or {}
    scan_raw = record.get("scan") or {}
    if not isinstance(asset_raw, dict) or not isinstance(plugin_raw, dict):
        return None
    if not isinstance(port_raw, dict):
        port_raw = {}
    if not isinstance(scan_raw, dict):
        scan_raw = {}

    for container in (record, plugin_raw, asset_raw):
        for key in container:
            if str(key).lower() in FREE_TEXT_FIELDS:
                export.text_fields_discarded += 1

    hostname = clean_hostname(asset_raw.get("hostname"))
    fqdn = clean_hostname(asset_raw.get("fqdn"))
    ipv4 = clean_ip(asset_raw.get("ipv4"))
    uuid = asset_raw.get("uuid") or asset_raw.get("id")
    asset_id = clean_name(uuid)[:64] if uuid else derive_asset_id(hostname, fqdn, ipv4)
    if not asset_id:
        return None
    os_values = asset_raw.get("operating_system")
    if isinstance(os_values, list):
        os_label = clean_name(os_values[0]) if os_values else None
    else:
        os_label = clean_name(os_values) if os_values else None
    tags_raw = asset_raw.get("tags") or []
    asset = Asset(
        asset_id=asset_id,
        hostname=hostname,
        fqdn=fqdn,
        ipv4=ipv4,
        operating_system=os_label or None,
        tags=clean_tags(tags_raw if isinstance(tags_raw, list) else []),
    )
    merge_asset(export.assets, asset)

    plugin_id = to_int(plugin_raw.get("id"), 1, 10**9)
    if plugin_id is None:
        return None
    severity = clean_severity(record.get("severity_id"))
    if severity is None:
        severity = clean_severity(record.get("severity"))
    if severity is None:
        severity = clean_severity(plugin_raw.get("risk_factor"))
    if severity is None:
        return None
    vpr_raw = plugin_raw.get("vpr") or {}
    vpr = to_float(vpr_raw.get("score"), 0.0, 10.0) if isinstance(vpr_raw, dict) else to_float(vpr_raw, 0.0, 10.0)
    stamp = clean_datetime(scan_raw.get("completed_at"))
    if stamp:
        stamps.append(stamp)
    return Finding(
        asset_id=asset_id,
        plugin_id=plugin_id,
        plugin_name=clean_name(plugin_raw.get("name")) or f"plugin {plugin_id}",
        severity=severity,
        cves=extract_cves(plugin_raw.get("cve") or ()),
        port=clean_port(port_raw.get("port")),
        protocol=clean_protocol(port_raw.get("protocol")),
        state=normalise_state(record.get("state")),
        first_found=clean_datetime(record.get("first_found")),
        last_found=clean_datetime(record.get("last_found")),
        cvss3=to_float(plugin_raw.get("cvss3_base_score"), 0.0, 10.0),
        vpr=vpr,
        exploit_available=to_bool(plugin_raw.get("exploit_available")),
        has_patch=to_bool(plugin_raw.get("has_patch")),
        record_ref=f"{label}:json#{index}",
    )


def parse(path: str, label: str) -> Export:
    with open(path, "rb") as handle:
        raw = handle.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ExportError(f"{label}: JSON export exceeds {MAX_JSON_BYTES} bytes")
    try:
        data = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ExportError(f"{label}: export is not UTF-8: {exc}") from None
    except json.JSONDecodeError as exc:
        raise PartialExportError(f"{label}: JSON is malformed or truncated at char {exc.pos}") from None

    export = Export(label=label, source=path, format="tenable-json")
    stamps: List[str] = []
    if isinstance(data, list):
        records: List[Any] = data
    elif isinstance(data, dict):
        export.manifest = _manifest_from(data)
        records = None  # type: ignore[assignment]
        for key in ("findings", "vulnerabilities", "records", "data"):
            if isinstance(data.get(key), list):
                records = data[key]
                break
        if records is None:
            raise ExportError(f"{label}: JSON object has no findings array")
    else:
        raise ExportError(f"{label}: JSON export must be an array or an object")
    if len(records) > MAX_RECORDS:
        raise ExportError(f"{label}: {len(records)} records exceeds the limit of {MAX_RECORDS}")

    for index, record in enumerate(records):
        export.records_seen += 1
        if not isinstance(record, dict):
            export.records_dropped += 1
            continue
        finding = _record_to_finding(record, index, label, export, stamps)
        if finding is None:
            export.records_dropped += 1
            continue
        export.findings.append(finding)
    export.findings.sort(key=finding_sort_key)
    return finalise(export, stamps)
