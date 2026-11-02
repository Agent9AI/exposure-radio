"""Nessus ``.nessus`` (XML) parser, hardened.

The file is streamed through the standard-library expat parser with:

* ``DOCTYPE`` rejected outright, so there is no DTD, no entity expansion
  and no external entity;
* entity declarations and external entity references rejected as well,
  belt and braces;
* parameter entity parsing disabled;
* a byte limit, an element depth limit and a per-element text cap.

Only allowlisted elements have their text read. ``plugin_output``,
``description``, ``synopsis``, ``solution``, ``see_also`` and the whole
``Policy`` section are never read: their characters are discarded as they
stream past.
"""

from __future__ import annotations

import xml.parsers.expat as expat
from typing import Dict, List, Optional

from ..model import Asset, Export, ExportError, Finding, PartialExportError
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
from .common import derive_asset_id, finalise, finding_sort_key, merge_asset

MAX_XML_BYTES = 512 * 1024 * 1024
MAX_DEPTH = 32
MAX_TEXT = 256
MAX_HOSTS = 500_000
MAX_ITEMS = 5_000_000
CHUNK = 1024 * 1024

_HOST_TAGS = {
    "host-ip": "ip",
    "host-fqdn": "fqdn",
    "host-rdns": "fqdn",
    "hostname": "hostname",
    "netbios-name": "hostname",
    "host-uuid": "uuid",
    "HOST_START": "start",
    "HOST_END": "end",
    "operating-system": "os",
}
_ITEM_TEXT = {"cve", "cvss3_base_score", "exploit_available", "vpr_score"}
_FREE_TEXT_CHILDREN = {"plugin_output", "description", "synopsis", "solution", "see_also", "xref", "plugin_name"}


class _Target:
    def __init__(self, label: str, export: Export) -> None:
        self.label = label
        self.export = export
        self.stack: List[str] = []
        self.root_seen = False
        self.in_policy = False
        self.host: Optional[Dict[str, object]] = None
        self.host_props: Dict[str, str] = {}
        self.host_items: List[Dict[str, object]] = []
        self.tag_name: Optional[str] = None
        self.item: Optional[Dict[str, object]] = None
        self.text_target: Optional[str] = None
        self.text: str = ""
        self.hosts_seen = 0
        self.items_seen = 0
        self.hosts_unfinished = 0
        self.stamps: List[str] = []

    # --- hardening handlers -------------------------------------------------
    def doctype(self, *_args: object) -> None:
        raise ExportError(f"{self.label}: DOCTYPE declarations are not accepted in scanner exports")

    def entity(self, *_args: object) -> None:
        raise ExportError(f"{self.label}: entity declarations are not accepted in scanner exports")

    def external_entity(self, *_args: object) -> int:
        raise ExportError(f"{self.label}: external entities are not accepted in scanner exports")

    # --- structure ------------------------------------------------------------
    def start(self, name: str, attrs: Dict[str, str]) -> None:
        if len(self.stack) >= MAX_DEPTH:
            raise ExportError(f"{self.label}: XML nesting deeper than {MAX_DEPTH}")
        if not self.root_seen:
            self.root_seen = True
            if name not in ("NessusClientData_v2", "NessusClientData"):
                raise ExportError(f"{self.label}: root element {name!r} is not a Nessus report")
        self.stack.append(name)
        self.text = ""
        self.text_target = None
        if name == "Policy":
            self.in_policy = True
            return
        if self.in_policy:
            return
        if name == "ReportHost":
            self.hosts_seen += 1
            if self.hosts_seen > MAX_HOSTS:
                raise ExportError(f"{self.label}: more than {MAX_HOSTS} hosts")
            self.host = {"name": attrs.get("name", "")}
            self.host_props = {}
            self.host_items = []
        elif name == "tag" and self.host is not None and self.item is None:
            tag = attrs.get("name", "")
            self.tag_name = tag if tag in _HOST_TAGS else None
            if self.tag_name:
                self.text_target = "tag"
        elif name == "ReportItem" and self.host is not None:
            self.items_seen += 1
            if self.items_seen > MAX_ITEMS:
                raise ExportError(f"{self.label}: more than {MAX_ITEMS} report items")
            self.item = {
                "port": attrs.get("port"),
                "protocol": attrs.get("protocol"),
                "severity": attrs.get("severity"),
                "pluginID": attrs.get("pluginID"),
                "pluginName": attrs.get("pluginName"),
                "cve": [],
            }
        elif self.item is not None and name in _ITEM_TEXT:
            self.text_target = name
        elif self.item is not None and name in _FREE_TEXT_CHILDREN:
            self.export.text_fields_discarded += 1

    def chars(self, data: str) -> None:
        if self.text_target is None:
            return  # discarded without being stored
        if len(self.text) < MAX_TEXT:
            self.text += data[: MAX_TEXT - len(self.text)]

    def end(self, name: str) -> None:
        if self.stack and self.stack[-1] == name:
            self.stack.pop()
        if name == "Policy":
            self.in_policy = False
            return
        if self.in_policy:
            return
        if name == "tag" and self.text_target == "tag" and self.tag_name:
            self.host_props[_HOST_TAGS[self.tag_name]] = self.text.strip()
            self.tag_name = None
        elif self.item is not None and name in _ITEM_TEXT and self.text_target == name:
            if name == "cve":
                self.item["cve"].append(self.text.strip())  # type: ignore[union-attr]
            else:
                self.item[name] = self.text.strip()
        elif name == "ReportItem" and self.item is not None:
            self.host_items.append(self.item)
            self.item = None
        elif name == "ReportHost" and self.host is not None:
            self._finish_host()
            self.host = None
        self.text_target = None
        self.text = ""

    def _finish_host(self) -> None:
        props = self.host_props
        name_attr = str(self.host.get("name", "")) if self.host else ""
        hostname = clean_hostname(props.get("hostname")) or (clean_hostname(name_attr) if not clean_ip(name_attr) else None)
        fqdn = clean_hostname(props.get("fqdn"))
        ipv4 = clean_ip(props.get("ip")) or clean_ip(name_attr)
        uuid = props.get("uuid")
        asset_id = clean_name(uuid)[:64] if uuid else derive_asset_id(hostname, fqdn, ipv4)
        if not asset_id:
            self.export.records_dropped += len(self.host_items)
            return
        end_stamp = clean_datetime(props.get("end"))
        if end_stamp:
            self.stamps.append(end_stamp)
        else:
            self.hosts_unfinished += 1
        os_label = clean_name(props.get("os")) or None
        merge_asset(
            self.export.assets,
            Asset(asset_id=asset_id, hostname=hostname, fqdn=fqdn, ipv4=ipv4, operating_system=os_label, last_activity=end_stamp),
        )
        for index, item in enumerate(self.host_items):
            self.export.records_seen += 1
            plugin_id = to_int(item.get("pluginID"), 1, 10**9)
            severity = clean_severity(item.get("severity"))
            if plugin_id is None or severity is None:
                self.export.records_dropped += 1
                continue
            self.export.findings.append(
                Finding(
                    asset_id=asset_id,
                    plugin_id=plugin_id,
                    plugin_name=clean_name(item.get("pluginName")) or f"plugin {plugin_id}",
                    severity=severity,
                    cves=extract_cves(item.get("cve") or ()),
                    port=clean_port(item.get("port")),
                    protocol=clean_protocol(item.get("protocol")),
                    state="OPEN",
                    first_found=None,
                    last_found=end_stamp,
                    cvss3=to_float(item.get("cvss3_base_score"), 0.0, 10.0),
                    vpr=to_float(item.get("vpr_score"), 0.0, 10.0),
                    exploit_available=to_bool(item.get("exploit_available")),
                    has_patch=None,
                    record_ref=f"{self.label}:nessus#{self.hosts_seen}.{index}",
                )
            )


def parse(path: str, label: str) -> Export:
    export = Export(label=label, source=path, format="nessus")
    target = _Target(label, export)
    parser = expat.ParserCreate()
    parser.buffer_text = True
    parser.StartDoctypeDeclHandler = target.doctype
    parser.EntityDeclHandler = target.entity
    parser.UnparsedEntityDeclHandler = target.entity
    parser.ExternalEntityRefHandler = target.external_entity
    parser.StartElementHandler = target.start
    parser.EndElementHandler = target.end
    parser.CharacterDataHandler = target.chars
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    total = 0
    try:
        with open(path, "rb") as handle:
            while True:
                chunk = handle.read(CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_XML_BYTES:
                    raise ExportError(f"{label}: XML export exceeds {MAX_XML_BYTES} bytes")
                parser.Parse(chunk, False)
            parser.Parse(b"", True)
    except expat.ExpatError as exc:
        raise PartialExportError(
            f"{label}: XML is malformed or truncated at line {exc.lineno}, column {exc.offset}"
        ) from None
    if not target.root_seen:
        raise ExportError(f"{label}: file is empty or not XML")
    if target.hosts_unfinished:
        export.integrity.fail(f"{target.hosts_unfinished} host(s) have no HOST_END: the scan did not finish")
    export.findings.sort(key=finding_sort_key)
    return finalise(export, target.stamps)
