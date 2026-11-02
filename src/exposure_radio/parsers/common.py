"""Helpers shared by the three parsers."""

from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional

from ..model import Asset, Export, Finding
from ..sanitize import clean_tag

# Field names that carry free text written by the scanner or by the scanned
# system. Parsers count them and never read their values.
FREE_TEXT_FIELDS = frozenset(
    {
        "output",
        "plugin_output",
        "plugin output",
        "description",
        "synopsis",
        "solution",
        "see_also",
        "see also",
        "plugin text",
        "banner",
        "xrefs",
        "stig_severity",
        "plugin_modification_date",
    }
)

OPEN_STATES = ("OPEN", "REOPENED", "NEW", "ACTIVE")
KNOWN_STATES = OPEN_STATES + ("FIXED", "RESURFACED")


def normalise_state(value: object) -> str:
    text = str(value or "OPEN").strip().upper()
    if text in KNOWN_STATES:
        return text
    if text in ("RESOLVED", "CLOSED", "PATCHED"):
        return "FIXED"
    return "OPEN"


def derive_asset_id(hostname: Optional[str], fqdn: Optional[str], ipv4: Optional[str]) -> Optional[str]:
    """Stable identifier for exports that carry no asset UUID."""
    basis = fqdn or hostname or ipv4
    if not basis:
        return None
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]
    return f"derived-{digest}"


def clean_tags(values: Iterable[object]) -> tuple:
    tags: List[str] = []
    for value in values:
        if isinstance(value, dict):
            key = clean_tag(value.get("key") or value.get("category") or "")
            val = clean_tag(value.get("value") or "")
            text = f"{key}:{val}" if key and val else (key or val)
        else:
            text = clean_tag(value)
        if text and text not in tags:
            tags.append(text)
        if len(tags) >= 32:
            break
    return tuple(tags)


def merge_asset(assets: Dict[str, Asset], asset: Asset) -> None:
    """Keep the most complete view of an asset seen across records."""
    existing = assets.get(asset.asset_id)
    if existing is None:
        assets[asset.asset_id] = asset
        return
    merged = Asset(
        asset_id=existing.asset_id,
        hostname=existing.hostname or asset.hostname,
        fqdn=existing.fqdn or asset.fqdn,
        ipv4=existing.ipv4 or asset.ipv4,
        operating_system=existing.operating_system or asset.operating_system,
        tags=tuple(dict.fromkeys(existing.tags + asset.tags)),
    )
    assets[asset.asset_id] = merged


def finalise(export: Export, scan_stamps: Iterable[Optional[str]]) -> Export:
    """Fill the scan date and run the generic integrity checks."""
    stamps = sorted(s for s in scan_stamps if s)
    if stamps:
        export.scan_date = stamps[-1][:10]
    else:
        last = sorted(f.last_found for f in export.findings if f.last_found)
        export.scan_date = last[-1][:10] if last else None
    if export.records_seen == 0:
        export.integrity.fail("export contains no records")
    if export.manifest.truncated:
        export.integrity.fail("export declares itself truncated")
    status = export.manifest.status.upper()
    if status not in ("FINISHED", "COMPLETE", "COMPLETED", "UNKNOWN", ""):
        export.integrity.fail(f"export status is {export.manifest.status!r}")
    expected, present = export.manifest.chunks_expected, export.manifest.chunks_present
    if expected is not None and present is not None and present < expected:
        export.integrity.fail(f"{present} of {expected} export chunks present")
    return export


def finding_sort_key(finding: Finding) -> tuple:
    return (finding.asset_id, finding.plugin_id, finding.port or -1, finding.protocol or "")
