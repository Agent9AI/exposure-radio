"""Typed records shared by the parsers, the delta engine and the gate.

Every record here is built from cleaned values only (see ``sanitize``).
Free text from the scanner never gets a field.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .sanitize import SEVERITY_NAMES


class ExportError(ValueError):
    """The export could not be read safely (bad format, limits exceeded)."""


class PartialExportError(ExportError):
    """The export is incomplete. The briefing must be held, not aired."""


@dataclass(frozen=True)
class Asset:
    asset_id: str
    hostname: Optional[str] = None
    fqdn: Optional[str] = None
    ipv4: Optional[str] = None
    operating_system: Optional[str] = None
    tags: Tuple[str, ...] = ()

    @property
    def label(self) -> str:
        """Best human label for the full edition (never used in audio)."""
        return self.fqdn or self.hostname or self.ipv4 or self.asset_id

    def identifiers(self) -> Tuple[str, ...]:
        """Every string that would identify this asset to an outsider."""
        values = [self.asset_id, self.hostname, self.fqdn, self.ipv4]
        return tuple(v for v in values if v)


@dataclass(frozen=True)
class Finding:
    """One scanner result for one plugin on one asset and port."""

    asset_id: str
    plugin_id: int
    plugin_name: str
    severity: int
    cves: Tuple[str, ...] = ()
    port: Optional[int] = None
    protocol: Optional[str] = None
    state: str = "OPEN"
    first_found: Optional[str] = None
    last_found: Optional[str] = None
    cvss3: Optional[float] = None
    vpr: Optional[float] = None
    exploit_available: Optional[bool] = None
    has_patch: Optional[bool] = None
    record_ref: str = ""

    @property
    def severity_name(self) -> str:
        return SEVERITY_NAMES.get(self.severity, "unknown")

    @property
    def is_open(self) -> bool:
        return self.state in ("OPEN", "REOPENED", "NEW", "ACTIVE")


@dataclass(frozen=True)
class ExportManifest:
    """What the export says about itself."""

    status: str = "UNKNOWN"
    chunks_expected: Optional[int] = None
    chunks_present: Optional[int] = None
    truncated: bool = False
    note: str = ""


@dataclass
class IntegrityReport:
    complete: bool = True
    reasons: List[str] = field(default_factory=list)

    def fail(self, reason: str) -> None:
        self.complete = False
        self.reasons.append(reason)


@dataclass
class Export:
    label: str
    source: str
    format: str
    assets: Dict[str, Asset] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    scan_date: Optional[str] = None
    manifest: ExportManifest = field(default_factory=ExportManifest)
    integrity: IntegrityReport = field(default_factory=IntegrityReport)
    records_seen: int = 0
    records_dropped: int = 0
    text_fields_discarded: int = 0

    @property
    def asset_ids(self) -> frozenset:
        return frozenset(self.assets)

    def identifiers(self) -> frozenset:
        """All tenant identifiers present in the export (for leak audits)."""
        values = set()
        for asset in self.assets.values():
            values.update(asset.identifiers())
        return frozenset(values)


@dataclass(frozen=True)
class AssetPluginFinding:
    """A finding deduplicated to (asset, plugin); ports are folded in."""

    asset_id: str
    plugin_id: int
    plugin_name: str
    severity: int
    cves: Tuple[str, ...]
    ports: Tuple[str, ...]
    state: str
    first_found: Optional[str]
    last_found: Optional[str]
    cvss3: Optional[float]
    vpr: Optional[float]
    exploit_available: Optional[bool]
    has_patch: Optional[bool]
    record_refs: Tuple[str, ...]

    @property
    def key(self) -> Tuple[str, int]:
        return (self.asset_id, self.plugin_id)

    @property
    def is_open(self) -> bool:
        return self.state in ("OPEN", "REOPENED", "NEW", "ACTIVE")
