"""Load a Tenable Vulnerability Management export into a normalized snapshot.

A snapshot directory holds what the Tenable VM export APIs return:

    export-status.json      GET /vulns/export/{uuid}/status
    vulns/chunk-N.json      GET /vulns/export/{uuid}/chunks/{N}
    assets.json             GET /assets/export/{uuid}/chunks/{N} (concatenated)

Only allowlisted structured fields are read. Free text (plugin output,
synopsis, description, solution, see_also) is never read.
"""

from __future__ import annotations

import hashlib
import json
import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .sanitize import clean_cve, clean_host, clean_ipv4, clean_tag, clean_text

SEVERITIES = ("info", "low", "medium", "high", "critical")
OPEN_STATES = ("OPEN", "REOPENED")


def parse_time(value: object) -> datetime | None:
    if value in (None, "", 0):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10**11 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            return None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return moment.astimezone(timezone.utc)
    return None


@dataclass(frozen=True)
class Asset:
    id: str
    label: str                  # safe display name: hostname, else short id
    hostnames: tuple[str, ...]  # every name/address that identifies the asset
    ipv4s: tuple[str, ...]
    owner: str
    site: str
    first_seen: datetime | None
    last_scan: datetime | None
    last_auth_scan: datetime | None


@dataclass(frozen=True)
class Finding:
    key: tuple[str, int, int, str]   # asset id, plugin id, port, protocol
    asset_id: str
    plugin_id: int
    plugin_name: str
    severity: str
    cves: tuple[str, ...]
    state: str
    first_found: datetime | None
    last_found: datetime | None
    last_fixed: datetime | None


@dataclass
class Snapshot:
    label: str
    exported_at: datetime
    window_start: datetime
    assets: dict[str, Asset] = field(default_factory=dict)
    findings: dict[tuple, Finding] = field(default_factory=dict)
    complete: bool = True
    problems: list[str] = field(default_factory=list)
    identifiers: set[str] = field(default_factory=set)
    sources: dict[str, str] = field(default_factory=dict)   # file -> sha256

    def covered(self, asset_id: str) -> bool:
        """True when the asset was scanned inside this snapshot's cycle."""
        asset = self.assets.get(asset_id)
        return bool(asset and asset.last_scan and asset.last_scan >= self.window_start)

    def authenticated(self, asset_id: str) -> bool:
        asset = self.assets.get(asset_id)
        return bool(asset and asset.last_auth_scan and asset.last_auth_scan >= self.window_start)

    def observed_open(self, finding: Finding) -> bool:
        """Open and re-observed during this cycle."""
        return (finding.state in OPEN_STATES and finding.last_found is not None
                and finding.last_found >= self.window_start)

    def carried_open(self, finding: Finding) -> bool:
        """Still marked open, but not re-observed during this cycle."""
        return finding.state in OPEN_STATES and not self.observed_open(finding)

    def fixed_in_cycle(self, finding: Finding) -> bool:
        return (finding.state == "FIXED" and finding.last_fixed is not None
                and finding.last_fixed >= self.window_start)

    @property
    def digest(self) -> str:
        """Content digest of the evidence this snapshot was built from."""
        joined = "".join(f"{k}:{v};" for k, v in sorted(self.sources.items()))
        return hashlib.sha256(joined.encode()).hexdigest()[:16]


def _read_json(root: Path, name: str, snapshot: Snapshot):
    path = root / name
    try:
        raw = path.read_bytes()
    except OSError:
        snapshot.complete = False
        snapshot.problems.append(f"missing {name}")
        return None
    digest_raw = raw
    if name == "export-status.json":
        try:
            status = json.loads(raw)
            digest_raw = json.dumps({k: status.get(k) for k in ("status", "chunks_available", "chunks_failed", "chunks_cancelled", "total_chunks", "finished_chunks", "filters")}, sort_keys=True).encode()
        except (ValueError, AttributeError):
            pass
    snapshot.sources[name] = hashlib.sha256(digest_raw).hexdigest()
    try:
        return json.loads(raw)
    except ValueError:
        snapshot.complete = False
        snapshot.problems.append(f"unreadable {path.name}")
        return None


def _tag(tags: list, key: str) -> str:
    for tag in tags or []:
        if isinstance(tag, dict) and str(tag.get("key", "")).lower() == key:
            return clean_tag(tag.get("value"))
    return ""


def _asset(raw: dict) -> Asset | None:
    asset_id = clean_tag(raw.get("id") or raw.get("uuid"), 64)
    if not asset_id:
        return None
    names = [h for h in (clean_host(x) for x in (raw.get("hostnames") or []) + (raw.get("fqdns") or [])) if h]
    ips = [ip for ip in (clean_ipv4(x) for x in raw.get("ipv4s") or []) if ip]
    names += [str(x) for x in (raw.get("netbios_names") or []) if clean_host(x)]
    for value in raw.get("ipv6s") or []:
        try:
            ips.append(str(ipaddress.IPv6Address(value)))
        except ValueError:
            pass
    short = [n for n in names if "." not in n]
    label = (short or names or [f"asset-{asset_id[:8]}"])[0]
    return Asset(
        id=asset_id,
        label=label,
        hostnames=tuple(dict.fromkeys(names)),
        ipv4s=tuple(dict.fromkeys(ips)),
        owner=_tag(raw.get("tags"), "owner"),
        site=_tag(raw.get("tags"), "site"),
        first_seen=parse_time(raw.get("first_seen")),
        last_scan=parse_time(raw.get("last_scan_time")),
        last_auth_scan=parse_time(raw.get("last_authenticated_scan_date")),
    )


def _finding(raw: dict) -> Finding | None:
    asset = raw.get("asset") or {}
    plugin = raw.get("plugin") or {}
    port = raw.get("port") or {}
    asset_id = clean_tag(asset.get("uuid"), 64)
    try:
        plugin_id = int(plugin.get("id"))
        port_no = int(port.get("port") or 0)
    except (TypeError, ValueError):
        return None
    if not asset_id:
        return None
    severity = str(raw.get("severity", "")).lower()
    if severity not in SEVERITIES:
        severity = "info"
    state = str(raw.get("state", "")).upper()
    if state not in ("OPEN", "REOPENED", "FIXED"):
        return None
    protocol = clean_tag(port.get("protocol") or "tcp", 8).lower()
    cves = tuple(dict.fromkeys(c for c in (clean_cve(x) for x in plugin.get("cve") or []) if c))
    return Finding(
        key=(asset_id, plugin_id, port_no, protocol),
        asset_id=asset_id,
        plugin_id=plugin_id,
        plugin_name=clean_text(plugin.get("name"), 90),
        severity=severity,
        cves=cves,
        state=state,
        first_found=parse_time(raw.get("first_found")),
        last_found=parse_time(raw.get("last_found")),
        last_fixed=parse_time(raw.get("last_fixed")),
    )


def load_snapshot(directory: str | Path, window_hours: float = 24.0, label: str | None = None) -> Snapshot:
    root = Path(directory)
    probe = Snapshot(label=label or root.name, exported_at=datetime.now(timezone.utc),
                     window_start=datetime.now(timezone.utc))
    status = _read_json(root, "export-status.json", probe) or {}
    exported = parse_time(status.get("created")) or probe.exported_at
    snap = Snapshot(label=label or root.name, exported_at=exported,
                    window_start=exported - timedelta(hours=window_hours),
                    complete=probe.complete, problems=list(probe.problems), sources=dict(probe.sources))

    state = str(status.get("status", "")).upper()
    if state != "FINISHED":
        snap.complete = False
        snap.problems.append(f"export status {clean_tag(state, 20) or 'unknown'}")
    for bucket in ("chunks_failed", "chunks_cancelled"):
        bad = status.get(bucket) or []
        if bad:
            snap.complete = False
            snap.problems.append(f"{len(bad)} export chunk(s) {bucket.split('_')[1]}")

    chunk_ids = status.get("chunks_available") or []
    total, finished = status.get("total_chunks"), status.get("finished_chunks")
    if not isinstance(chunk_ids, list) or not isinstance(total, int) or not isinstance(finished, int) or total != finished or len(set(chunk_ids)) != total:
        snap.complete = False
        snap.problems.append("export chunk counts are incomplete or invalid")
        chunk_ids = chunk_ids if isinstance(chunk_ids, list) else []
    if set((status.get("filters") or {}).get("state") or []) != {"OPEN", "REOPENED", "FIXED"}:
        snap.complete = False
        snap.problems.append("export does not include all finding states")
    if not chunk_ids:
        chunk_ids = sorted(int(p.stem.split("-")[1]) for p in (root / "vulns").glob("chunk-*.json")
                           if p.stem.split("-")[1].isdigit())
    for chunk in chunk_ids:
        rows = _read_json(root, f"vulns/chunk-{int(chunk)}.json", snap)
        if not isinstance(rows, list):
            snap.complete = False
            snap.problems.append("invalid vulnerability chunk")
            continue
        for raw in rows:
            if isinstance(raw, dict):
                finding = _finding(raw)
                if finding:
                    snap.findings[finding.key] = finding
                    asset_data = raw.get("asset") or {}
                    identifiers = [asset_data.get(k) for k in ("hostname", "fqdn", "ipv4", "ipv6")]
                    # Retain identifiers even when the inventory export omits the asset.
                    snap.identifiers.update(str(x) for x in identifiers if x and isinstance(x, str))
                    existing = snap.assets.get(finding.asset_id)
                    names = tuple(str(x) for x in identifiers if x and isinstance(x, str))
                    if names and not existing:
                        snap.assets[finding.asset_id] = Asset(finding.asset_id, names[0], names, (), "", "", None, None, None)

    rows = _read_json(root, "assets.json", snap)
    if not isinstance(rows, list):
        snap.complete = False
        snap.problems.append("invalid asset export")
        rows = []
    for raw in rows:
        if isinstance(raw, dict):
            asset = _asset(raw)
            if asset:
                snap.assets[asset.id] = asset

    # Findings may reference assets the asset export omitted; keep them visible.
    for finding in snap.findings.values():
        if finding.asset_id not in snap.assets:
            snap.assets[finding.asset_id] = Asset(finding.asset_id, f"asset-{finding.asset_id[:8]}", (), (),
                                                  "", "", None, None, None)
    if not any(snap.covered(a) for a in snap.assets):
        snap.problems.append("no asset was scanned during this cycle")
    return snap
