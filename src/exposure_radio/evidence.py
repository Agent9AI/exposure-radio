"""Turning raw findings into evidence: dedupe, primary CVE, scan coverage.

Rules (also stated in the README so a reviewer can check them):

* Per-port dedupe. Tenable reports one row per (asset, plugin, port,
  protocol). The same TLS or SSH weakness on three ports is one exposure on
  one asset, so rows collapse to (asset, plugin) and the ports are kept as a
  list. Asset counts in the briefing are counts of distinct assets.
* Primary CVE. A plugin may cite many CVEs. The one the briefing names is
  chosen by: CISA KEV listing first, then highest EPSS score, then the
  highest CVSS v3 base score carried by the finding, then the lexically
  greatest CVE ID (newest) as a deterministic tie-break.
* Coverage. An asset is "in scope" for an export if it appears in that
  export at all, including informational findings. Assets that were in the
  previous export but not the current one were not rescanned; nothing about
  them is treated as fixed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from .model import AssetPluginFinding, Export, Finding


def dedupe(findings: Iterable[Finding]) -> List[AssetPluginFinding]:
    """Collapse per-port rows to one record per (asset, plugin)."""
    groups: Dict[Tuple[str, int], List[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.asset_id, finding.plugin_id), []).append(finding)
    result: List[AssetPluginFinding] = []
    for (asset_id, plugin_id), rows in sorted(groups.items()):
        ports = sorted({f"{r.port}/{r.protocol or 'tcp'}" for r in rows if r.port is not None})
        cves = sorted({cve for r in rows for cve in r.cves})
        open_rows = [r for r in rows if r.is_open]
        state = "OPEN" if open_rows else rows[0].state
        firsts = sorted(r.first_found for r in rows if r.first_found)
        lasts = sorted(r.last_found for r in rows if r.last_found)
        cvss = [r.cvss3 for r in rows if r.cvss3 is not None]
        vprs = [r.vpr for r in rows if r.vpr is not None]
        exploits = [r.exploit_available for r in rows if r.exploit_available is not None]
        patches = [r.has_patch for r in rows if r.has_patch is not None]
        result.append(
            AssetPluginFinding(
                asset_id=asset_id,
                plugin_id=plugin_id,
                plugin_name=rows[0].plugin_name,
                severity=max(r.severity for r in rows),
                cves=tuple(cves),
                ports=tuple(ports),
                state=state,
                first_found=firsts[0] if firsts else None,
                last_found=lasts[-1] if lasts else None,
                cvss3=max(cvss) if cvss else None,
                vpr=max(vprs) if vprs else None,
                exploit_available=any(exploits) if exploits else None,
                has_patch=any(patches) if patches else None,
                record_refs=tuple(r.record_ref for r in rows),
            )
        )
    return result


def select_primary_cve(
    cves: Sequence[str],
    kev_listed: FrozenSet[str],
    epss_scores: Dict[str, float],
    cvss3: Optional[float] = None,
) -> Optional[str]:
    """Pick the CVE the briefing names for a plugin. See module docstring."""
    if not cves:
        return None

    def rank(cve: str) -> tuple:
        return (
            1 if cve in kev_listed else 0,
            epss_scores.get(cve, -1.0),
            cvss3 if cvss3 is not None else -1.0,
            cve_sort_key(cve),
        )

    return max(cves, key=rank)


def cve_sort_key(cve: str) -> Tuple[int, int]:
    """Numeric sort key so CVE-2024-9999 < CVE-2024-10000."""
    try:
        _, year, number = cve.split("-")
        return (int(year), int(number))
    except ValueError:
        return (0, 0)


@dataclass(frozen=True)
class Coverage:
    """Which assets each export covers."""

    previous: FrozenSet[str]
    current: FrozenSet[str]

    @property
    def rescanned(self) -> FrozenSet[str]:
        return self.previous & self.current

    @property
    def not_rescanned(self) -> FrozenSet[str]:
        """In the previous export, absent from the current one."""
        return self.previous - self.current

    @property
    def newly_in_scope(self) -> FrozenSet[str]:
        """In the current export only: visibility grew."""
        return self.current - self.previous


def coverage(previous: Optional[Export], current: Export) -> Coverage:
    prev_ids = previous.asset_ids if previous is not None else frozenset()
    return Coverage(previous=frozenset(prev_ids), current=frozenset(current.asset_ids))
