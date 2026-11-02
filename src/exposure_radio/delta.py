"""Coverage-aware delta between two exports.

A finding that is present now and absent before is only "new exposure" if
the asset was scanned before. If the asset is new to the export, the right
word is "new visibility": the estate did not get worse, the view got wider.

A finding that is absent now and present before is only "closed" if the
asset was rescanned. If the asset is missing from the current export, the
absence is "unverified": it stays open in every count until a scan says
otherwise. This is ADR-0001 rule 7.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .evidence import Coverage
from .model import AssetPluginFinding

Key = Tuple[str, int]

PERSISTING = "persisting"
NEW_EXPOSURE = "new_exposure"
NEW_VISIBILITY = "new_visibility"
REOPENED = "reopened"
CLOSED = "closed"
UNVERIFIED_ABSENCE = "unverified_absence"

CATEGORIES = (PERSISTING, NEW_EXPOSURE, NEW_VISIBILITY, REOPENED, CLOSED, UNVERIFIED_ABSENCE)


@dataclass(frozen=True)
class Change:
    category: str
    finding: AssetPluginFinding  # the current record, or the previous one for absences


@dataclass
class Delta:
    changes: List[Change] = field(default_factory=list)
    coverage: Optional[Coverage] = None
    has_previous: bool = True

    def by_category(self, category: str) -> List[Change]:
        return [c for c in self.changes if c.category == category]

    def count(self, category: str, severity: Optional[int] = None) -> int:
        return sum(
            1
            for c in self.changes
            if c.category == category and (severity is None or c.finding.severity == severity)
        )

    def count_min_severity(self, category: str, min_severity: int) -> int:
        return sum(1 for c in self.changes if c.category == category and c.finding.severity >= min_severity)

    def cves(self, category: str) -> Dict[str, int]:
        """Distinct assets per CVE within a category."""
        out: Dict[str, set] = {}
        for change in self.changes:
            if change.category != category:
                continue
            for cve in change.finding.cves:
                out.setdefault(cve, set()).add(change.finding.asset_id)
        return {cve: len(assets) for cve, assets in out.items()}

    def summary(self) -> Dict[str, int]:
        result = {category: self.count(category) for category in CATEGORIES}
        result["critical_closed"] = self.count(CLOSED, 4)
        result["critical_new_exposure"] = self.count(NEW_EXPOSURE, 4)
        result["critical_new_visibility"] = self.count(NEW_VISIBILITY, 4)
        result["critical_unverified_absence"] = self.count(UNVERIFIED_ABSENCE, 4)
        result["high_closed"] = self.count(CLOSED, 3)
        if self.coverage is not None:
            result["assets_rescanned"] = len(self.coverage.rescanned)
            result["assets_not_rescanned"] = len(self.coverage.not_rescanned)
            result["assets_newly_in_scope"] = len(self.coverage.newly_in_scope)
        return result


def _open_index(findings: Iterable[AssetPluginFinding]) -> Dict[Key, AssetPluginFinding]:
    return {f.key: f for f in findings if f.is_open}


def _all_index(findings: Iterable[AssetPluginFinding]) -> Dict[Key, AssetPluginFinding]:
    return {f.key: f for f in findings}


def compute_delta(
    previous: Optional[List[AssetPluginFinding]],
    current: List[AssetPluginFinding],
    cov: Coverage,
) -> Delta:
    """Classify every open finding in either export. Informational rows are ignored."""
    delta = Delta(coverage=cov, has_previous=previous is not None)
    current = [f for f in current if f.severity > 0]
    if previous is None:
        for finding in current:
            if finding.is_open:
                delta.changes.append(Change(NEW_VISIBILITY, finding))
        return delta
    previous = [f for f in previous if f.severity > 0]
    prev_open = _open_index(previous)
    prev_all = _all_index(previous)
    cur_open = _open_index(current)
    cur_all = _all_index(current)

    for key, finding in sorted(cur_open.items()):
        if key in prev_open:
            delta.changes.append(Change(PERSISTING, finding))
        elif key in prev_all:
            delta.changes.append(Change(REOPENED, finding))
        elif finding.asset_id in cov.previous:
            delta.changes.append(Change(NEW_EXPOSURE, finding))
        else:
            delta.changes.append(Change(NEW_VISIBILITY, finding))

    for key, finding in sorted(prev_open.items()):
        if key in cur_open:
            continue
        if key in cur_all or finding.asset_id in cov.current:
            delta.changes.append(Change(CLOSED, finding))
        else:
            delta.changes.append(Change(UNVERIFIED_ABSENCE, finding))
    return delta
