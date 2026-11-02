"""Alert policy: when to interrupt, decided in code with durable memory.

Breaking in has a cost, so the decision is deterministic and logged:

* BREAK_IN  - a KEV-listed CVE is open on assets it was not announced for
              before: newly listed by CISA since the previous export, newly
              exposed on rescanned assets, newly visible on assets new to
              the scan, or reopened.
* HEALTH    - nothing to announce, but the evidence itself is in doubt: the
              export is incomplete or assets were missed.
* SCHEDULED - the normal briefing; changes exist but none warrants interruption.
* SILENT    - this exact evidence was already briefed; nothing is repeated.

An alert is keyed by CVE and the set of affected assets, so re-running
unchanged data never repeats an alert, while a new asset joining an
exploited CVE does.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from .facts import FactStore, priority_key
from .memory import Memory
from .model import AssetPluginFinding

BREAK_IN = "BREAK_IN"
HEALTH = "HEALTH"
SCHEDULED = "SCHEDULED"
SILENT = "SILENT"
KINDS = (BREAK_IN, HEALTH, SCHEDULED, SILENT)


@dataclass
class Alert:
    cve: str
    key: str
    reasons: List[str]
    duplicate_of: Optional[str] = None

    @property
    def fresh(self) -> bool:
        return self.duplicate_of is None

    def to_dict(self) -> Dict[str, object]:
        return {"cve": self.cve, "key": self.key, "reasons": list(self.reasons), "duplicate_of": self.duplicate_of}


@dataclass
class Decision:
    kind: str
    lead: Optional[str]
    reasons: List[str] = field(default_factory=list)
    health: List[str] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    fingerprint: str = ""
    previously_briefed: Optional[str] = None

    @property
    def fresh_alerts(self) -> List[Alert]:
        return [a for a in self.alerts if a.fresh]

    def to_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "lead": self.lead,
            "reasons": list(self.reasons),
            "health": list(self.health),
            "alerts": [a.to_dict() for a in self.alerts],
            "fingerprint": self.fingerprint,
            "previously_briefed": self.previously_briefed,
        }


def _digest(parts: Iterable[str]) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def evidence_fingerprint(findings: Sequence[AssetPluginFinding], kev_open: Iterable[str], held: bool) -> str:
    """Stable hash of what the episode is about: open rows, KEV set, hold state."""
    rows = sorted(f"{f.asset_id}|{f.plugin_id}|{f.state}" for f in findings if f.severity > 0)
    rows.append("kev:" + ",".join(sorted(kev_open)))
    rows.append("held:" + ("1" if held else "0"))
    return _digest(rows)


def alert_key(cve: str, asset_ids: Iterable[str]) -> str:
    return _digest([cve] + sorted(asset_ids))[:24]


def decide(
    store: FactStore,
    current_findings: Sequence[AssetPluginFinding],
    primary_cves: Dict[Tuple[str, int], Optional[str]],
    kev_listed: FrozenSet[str],
    memory: Memory,
    episode_date: str,
    held: bool,
) -> Decision:
    open_rows = [f for f in current_findings if f.is_open and f.severity > 0]
    assets_by_cve: Dict[str, set] = {}
    for finding in open_rows:
        cve = primary_cves.get(finding.key)
        if cve:
            assets_by_cve.setdefault(cve, set()).add(finding.asset_id)
    kev_open = sorted(c for c in assets_by_cve if c in kev_listed)
    fingerprint = evidence_fingerprint(current_findings, kev_open, held)

    alerts: List[Alert] = []
    for cve in kev_open:
        subject = f"cve:{cve}"
        reasons: List[str] = []
        if store.value(subject, "kev_added_since_previous") is True:
            reasons.append("newly listed by CISA since the previous export")
        if int(store.value(subject, "new_exposure_count", 0) or 0) > 0:
            reasons.append("newly exposed on assets that were already being scanned")
        if int(store.value(subject, "new_visibility_count", 0) or 0) > 0:
            reasons.append("found on assets new to the scan")
        if int(store.value(subject, "reopened_count", 0) or 0) > 0:
            reasons.append("reopened on assets where it had been fixed")
        if not reasons:
            continue
        key = alert_key(cve, assets_by_cve[cve])
        seen = memory.seen_alert(key)
        alerts.append(Alert(cve, key, reasons, duplicate_of=seen))

    previously = memory.seen_episode(fingerprint)
    health: List[str] = []
    if held:
        health.append("export incomplete: nothing counts as fixed")
    missed = int(store.value("episode", "assets_not_rescanned", 0) or 0)
    if missed:
        health.append(f"{missed} previously scanned asset(s) were not rescanned")

    fresh = [a for a in alerts if a.fresh]
    if previously:
        decision = Decision(SILENT, None, [f"evidence unchanged since the episode briefed on {previously}"], health, alerts, fingerprint, previously)
    elif fresh:
        lead = max((a.cve for a in fresh), key=lambda c: priority_key(c, store))
        reasons = [f"{a.cve}: {'; '.join(a.reasons)}" for a in sorted(fresh, key=lambda a: priority_key(a.cve, store), reverse=True)]
        decision = Decision(BREAK_IN, lead, reasons, health, alerts, fingerprint)
    elif health:
        decision = Decision(HEALTH, str(store.value("priority", "lead_cve") or "") or None, ["nothing new to announce; the evidence itself is in doubt"], health, alerts, fingerprint)
    else:
        decision = Decision(SCHEDULED, str(store.value("priority", "lead_cve") or "") or None, ["changes exist but none warrants an interruption"], health, alerts, fingerprint)

    if decision.kind != SILENT:
        for alert in fresh:
            memory.record_alert(alert.key, alert.cve, episode_date)
        memory.record_briefed(fingerprint, episode_date)
    return decision
