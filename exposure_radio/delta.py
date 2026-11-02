"""Coverage-aware change detection between two snapshots.

The question a vulnerability manager actually asks is "what changed", and a
naive diff answers it wrongly in three common ways:

* a new network segment is scanned for the first time and the finding count
  jumps: that is new *visibility*, not new exposure;
* a scanner misses a site and its findings vanish from the report: that is an
  *unverified* result, not a fix;
* nothing in the environment changed but CISA listed a CVE you already have
  as exploited: that is a new *priority*, with an unchanged scan.

Each finding change is classified with the scan coverage of both cycles.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .feeds import KevCatalog
from .snapshot import Finding, Snapshot


class Kind(str, Enum):
    NEW_EXPOSURE = "new_exposure"        # appeared on an asset already scanned before
    NEW_VISIBILITY = "new_visibility"    # appeared because coverage grew
    PERSISTING = "persisting"            # open before, re-observed open now
    REOPENED = "reopened"                # fixed before, open again
    FIXED = "fixed"                      # rescanned and confirmed fixed this cycle
    NOT_DETECTED = "not_detected"        # absent from a rescanned asset, no fix record
    UNVERIFIED = "unverified"            # asset not rescanned; status unknown
    ASSET_GONE = "asset_gone"            # asset left the inventory; status unknown


PRIORITY = ("critical", "high")


@dataclass
class Change:
    kind: Kind
    finding: Finding


@dataclass
class CveRollup:
    cve: str
    severity: str = "info"
    plugin_name: str = ""
    open_assets: set[str] = field(default_factory=set)        # open now, re-observed or carried
    unverified_assets: set[str] = field(default_factory=set)  # open but not re-checked
    new_exposure_assets: set[str] = field(default_factory=set)
    new_visibility_assets: set[str] = field(default_factory=set)
    fixed_assets: set[str] = field(default_factory=set)
    not_detected_assets: set[str] = field(default_factory=set)
    reopened_assets: set[str] = field(default_factory=set)
    first_found: dict[str, object] = field(default_factory=dict)   # asset -> datetime
    in_kev: bool = False
    newly_listed: bool = False


@dataclass
class Delta:
    prev: Snapshot
    curr: Snapshot
    changes: list[Change]
    cves: dict[str, CveRollup]
    new_assets: set[str]               # in inventory now, not scanned last cycle
    missed_assets: set[str]            # scanned last cycle, not this cycle
    gone_assets: set[str]              # left the inventory
    health: list[str]

    def count(self, kind: Kind, severities: tuple[str, ...] = PRIORITY) -> int:
        return sum(1 for c in self.changes if c.kind is kind and c.finding.severity in severities)

    def open_priority(self) -> int:
        return sum(1 for c in self.changes if c.finding.severity in PRIORITY and c.kind not in (Kind.FIXED, Kind.NOT_DETECTED))

    @property
    def unchanged(self) -> bool:
        return self.prev.digest == self.curr.digest


def _rank(severity: str) -> int:
    return ("info", "low", "medium", "high", "critical").index(severity)


def compute_delta(prev: Snapshot, curr: Snapshot, kev_prev: KevCatalog, kev_curr: KevCatalog,
                  coverage_drop_alert: float = 0.10) -> Delta:
    changes: list[Change] = []

    for key, f in curr.findings.items():
        before = prev.findings.get(key)
        if curr.observed_open(f):
            if before is None:
                newly_scanned = not prev.covered(f.asset_id)
                newly_credentialed = curr.authenticated(f.asset_id) and not prev.authenticated(f.asset_id)
                kind = (Kind.PERSISTING if not prev.complete else
                        Kind.NEW_VISIBILITY if (newly_scanned or newly_credentialed) else Kind.NEW_EXPOSURE)
            elif before.state == "FIXED" or (f.state == "REOPENED" and before.state != "REOPENED"):
                kind = Kind.REOPENED
            else:
                kind = Kind.PERSISTING
            changes.append(Change(kind, f))
        elif curr.carried_open(f):
            changes.append(Change(Kind.UNVERIFIED, f))
        elif curr.fixed_in_cycle(f) and before is not None and before.state in ("OPEN", "REOPENED"):
            reliable = curr.covered(f.asset_id) and not (prev.authenticated(f.asset_id) and not curr.authenticated(f.asset_id))
            changes.append(Change(Kind.FIXED if reliable else Kind.UNVERIFIED, f if reliable else before))

    for key, f in prev.findings.items():
        if key in curr.findings or f.state not in ("OPEN", "REOPENED"):
            continue
        if f.asset_id not in curr.assets:
            changes.append(Change(Kind.ASSET_GONE, f))
        elif curr.covered(f.asset_id) and not (prev.authenticated(f.asset_id) and not curr.authenticated(f.asset_id)):
            changes.append(Change(Kind.NOT_DETECTED, f))
        else:
            changes.append(Change(Kind.UNVERIFIED, f))

    cves: dict[str, CveRollup] = {}
    for change in changes:
        f = change.finding
        for cve in f.cves:
            roll = cves.setdefault(cve, CveRollup(cve))
            if _rank(f.severity) > _rank(roll.severity):
                roll.severity, roll.plugin_name = f.severity, f.plugin_name
            roll.plugin_name = roll.plugin_name or f.plugin_name
            k = change.kind
            if k in (Kind.NEW_EXPOSURE, Kind.NEW_VISIBILITY, Kind.PERSISTING, Kind.REOPENED, Kind.UNVERIFIED,
                     Kind.ASSET_GONE):
                roll.open_assets.add(f.asset_id)
                if f.first_found:
                    prior = roll.first_found.get(f.asset_id)
                    roll.first_found[f.asset_id] = min(prior, f.first_found) if prior else f.first_found
            if k in (Kind.UNVERIFIED, Kind.ASSET_GONE):
                roll.unverified_assets.add(f.asset_id)
            elif k is Kind.NEW_EXPOSURE:
                roll.new_exposure_assets.add(f.asset_id)
            elif k is Kind.NEW_VISIBILITY:
                roll.new_visibility_assets.add(f.asset_id)
            elif k is Kind.REOPENED:
                roll.reopened_assets.add(f.asset_id)
            elif k is Kind.FIXED:
                roll.fixed_assets.add(f.asset_id)
            elif k is Kind.NOT_DETECTED:
                roll.not_detected_assets.add(f.asset_id)
    for roll in cves.values():
        roll.fixed_assets -= roll.open_assets
        roll.in_kev = roll.cve in kev_curr.entries
        roll.newly_listed = roll.in_kev and roll.cve not in kev_prev.entries and bool(roll.open_assets)

    prev_scanned = {a for a in prev.assets if prev.covered(a)}
    curr_scanned = {a for a in curr.assets if curr.covered(a)}
    new_assets = (curr_scanned - prev_scanned) | {a for a in curr_scanned if curr.authenticated(a) and not prev.authenticated(a)}
    missed = {a for a in prev_scanned if a in curr.assets and (a not in curr_scanned or (prev.authenticated(a) and not curr.authenticated(a)))}
    gone = {a for a in prev.assets if a not in curr.assets}

    health = list(curr.problems) + ["previous export: " + problem for problem in prev.problems]
    if not prev.complete:
        health.append("the previous export is incomplete; changes cannot be reliably classified")
    if not curr.complete:
        health.append("the latest export is incomplete, so fixes cannot be confirmed")
    if prev_scanned and len(missed) / len(prev_scanned) >= coverage_drop_alert:
        health.append(f"{len(missed)} of {len(prev_scanned)} previously scanned assets were not rescanned")
    elif missed:
        health.append(f"{len(missed)} previously scanned asset(s) were not rescanned")
    if gone:
        health.append(f"{len(gone)} asset(s) left the inventory; their findings are unverified, not fixed")

    if not curr.complete:
        # Fail closed: an incomplete export cannot prove anything was fixed.
        for change in changes:
            if change.kind in (Kind.FIXED, Kind.NOT_DETECTED):
                change.kind = Kind.UNVERIFIED
        for roll in cves.values():
            roll.unverified_assets |= roll.fixed_assets | roll.not_detected_assets
            roll.open_assets |= roll.fixed_assets | roll.not_detected_assets
            roll.fixed_assets.clear()
            roll.not_detected_assets.clear()

    return Delta(prev, curr, changes, cves, new_assets, missed, gone, health)
