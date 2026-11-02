"""The evidence ledger: typed facts with sources.

A fact is ``(subject, predicate, value, source)`` plus the evidence rows it
was built from. Subjects are::

    episode                 the current export as a whole
    delta                   what changed since the previous export
    cve:CVE-2024-3400       one vulnerability across the estate
    priority                the ranked list the briefing leads with

Sources are ledger identifiers (``export:current``, ``kev:...``). The
builders here are the only place facts are created from data; the gate and
the templates only read them.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from .delta import CLOSED, NEW_EXPOSURE, NEW_VISIBILITY, REOPENED, UNVERIFIED_ABSENCE, UNVERIFIED_OPEN, Delta
from .evidence import cve_sort_key
from .feeds import Feeds
from .model import AssetPluginFinding, Export
from .sanitize import SEVERITY_NAMES


@dataclass(frozen=True)
class Fact:
    fact_id: str
    subject: str
    predicate: str
    value: object
    source: str
    evidence: Tuple[str, ...] = ()

    def to_dict(self, redact: bool = False) -> Dict[str, object]:
        data: Dict[str, object] = {
            "id": self.fact_id,
            "subject": self.subject,
            "predicate": self.predicate,
            "value": list(self.value) if isinstance(self.value, tuple) else self.value,
            "source": self.source,
        }
        if not redact:
            data["evidence"] = list(self.evidence)
        else:
            data["evidence_count"] = len(self.evidence)
        return data


class FactStore:
    def __init__(self) -> None:
        self._facts: Dict[str, Fact] = {}
        self._index: Dict[Tuple[str, str], Fact] = {}
        self._counter = 0

    def add(self, subject: str, predicate: str, value: object, source: str, evidence: Iterable[str] = ()) -> Fact:
        if isinstance(value, list):
            value = tuple(value)
        self._counter += 1
        fact = Fact(f"f{self._counter:04d}", subject, predicate, value, source, tuple(evidence))
        self._facts[fact.fact_id] = fact
        self._index[(subject, predicate)] = fact
        return fact

    def get(self, subject: str, predicate: str) -> Optional[Fact]:
        return self._index.get((subject, predicate))

    def value(self, subject: str, predicate: str, default: object = None) -> object:
        fact = self.get(subject, predicate)
        return fact.value if fact is not None else default

    def by_id(self, fact_id: str) -> Optional[Fact]:
        return self._facts.get(fact_id)

    def subjects(self, prefix: str = "") -> List[str]:
        seen: Dict[str, None] = {}
        for subject, _ in self._index:
            if subject.startswith(prefix):
                seen.setdefault(subject, None)
        return list(seen)

    def cves(self) -> List[str]:
        return [s[4:] for s in self.subjects("cve:")]

    def __len__(self) -> int:
        return len(self._facts)

    def __iter__(self):
        return iter(self._facts.values())

    def to_list(self, redact: bool = False) -> List[Dict[str, object]]:
        return [f.to_dict(redact=redact) for f in self._facts.values()]

    def to_json(self, redact: bool = False) -> str:
        return json.dumps(self.to_list(redact=redact), indent=2, sort_keys=False)


# --------------------------------------------------------------------------
# Priority and SLA rules
# --------------------------------------------------------------------------


def priority_key(cve: str, store: FactStore) -> tuple:
    """Higher is more urgent.

    Order: KEV listing, severity, KEV entries added since the previous
    export, EPSS score, public exploit, number of open assets, CVSS v3,
    then the newest CVE id as a deterministic tie-break.
    """
    subject = f"cve:{cve}"
    severity_name = store.value(subject, "severity", "info")
    severity = {v: k for k, v in SEVERITY_NAMES.items()}.get(str(severity_name), 0)
    return (
        1 if store.value(subject, "kev_listed", False) else 0,
        severity,
        1 if store.value(subject, "kev_added_since_previous", False) else 0,
        float(store.value(subject, "epss_score", -1.0) or -1.0),
        1 if store.value(subject, "exploit_available", False) else 0,
        int(store.value(subject, "open_asset_count", 0) or 0),
        float(store.value(subject, "cvss3", 0.0) or 0.0),
        cve_sort_key(cve),
    )


def sla_deadline(sla: Dict[str, object], start: str, severity: int, kev_listed: bool, exploit_available: bool) -> Tuple[str, int]:
    days_cfg = sla.get("deadline_days") if isinstance(sla.get("deadline_days"), dict) else {}
    if kev_listed and "kev_listed" in days_cfg:
        days = int(days_cfg["kev_listed"])
    else:
        days = int(days_cfg.get(SEVERITY_NAMES.get(severity, "low"), days_cfg.get("low", 180)))
    if exploit_available:
        days += int(sla.get("exploit_available_bonus_days", 0) or 0)
    days = max(days, int(sla.get("minimum_days", 1) or 1))
    start_date = date.fromisoformat(start)
    return (start_date + timedelta(days=days)).isoformat(), days


def owner_for(tags: Iterable[str], owners: Dict[str, object]) -> str:
    by_tag = owners.get("by_tag") if isinstance(owners.get("by_tag"), dict) else {}
    for tag in tags:
        if tag in by_tag:
            return str(by_tag[tag])
    return str(owners.get("default", "UNASSIGNED"))


# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


@dataclass
class EvidenceInputs:
    current: Export
    previous: Optional[Export]
    current_findings: List[AssetPluginFinding]
    previous_findings: Optional[List[AssetPluginFinding]]
    primary_cves: Dict[Tuple[str, int], Optional[str]]
    delta: Delta
    feeds: Feeds
    sla: Dict[str, object]
    owners: Dict[str, object]
    episode_date: str
    held: bool
    hold_reasons: Sequence[str] = ()
    previous_kev_cves: Optional[FrozenSet[str]] = None


def build_facts(inputs: EvidenceInputs) -> FactStore:
    store = FactStore()
    current, previous = inputs.current, inputs.previous
    kev, epss, research = inputs.feeds.kev, inputs.feeds.epss, inputs.feeds.research
    src_cur = "export:current"
    src_prev = "export:previous"
    src_delta = f"delta:{inputs.episode_date}"
    src_sla = "sla:data/sla.json"
    src_owners = "owners:data/owners.json"

    open_findings = [f for f in inputs.current_findings if f.is_open and f.severity > 0]
    cov = inputs.delta.coverage
    prev_date = previous.scan_date if previous is not None else None

    # --- episode ---------------------------------------------------------------
    store.add("episode", "export_date", inputs.episode_date, src_cur)
    if previous is not None and previous.scan_date:
        store.add("episode", "previous_export_date", previous.scan_date, src_prev)
    scope = sorted(cov.current) if cov is not None else sorted(current.assets)
    store.add("episode", "asset_count", len(scope), src_cur, scope)
    store.add("episode", "inventory_count", len(current.assets), src_cur, sorted(current.assets))
    store.add("episode", "finding_count", len(open_findings), src_cur)
    store.add("episode", "open_critical_count", sum(1 for f in open_findings if f.severity == 4), src_cur)
    store.add("episode", "open_high_count", sum(1 for f in open_findings if f.severity == 3), src_cur)
    store.add("episode", "export_complete", bool(current.integrity.complete), src_cur)
    store.add("episode", "held", bool(inputs.held), src_cur)
    store.add("episode", "hold_reasons", tuple(inputs.hold_reasons), src_cur)
    store.add("episode", "text_fields_discarded", int(current.text_fields_discarded), src_cur)
    if cov is not None:
        store.add("episode", "assets_rescanned", len(cov.rescanned), src_delta, sorted(cov.rescanned))
        store.add("episode", "assets_not_rescanned", len(cov.not_rescanned), src_delta, sorted(cov.not_rescanned))
        store.add("episode", "assets_newly_in_scope", len(cov.newly_in_scope), src_delta, sorted(cov.newly_in_scope))

    # --- per CVE ---------------------------------------------------------------
    per_cve: Dict[str, List[AssetPluginFinding]] = {}
    for finding in open_findings:
        cve = inputs.primary_cves.get(finding.key)
        if cve:
            per_cve.setdefault(cve, []).append(finding)
    closed_by_cve = inputs.delta.cves(CLOSED)
    unverified_by_cve = inputs.delta.cves(UNVERIFIED_ABSENCE)
    unverified_open_by_cve = inputs.delta.cves(UNVERIFIED_OPEN)
    new_exposure_by_cve = inputs.delta.cves(NEW_EXPOSURE)
    new_visibility_by_cve = inputs.delta.cves(NEW_VISIBILITY)
    reopened_by_cve = inputs.delta.cves(REOPENED)

    all_cves = set(per_cve) | set(closed_by_cve) | set(unverified_by_cve)
    kev_open_cves: List[str] = []
    kev_open_assets: set = set()
    for cve in sorted(all_cves, key=cve_sort_key):
        subject = f"cve:{cve}"
        rows = per_cve.get(cve, [])
        assets = sorted({r.asset_id for r in rows})
        refs = [ref for r in rows for ref in r.record_refs]
        severity = max((r.severity for r in rows), default=0)
        store.add(subject, "open_asset_count", len(assets), src_cur, assets)
        store.add(subject, "severity", SEVERITY_NAMES.get(severity, "info"), src_cur, refs)
        cvss = [r.cvss3 for r in rows if r.cvss3 is not None]
        if cvss:
            store.add(subject, "cvss3", max(cvss), src_cur, refs)
        exploit = any(bool(r.exploit_available) for r in rows)
        store.add(subject, "exploit_available", exploit, src_cur, refs)
        store.add(subject, "plugin_ids", tuple(sorted({r.plugin_id for r in rows})), src_cur, refs)
        store.add(subject, "ports", tuple(sorted({p for r in rows for p in r.ports})), src_cur, refs)
        firsts = sorted(r.first_found for r in rows if r.first_found)
        if firsts:
            store.add(subject, "first_seen", firsts[0][:10], src_cur, refs)
        groups = sorted({t for r in rows if r.asset_id in current.assets for t in current.assets[r.asset_id].tags})
        store.add(subject, "asset_groups", tuple(groups), src_cur, assets)
        store.add(subject, "closed_asset_count", closed_by_cve.get(cve, 0), src_delta)
        store.add(subject, "unverified_absence_count", unverified_by_cve.get(cve, 0), src_delta)
        store.add(subject, "unverified_open_count", unverified_open_by_cve.get(cve, 0), src_delta)
        store.add(subject, "new_exposure_count", new_exposure_by_cve.get(cve, 0), src_delta)
        store.add(subject, "new_visibility_count", new_visibility_by_cve.get(cve, 0), src_delta)
        store.add(subject, "reopened_count", reopened_by_cve.get(cve, 0), src_delta)

        entry = kev.get(cve)
        listed = entry is not None
        store.add(subject, "kev_listed", listed, kev.source_id or "kev:none")
        if entry is not None:
            store.add(subject, "kev_vendor", entry.vendor, kev.source_id)
            store.add(subject, "kev_product", entry.product, kev.source_id)
            store.add(subject, "kev_name", entry.name, kev.source_id)
            store.add(subject, "kev_date_added", entry.date_added, kev.source_id)
            if entry.due_date:
                store.add(subject, "kev_catalogue_due_date", entry.due_date, kev.source_id)
            if entry.ransomware is not None:
                store.add(subject, "kev_ransomware_use", entry.ransomware, kev.source_id)
            if entry.required_action:
                store.add(subject, "kev_required_action", entry.required_action, kev.source_id)
            since_previous = (
                prev_date is not None and prev_date < entry.date_added <= inputs.episode_date
            )
            store.add(subject, "kev_added_since_previous", bool(since_previous), kev.source_id)
            if assets:
                kev_open_cves.append(cve)
                kev_open_assets.update(assets)
        score = epss.score(cve)
        if score is not None:
            store.add(subject, "epss_score", round(score, 5), epss.source_id)
            pct = epss.percentile(cve)
            if pct is not None:
                store.add(subject, "epss_percentile", round(pct, 5), epss.source_id)
        pubs = research.for_cve(cve)
        store.add(subject, "research_count", len(pubs), research.source_id or "tenable-research:none")
        if pubs:
            newest = sorted(pubs, key=lambda p: p.published)[-1]
            store.add(subject, "research_url", newest.url, research.source_id)
            store.add(subject, "research_title", newest.title, research.source_id)
            store.add(subject, "research_published", newest.published, research.source_id)
        if assets:
            deadline, days = sla_deadline(inputs.sla, inputs.episode_date, severity, listed, exploit)
            store.add(subject, "sla_deadline", deadline, src_sla)
            store.add(subject, "sla_days", days, src_sla)
            store.add(subject, "owner", owner_for(groups, inputs.owners), src_owners)

    store.add("episode", "kev_open_cve_count", len(kev_open_cves), src_cur, kev_open_cves)
    store.add("episode", "kev_open_asset_count", len(kev_open_assets), src_cur, sorted(kev_open_assets))

    # --- delta -------------------------------------------------------------------
    summary = inputs.delta.summary()
    store.add("delta", "has_previous", bool(inputs.delta.has_previous), src_delta)
    for key in (
        "critical_closed",
        "high_closed",
        "critical_new_exposure",
        "critical_new_visibility",
        "critical_unverified_absence",
        "critical_unverified_open",
    ):
        store.add("delta", key, int(summary.get(key, 0)), src_delta)
    store.add("delta", "closed_count", int(summary.get(CLOSED, 0)), src_delta)
    store.add("delta", "new_exposure_count", int(summary.get(NEW_EXPOSURE, 0)), src_delta)
    store.add("delta", "new_visibility_count", int(summary.get(NEW_VISIBILITY, 0)), src_delta)
    store.add("delta", "unverified_absence_count", int(summary.get(UNVERIFIED_ABSENCE, 0)), src_delta)
    store.add("delta", "unverified_open_count", int(summary.get(UNVERIFIED_OPEN, 0)), src_delta)
    store.add("delta", "reopened_count", int(summary.get(REOPENED, 0)), src_delta)

    # KEV entries added to the catalogue since the previous export that touch the estate.
    estate_cves = set(all_cves)
    added = [e.cve for e in kev.added_between(prev_date, inputs.episode_date) if e.cve in estate_cves]
    store.add("delta", "kev_new_entries", tuple(added), kev.source_id or "kev:none")
    store.add("delta", "kev_new_entry_count", len(added), kev.source_id or "kev:none")
    # KEV-listed CVEs open now that were not open (as KEV-listed) in the previous episode.
    if inputs.previous_kev_cves is not None:
        newly = sorted(set(kev_open_cves) - set(inputs.previous_kev_cves), key=cve_sort_key)
        store.add("delta", "kev_newly_exposed", tuple(newly), src_delta)
        store.add("delta", "kev_newly_exposed_count", len(newly), src_delta)

    # --- priority ------------------------------------------------------------------
    ranked = sorted((c for c in per_cve), key=lambda c: priority_key(c, store), reverse=True)
    for rank, cve in enumerate(ranked, start=1):
        store.add(f"cve:{cve}", "priority_rank", rank, src_delta)
    top = tuple(ranked[:3])
    store.add("priority", "items", top, src_delta)
    store.add("priority", "count", len(top), src_delta)
    if top:
        store.add("priority", "lead_cve", top[0], src_delta)
    store.add("priority", "ranked_total", len(ranked), src_delta)
    return store
