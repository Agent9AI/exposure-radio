"""The evidence ledger: typed facts derived from snapshots and feeds.

Every statement Exposure Radio makes must cite one of these facts. A fact is
``(subject, predicate, value, source)``. Subjects are a CVE ID, ``tenant`` or
``bulletin``. Predicates come from a closed registry with fixed value types.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .delta import Delta, Kind
from .feeds import EpssScores, KevCatalog

# predicate -> value type. Anything else is not a fact.
PREDICATES: dict[str, type] = {
    "tenant.open_priority_findings": int,
    "tenant.open_kev_cves": int,
    "tenant.new_exposure_findings": int,
    "tenant.new_visibility_findings": int,
    "tenant.new_visibility_assets": int,
    "tenant.fixed_findings": int,
    "tenant.unverified_findings": int,
    "tenant.unverified_assets": int,
    "tenant.assets_scanned": int,
    "tenant.assets_total": int,
    "tenant.export_complete": bool,
    "bulletin.decision": str,
    "bulletin.lead": str,
    "cve.name": str,
    "cve.severity": str,
    "cve.open_assets": int,
    "cve.unverified_assets": int,
    "cve.fixed_assets": int,
    "cve.not_detected_assets": int,
    "cve.new_exposure_assets": int,
    "cve.new_visibility_assets": int,
    "cve.in_kev": bool,
    "cve.kev_newly_listed": bool,
    "cve.kev_added": str,
    "cve.kev_ransomware": bool,
    "cve.kev_catalog_due": str,
    "cve.epss_percent": int,
    "cve.oldest_open_days": int,
    "cve.internal_due": str,
    "cve.overdue_assets": int,
    "cve.affected_hosts": tuple,
    "cve.owners": tuple,
}

# Facts that identify systems. Never shown to a model, never in executive output.
SENSITIVE = {"cve.affected_hosts"}

DEFAULT_SLA_DAYS = {"kev": 7, "critical": 15, "high": 30, "medium": 90, "low": 180, "info": 365}


@dataclass(frozen=True)
class Fact:
    id: str
    subject: str
    predicate: str
    value: object
    source: str

    def as_dict(self) -> dict:
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        return {"id": self.id, "subject": self.subject, "predicate": self.predicate,
                "value": value, "source": self.source}


@dataclass
class Ledger:
    facts: list[Fact]
    clock: datetime
    sources: dict[str, str]
    sensitive_terms: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        self._by_id = {f.id: f for f in self.facts}
        self._by_key = {(f.subject, f.predicate): f for f in self.facts}

    def get(self, fact_id: str) -> Fact | None:
        return self._by_id.get(fact_id)

    def find(self, subject: str, predicate: str) -> Fact | None:
        return self._by_key.get((subject, predicate))

    def value(self, subject: str, predicate: str, default=None):
        fact = self.find(subject, predicate)
        return fact.value if fact else default

    @property
    def subjects(self) -> set[str]:
        return {f.subject for f in self.facts}

    @property
    def cves(self) -> list[str]:
        return sorted({f.subject for f in self.facts if f.subject.startswith("CVE-")})

    @property
    def id(self) -> str:
        body = json.dumps([f.as_dict() for f in self.facts], sort_keys=True, default=str)
        return hashlib.sha256(body.encode()).hexdigest()[:16]

    def public_view(self, subjects: set[str] | None = None) -> list[dict]:
        """Facts safe to show a model: no host identities, and no names that
        came from scanner text (only CISA's names are passed through)."""
        return [f.as_dict() for f in self.facts
                if f.predicate not in SENSITIVE
                and not (f.predicate == "cve.name" and not f.source.startswith("CISA KEV"))
                and (subjects is None or f.subject in subjects)]


def _days(a: datetime, b: datetime) -> int:
    return max(0, (a - b).days)


def build_ledger(delta: Delta, kev: KevCatalog, epss: EpssScores | None, decision: str = "",
                 lead: str = "", sla_days: dict[str, int] | None = None) -> Ledger:
    sla = {**DEFAULT_SLA_DAYS, **(sla_days or {})}
    curr, prev = delta.curr, delta.prev
    clock = curr.exported_at
    scan_src = f"Tenable VM export {curr.label} ({curr.digest})"
    diff_src = f"Tenable VM exports {prev.label} -> {curr.label} ({prev.digest}->{curr.digest})"
    kev_src = f"CISA KEV catalog {kev.version} as of {kev.as_of}"
    epss_src = f"FIRST EPSS {epss.score_date}" if epss else ""

    rows: list[tuple[str, str, object, str]] = []
    add = rows.append
    add(("tenant", "tenant.open_priority_findings", delta.open_priority(), scan_src))
    add(("tenant", "tenant.open_kev_cves",
         sum(1 for r in delta.cves.values() if r.in_kev and r.open_assets), f"{scan_src}; {kev_src}"))
    add(("tenant", "tenant.new_exposure_findings", delta.count(Kind.NEW_EXPOSURE), diff_src))
    add(("tenant", "tenant.new_visibility_findings", delta.count(Kind.NEW_VISIBILITY), diff_src))
    add(("tenant", "tenant.new_visibility_assets", len(delta.new_assets), diff_src))
    add(("tenant", "tenant.fixed_findings", delta.count(Kind.FIXED), diff_src))
    add(("tenant", "tenant.unverified_findings",
         delta.count(Kind.UNVERIFIED) + delta.count(Kind.ASSET_GONE), diff_src))
    add(("tenant", "tenant.unverified_assets", len(delta.missed_assets) + len(delta.gone_assets), diff_src))
    add(("tenant", "tenant.assets_scanned", sum(1 for a in curr.assets if curr.covered(a)), scan_src))
    add(("tenant", "tenant.assets_total", len(curr.assets), scan_src))
    add(("tenant", "tenant.export_complete", curr.complete, scan_src))
    add(("bulletin", "bulletin.decision", decision, "alert policy"))
    add(("bulletin", "bulletin.lead", lead, "alert policy"))

    for cve in sorted(delta.cves):
        r = delta.cves[cve]
        entry = kev.get(cve)
        add((cve, "cve.name", entry.name if entry else r.plugin_name, kev_src if entry else scan_src))
        add((cve, "cve.severity", r.severity, scan_src))
        for pred, assets in (("cve.open_assets", r.open_assets), ("cve.unverified_assets", r.unverified_assets),
                             ("cve.fixed_assets", r.fixed_assets), ("cve.not_detected_assets", r.not_detected_assets),
                             ("cve.new_exposure_assets", r.new_exposure_assets),
                             ("cve.new_visibility_assets", r.new_visibility_assets)):
            add((cve, pred, len(assets), diff_src))
        add((cve, "cve.in_kev", bool(entry), kev_src))
        add((cve, "cve.kev_newly_listed", r.newly_listed, kev_src))
        if entry:
            add((cve, "cve.kev_added", entry.date_added, kev_src))
            add((cve, "cve.kev_ransomware", entry.ransomware, kev_src))
            add((cve, "cve.kev_catalog_due", entry.due_date, kev_src))
        score = epss.get(cve) if epss else None
        if score and score[0] >= 0.01:
            add((cve, "cve.epss_percent", int(round(score[0] * 100)), epss_src))
        if r.open_assets:
            firsts = {a: r.first_found[a] for a in r.open_assets if a in r.first_found}
            days = sla["kev"] if entry else sla.get(r.severity, sla["info"])
            # The KEV clock cannot start before CISA listed the CVE.
            listed = datetime.fromisoformat(entry.date_added).replace(tzinfo=clock.tzinfo) if entry else None
            starts = {a: max(t, listed) if listed else t for a, t in firsts.items()}
            if firsts:
                add((cve, "cve.oldest_open_days", _days(clock, min(firsts.values())), scan_src))
                basis = f"internal SLA: {days} days from " + ("KEV listing or first detection, whichever is later"
                                                               if entry else f"first detection ({r.severity})")
                add((cve, "cve.internal_due", (min(starts.values()) + timedelta(days=days)).date().isoformat(), basis))
                overdue = sum(1 for start in starts.values() if start + timedelta(days=days) < clock)
                add((cve, "cve.overdue_assets", overdue, basis))
            hosts = tuple(sorted(curr.assets[a].label if a in curr.assets else prev.assets[a].label
                                 for a in r.open_assets))
            add((cve, "cve.affected_hosts", hosts, scan_src))
            owners = {(curr.assets.get(a) or prev.assets.get(a)).owner for a in r.open_assets}
            add((cve, "cve.owners", tuple(sorted(o for o in owners if o)), scan_src))

    facts = [Fact(f"F{i:03d}", s, p, v, src) for i, (s, p, v, src) in enumerate(rows, 1)]
    for fact in facts:
        if not isinstance(fact.value, PREDICATES[fact.predicate]):
            raise TypeError(f"{fact.predicate} expects {PREDICATES[fact.predicate].__name__}: {fact.value!r}")

    terms: set[str] = set()
    for snap in (prev, curr):
        for asset in snap.assets.values():
            terms.add(asset.id)
            terms.update(asset.hostnames)
            terms.update(asset.ipv4s)
            terms.add(asset.label)
    sources = {"scan": scan_src, "diff": diff_src, "kev": kev_src}
    if epss:
        sources["epss"] = epss_src
    return Ledger(facts, clock, sources, frozenset(t for t in terms if t))
