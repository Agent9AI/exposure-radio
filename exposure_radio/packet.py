"""Remediation packet: the ticket-ready action card.

One card per priority CVE. Every number on the card is a fact from the
ledger (with its fact id), so the card and the audio can never disagree.
Three kinds of date are kept apart on purpose:

* KEV catalogue dates: ``dateAdded`` and the catalogue's own ``dueDate``
  field, reported as CISA catalogue values;
* federal policy: CISA Binding Operational Directive 26-04, which replaced
  BOD 22-01 and sets timelines for federal civilian agencies;
* the internal SLA deadline, computed from ``data/sla.json``.

The full edition lists affected assets. The CISO edition gives counts and
groups only and is audited for identifiers before it is written.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .facts import Fact, FactStore
from .model import AssetPluginFinding, Export
from .sanitize import SEVERITY_NAMES
from .templates import vendor_product

FEDERAL_POLICY_NOTE = (
    "Federal civilian agencies remediate KEV entries on the timelines of CISA BOD 26-04 (which replaced BOD 22-01). "
    "That directive is not this organisation's SLA; the deadline above is."
)


@dataclass
class CardItem:
    cve: str
    rank: int
    severity: str
    open_asset_count: int
    owner: str
    sla_deadline: str
    sla_days: int
    export_date: str
    kev: Optional[Dict[str, object]]
    epss: Optional[Dict[str, object]]
    exploit_available: bool
    cvss3: Optional[float]
    first_seen: Optional[str]
    plugin_ids: Tuple[int, ...]
    plugin_names: Tuple[str, ...]
    ports: Tuple[str, ...]
    asset_groups: Tuple[str, ...]
    assets: Tuple[str, ...]  # labels in the full edition, empty in the CISO edition
    change: Dict[str, int]
    research: Optional[Dict[str, str]]
    evidence: List[Dict[str, object]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "cve": self.cve,
            "rank": self.rank,
            "severity": self.severity,
            "open_asset_count": self.open_asset_count,
            "owner": self.owner,
            "deadline": {
                "internal_sla": self.sla_deadline,
                "sla_days": self.sla_days,
                "clock_start": self.export_date,
                "policy_note": FEDERAL_POLICY_NOTE,
            },
            "kev": self.kev,
            "epss": self.epss,
            "exploit_available": self.exploit_available,
            "cvss3": self.cvss3,
            "first_seen": self.first_seen,
            "plugin_ids": list(self.plugin_ids),
            "plugin_names": list(self.plugin_names),
            "ports": list(self.ports),
            "asset_groups": list(self.asset_groups),
            "assets": list(self.assets),
            "change_since_previous": dict(self.change),
            "tenable_research": self.research,
            "evidence": list(self.evidence),
            "references": list(self.references),
            "ticket_markdown": render_ticket(self),
        }


def _fact_ref(fact: Optional[Fact]) -> Optional[Dict[str, object]]:
    if fact is None:
        return None
    return {"fact": fact.fact_id, "predicate": fact.predicate, "value": fact.value if not isinstance(fact.value, tuple) else list(fact.value), "source": fact.source}


def build_items(
    store: FactStore,
    current: Export,
    findings: Sequence[AssetPluginFinding],
    primary_cves: Dict[Tuple[str, int], Optional[str]],
    edition: str = "full",
    max_items: int = 3,
) -> List[CardItem]:
    items: List[CardItem] = []
    ranked = list(store.value("priority", "items", ()) or ())[:max_items]
    export_date = str(store.value("episode", "export_date", ""))
    for rank, cve in enumerate(ranked, start=1):
        subject = f"cve:{cve}"
        rows = [f for f in findings if f.is_open and primary_cves.get(f.key) == cve]
        asset_ids = sorted({r.asset_id for r in rows})
        assets: Tuple[str, ...] = ()
        if edition == "full":
            assets = tuple(current.assets[a].label if a in current.assets else a for a in asset_ids)
        kev: Optional[Dict[str, object]] = None
        if store.value(subject, "kev_listed") is True:
            kev = {
                "listed": True,
                "vendor": store.value(subject, "kev_vendor"),
                "product": store.value(subject, "kev_product"),
                "name": store.value(subject, "kev_name"),
                "date_added": store.value(subject, "kev_date_added"),
                "catalogue_due_date": store.value(subject, "kev_catalogue_due_date"),
                "known_ransomware_campaign_use": store.value(subject, "kev_ransomware_use"),
                "required_action": store.value(subject, "kev_required_action"),
                "catalogue_note": "dateAdded, dueDate and requiredAction are CISA catalogue fields, reported as published.",
            }
        epss: Optional[Dict[str, object]] = None
        if store.get(subject, "epss_score") is not None:
            epss = {
                "score": store.value(subject, "epss_score"),
                "percentile": store.value(subject, "epss_percentile"),
            }
        research: Optional[Dict[str, str]] = None
        if store.get(subject, "research_url") is not None:
            research = {
                "title": str(store.value(subject, "research_title", "")),
                "url": str(store.value(subject, "research_url", "")),
                "published": str(store.value(subject, "research_published", "") or ""),
            }
        plugin_ids = tuple(int(p) for p in (store.value(subject, "plugin_ids", ()) or ()))
        # Scanner-supplied names stay in the full edition only; the CISO edition carries plugin ids.
        plugin_names = tuple(sorted({r.plugin_name for r in rows})) if edition == "full" else ()
        evidence = [
            ref
            for ref in (
                _fact_ref(store.get(subject, predicate))
                for predicate in (
                    "open_asset_count",
                    "severity",
                    "kev_listed",
                    "kev_date_added",
                    "epss_score",
                    "exploit_available",
                    "new_exposure_count",
                    "closed_asset_count",
                    "unverified_absence_count",
                    "sla_deadline",
                    "owner",
                )
            )
            if ref is not None
        ]
        references = [f"https://nvd.nist.gov/vuln/detail/{cve}"]
        if kev:
            references.append(f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}")
        references.extend(f"https://www.tenable.com/plugins/nessus/{pid}" for pid in plugin_ids[:5])
        if research:
            references.append(research["url"])
        items.append(
            CardItem(
                cve=cve,
                rank=rank,
                severity=str(store.value(subject, "severity", "unknown")),
                open_asset_count=int(store.value(subject, "open_asset_count", 0) or 0),
                owner=str(store.value(subject, "owner", "UNASSIGNED")),
                sla_deadline=str(store.value(subject, "sla_deadline", "")),
                sla_days=int(store.value(subject, "sla_days", 0) or 0),
                export_date=export_date,
                kev=kev,
                epss=epss,
                exploit_available=store.value(subject, "exploit_available") is True,
                cvss3=store.value(subject, "cvss3"),  # type: ignore[arg-type]
                first_seen=store.value(subject, "first_seen"),  # type: ignore[arg-type]
                plugin_ids=plugin_ids,
                plugin_names=plugin_names,
                ports=tuple(str(p) for p in (store.value(subject, "ports", ()) or ())),
                asset_groups=tuple(str(g) for g in (store.value(subject, "asset_groups", ()) or ())),
                assets=assets,
                change={
                    "new_exposure": int(store.value(subject, "new_exposure_count", 0) or 0),
                    "closed": int(store.value(subject, "closed_asset_count", 0) or 0),
                    "unverified_absence": int(store.value(subject, "unverified_absence_count", 0) or 0),
                    "reopened": int(store.value(subject, "reopened_count", 0) or 0),
                },
                research=research,
                evidence=evidence,
                references=references,
            )
        )
    return items


def render_ticket(item: CardItem) -> str:
    """Copyable ticket text (Markdown)."""
    kev_line = "Not in the CISA KEV catalogue snapshot."
    required_line = ""
    if item.kev:
        due = item.kev.get("catalogue_due_date")
        ransom = item.kev.get("known_ransomware_campaign_use")
        kev_line = (
            f"CISA KEV: listed since {item.kev.get('date_added')} ({vendor_product(item.kev.get('vendor'), item.kev.get('product'))})."
            + (f" Catalogue dueDate field: {due} (CISA catalogue value)." if due else "")
            + (" Known ransomware campaign use: yes." if ransom is True else "")
        )
        if item.kev.get("required_action"):
            required_line = f"- CISA required action (catalogue text): {item.kev['required_action']}"
    epss_line = "EPSS: no score in the offline snapshot (run `feeds refresh`)."
    if item.epss and item.epss.get("score") is not None:
        epss_line = f"EPSS: {float(item.epss['score']) * 100:.1f}% probability of exploitation within 30 days."
    if item.assets:
        assets_block = "\n".join(f"- {label}" for label in item.assets)
    else:
        groups = ", ".join(item.asset_groups) if item.asset_groups else "groups withheld"
        assets_block = f"- {item.open_asset_count} asset(s); identifiers withheld in this edition ({groups})"
    plugins = ", ".join(f"{pid}" for pid in item.plugin_ids) or "n/a"
    names = "; ".join(item.plugin_names) if item.plugin_names else "n/a"
    ports = ", ".join(item.ports) if item.ports else "n/a"
    change = item.change
    evidence_lines = "\n".join(
        f"- {e['fact']}: {e['predicate']} = {e['value']} ({e['source']})" for e in item.evidence
    )
    refs = "\n".join(f"- {url}" for url in item.references)
    kev_tag = ", KEV-listed" if item.kev else ""
    lines = [
        f"## Patch {item.cve} on {item.open_asset_count} asset(s) ({item.severity}{kev_tag})",
        "",
        f"**Owner:** {item.owner}" + (" (map a team to the asset tags in data/owners.json)" if item.owner.lower().startswith("unassigned") else ""),
        f"**Deadline (internal SLA):** {item.sla_deadline} ({item.sla_days} days from export date {item.export_date})",
        f"**Policy context:** {FEDERAL_POLICY_NOTE}",
        "",
        "**Why now**",
        f"- {kev_line}",
    ]
    if required_line:
        lines.append(required_line)
    lines += [
        f"- {epss_line}",
        f"- Public exploit available: {'yes' if item.exploit_available else 'not flagged by the scanner'}.",
        f"- CVSS v3 base score: {item.cvss3 if item.cvss3 is not None else 'n/a'}.",
        f"- First seen in this estate: {item.first_seen or 'n/a'}.",
        "",
        f"**Affected assets ({item.open_asset_count})**",
        assets_block,
        "",
        "**Scanner evidence**",
        f"- Tenable plugin id(s): {plugins}",
        f"- Plugin name(s) as reported by the scanner (sanitised): {names}",
        f"- Ports: {ports}",
        "",
        "**Change since previous export**",
        f"- New exposure: {change.get('new_exposure', 0)}; closed on rescanned assets: {change.get('closed', 0)}; "
        f"unverified absences: {change.get('unverified_absence', 0)}; reopened: {change.get('reopened', 0)}",
        "",
        "**Evidence (fact id: predicate = value (source))**",
        evidence_lines or "- none",
        "",
        "**References**",
        refs,
    ]
    return "\n".join(lines)


def build_packet(
    store: FactStore,
    current: Export,
    findings: Sequence[AssetPluginFinding],
    primary_cves: Dict[Tuple[str, int], Optional[str]],
    ledger_sources: Sequence[Dict[str, str]],
    edition: str = "full",
    receipt: Optional[Dict[str, object]] = None,
) -> Dict[str, object]:
    items = build_items(store, current, findings, primary_cves, edition=edition)
    return {
        "edition": edition,
        "episode_date": store.value("episode", "export_date"),
        "held": store.value("episode", "held") is True,
        "hold_reasons": list(store.value("episode", "hold_reasons", ()) or ()),
        "summary": {
            "assets": store.value("episode", "asset_count"),
            "open_findings": store.value("episode", "finding_count"),
            "open_critical": store.value("episode", "open_critical_count"),
            "open_high": store.value("episode", "open_high_count"),
            "kev_open_cves": store.value("episode", "kev_open_cve_count"),
            "critical_closed": store.value("delta", "critical_closed"),
            "new_exposure": store.value("delta", "new_exposure_count"),
            "new_visibility": store.value("delta", "new_visibility_count"),
            "unverified_absence": store.value("delta", "unverified_absence_count"),
            "kev_new_entries": list(store.value("delta", "kev_new_entries", ()) or ()),
        },
        "items": [item.to_dict() for item in items],
        "sources": list(ledger_sources),
        "gate_receipt": receipt,
        "severity_scale": SEVERITY_NAMES,
    }
