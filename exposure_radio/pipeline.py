"""End-to-end episode pipeline.

exports -> dedupe -> coverage -> delta -> feeds -> facts -> segments ->
gate -> packet + alert -> memory. Everything downstream of ``build_facts``
sees facts only.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .alert import audit_alert, build_alert
from .briefing import build_segments
from .delta import Delta, compute_delta
from .evidence import coverage, dedupe, select_primary_cve
from .facts import EvidenceInputs, FactStore, build_facts
from .feeds import Feeds, Source, load_feeds, sha256_file, sha256_path
from .gate import GateResult, run_gate
from .memory import Memory
from .model import AssetPluginFinding, Export, ExportError, PartialExportError
from .packet import build_packet
from .parsers import load_export
from .policy import Decision, decide
from .templates import Segment
from .textaudit import ForbiddenTerms, Issue, audit_free_text

DEFAULT_DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def _load_json(path: str) -> Dict[str, object]:
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    return data if isinstance(data, dict) else {}


@dataclass
class Episode:
    current: Export
    previous: Optional[Export]
    current_findings: List[AssetPluginFinding]
    previous_findings: Optional[List[AssetPluginFinding]]
    primary_cves: Dict[Tuple[str, int], Optional[str]]
    delta: Delta
    feeds: Feeds
    facts: FactStore
    segments: List[Segment]
    gate: GateResult
    forbidden: ForbiddenTerms
    packet_full: Dict[str, object]
    packet_ciso: Dict[str, object]
    alert: Dict[str, str]
    pii_issues: Dict[str, List[Issue]]
    held: bool
    hold_reasons: List[str]
    decision: Optional[Decision] = None
    memory_trend: List[Dict[str, object]] = field(default_factory=list)

    @property
    def sentences(self) -> List[str]:
        return list(self.gate.sentences)

    @property
    def sources(self) -> List[Dict[str, str]]:
        return self.feeds.ledger.to_list()

    def transcript(self) -> List[Dict[str, object]]:
        out = []
        for index, (segment, sentence) in enumerate(zip(self.gate.segments, self.gate.sentences, strict=True)):
            cites = []
            for claim in segment.claims:
                fact = self.facts.by_id(claim.cite)
                if fact is not None:
                    cites.append(
                        {
                            "fact": fact.fact_id,
                            "subject": fact.subject,
                            "predicate": fact.predicate,
                            "value": list(fact.value) if isinstance(fact.value, tuple) else fact.value,
                            "source": fact.source,
                        }
                    )
            out.append({"index": index, "template": segment.template_id, "text": sentence, "cites": cites})
        return out


def load_exports(previous_path: Optional[str], current_path: str) -> Tuple[Optional[Export], Export, List[str]]:
    """Load both exports. Partial current exports are kept but flagged."""
    hold_reasons: List[str] = []
    current = load_export(current_path, "current")
    if not current.integrity.complete:
        hold_reasons.extend(current.integrity.reasons)
    previous = None
    if previous_path:
        try:
            previous = load_export(previous_path, "previous")
        except PartialExportError as exc:
            hold_reasons.append(f"previous export unusable: {exc}")
            previous = None
        if previous is not None and not previous.integrity.complete:
            hold_reasons.append("previous export incomplete: " + "; ".join(previous.integrity.reasons))
    return previous, current, hold_reasons


def run_episode(
    current_path: str,
    previous_path: Optional[str] = None,
    data_dir: Optional[str] = None,
    memory: Optional[Memory] = None,
    synthetic_note: bool = True,
    items: Optional[Sequence[str]] = None,
    episode_date: Optional[str] = None,
) -> Episode:
    data_dir = data_dir or DEFAULT_DATA_DIR
    previous, current, hold_reasons = load_exports(previous_path, current_path)
    held = bool(hold_reasons)

    feeds = load_feeds(os.path.join(data_dir, "feeds"))
    sla = _load_json(os.path.join(data_dir, "sla.json"))
    owners = _load_json(os.path.join(data_dir, "owners.json"))
    ledger = feeds.ledger
    ledger.add(Source("export:current", "export", "Current Tenable export", os.path.relpath(current.source), sha256_path(current.source), current.scan_date or "", coverage=f"{len(current.assets)} assets"))
    if previous is not None:
        ledger.add(Source("export:previous", "export", "Previous Tenable export", os.path.relpath(previous.source), sha256_path(previous.source), previous.scan_date or "", coverage=f"{len(previous.assets)} assets"))
    date = episode_date or current.scan_date or ""
    if not date:
        raise ExportError("current export carries no scan or finding dates; pass --episode-date")
    ledger.add(Source(f"delta:{date}", "delta", "Computed delta between the two exports", "", "", date, note="coverage-aware classification, see exposure_radio/delta.py"))
    ledger.add(Source("sla:data/sla.json", "config", "Internal SLA policy", os.path.relpath(os.path.join(data_dir, "sla.json")), sha256_file(os.path.join(data_dir, "sla.json")) if os.path.isfile(os.path.join(data_dir, "sla.json")) else "", ""))
    ledger.add(Source("owners:data/owners.json", "config", "Owner mapping", os.path.relpath(os.path.join(data_dir, "owners.json")), sha256_file(os.path.join(data_dir, "owners.json")) if os.path.isfile(os.path.join(data_dir, "owners.json")) else "", ""))

    current_findings = dedupe(current.findings)
    previous_findings = dedupe(previous.findings) if previous is not None else None
    cov = coverage(previous, current)
    delta = compute_delta(previous_findings, current_findings, cov)

    kev_listed = feeds.kev.listed
    epss_map = feeds.epss.score_map
    primary: Dict[Tuple[str, int], Optional[str]] = {}
    for finding in current_findings + (previous_findings or []):
        if finding.key not in primary:
            primary[finding.key] = select_primary_cve(finding.cves, kev_listed, epss_map, finding.cvss3)

    owns_memory = memory is None
    memory = memory or Memory()
    previous_kev: Optional[frozenset] = None
    if previous is not None and previous_findings is not None:
        prev_summary = {"assets": len(previous.assets)}
        memory.record_episode(previous.scan_date or "", "previous", previous.asset_ids, previous_findings, primary, kev_listed, False, feeds.kev.catalog_version, prev_summary)
        previous_kev = frozenset(
            c for c in (primary.get(f.key) for f in previous_findings if f.is_open) if c and c in kev_listed
        )

    facts = build_facts(
        EvidenceInputs(
            current=current,
            previous=previous,
            current_findings=current_findings,
            previous_findings=previous_findings,
            primary_cves=primary,
            delta=delta,
            feeds=feeds,
            sla=sla,
            owners=owners,
            episode_date=date,
            held=held,
            hold_reasons=hold_reasons,
            previous_kev_cves=previous_kev,
        )
    )
    decision = decide(facts, current_findings, primary, kev_listed, memory, date, held)
    facts.add("episode", "decision", decision.kind, f"policy:{date}")
    facts.add("episode", "decision_reasons", tuple(decision.reasons), f"policy:{date}")
    facts.add("episode", "decision_health", tuple(decision.health), f"policy:{date}")
    ledger.add(Source(f"policy:{date}", "policy", "Alert policy decision", "", "", date, note="deterministic rules, see exposure_radio/policy.py"))

    segments = build_segments(facts, synthetic_note=synthetic_note, items=items)
    trusted_vocabulary = [
        phrase
        for entry in feeds.kev.entries.values()
        for phrase in (entry.name, entry.product, entry.vendor)
    ]
    forbidden = ForbiddenTerms.from_exports(previous, current, trusted=trusted_vocabulary)
    gate = run_gate(segments, facts, forbidden, edition="full")

    receipt_dict = gate.receipt.to_dict()
    packet_full = build_packet(facts, current, current_findings, primary, ledger.to_list(), edition="full", receipt=receipt_dict)
    packet_ciso = build_packet(facts, current, current_findings, primary, ledger.to_list(), edition="ciso", receipt=receipt_dict)
    alert = build_alert(facts, gate.receipt.script_sha256, decision.kind)

    pii_issues = {
        "ciso_packet": audit_free_text(json.dumps(packet_ciso, sort_keys=True), forbidden),
        "alert": audit_alert(alert, forbidden),
        "narration": [i for i in gate.issues],
        "facts_redacted": audit_free_text(facts.to_json(redact=True), forbidden),
    }
    if pii_issues["ciso_packet"]:
        packet_ciso = {"edition": "ciso", "withheld": True, "reason": "identifier audit failed", "issues": [i.to_dict() for i in pii_issues["ciso_packet"]]}
    if pii_issues["alert"]:
        alert = {"title": "Exposure Radio", "body": "Briefing ready.", "reference": alert.get("reference", ""), "action": "Open the briefing", "withheld_detail": "alert text failed the identifier audit"}

    memory.record_episode(date, "current", cov.current, current_findings, primary, kev_listed, held, feeds.kev.catalog_version, delta.summary())
    trend = memory.trend()
    if owns_memory:
        memory.close()

    return Episode(
        current=current,
        previous=previous,
        current_findings=current_findings,
        previous_findings=previous_findings,
        primary_cves=primary,
        delta=delta,
        feeds=feeds,
        facts=facts,
        segments=segments,
        gate=gate,
        forbidden=forbidden,
        packet_full=packet_full,
        packet_ciso=packet_ciso,
        alert=alert,
        pii_issues=pii_issues,
        held=held,
        hold_reasons=hold_reasons,
        decision=decision,
        memory_trend=trend,
    )


def write_outputs(episode: Episode, out_dir: str) -> Dict[str, str]:
    """Write every artefact of an episode. Returns path by name."""
    os.makedirs(out_dir, exist_ok=True)
    paths: Dict[str, str] = {}

    def dump(name: str, data: object) -> None:
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            if isinstance(data, str):
                handle.write(data)
                if not data.endswith("\n"):
                    handle.write("\n")
            else:
                json.dump(data, handle, indent=2, sort_keys=False)
                handle.write("\n")
        paths[name] = path

    dump("briefing.txt", "\n".join(episode.sentences))
    dump("transcript.json", {"edition": "full", "passed": episode.gate.passed, "sentences": episode.transcript()})
    dump("receipt.json", episode.gate.receipt.to_dict())
    dump("packet_full.json", episode.packet_full)
    dump("packet_ciso.json", episode.packet_ciso)
    dump(
        "packet_full.md",
        "\n\n---\n\n".join(item["ticket_markdown"] for item in episode.packet_full.get("items", [])) or "(no items)",
    )
    if not episode.packet_ciso.get("withheld"):
        dump(
            "packet_ciso.md",
            "\n\n---\n\n".join(item["ticket_markdown"] for item in episode.packet_ciso.get("items", [])) or "(no items)",
        )
    dump("alert.json", episode.alert)
    dump("decision.json", episode.decision.to_dict() if episode.decision else {})
    dump("facts.json", episode.facts.to_list(redact=False))
    dump("facts_redacted.json", episode.facts.to_list(redact=True))
    dump("ledger.json", episode.sources)
    dump("delta.json", episode.delta.summary())
    dump("memory_trend.json", episode.memory_trend)
    return paths
