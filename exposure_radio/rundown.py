"""Deterministic producer: decision + ledger -> script, action card, receipt.

The anchor carries the decision and the next step. The analyst carries the
evidence. Every line is rendered from a template, parsed back into claims,
cited, and gated before anything else happens.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .claims import BY_ID, parse_sentence, render
from .delta import Delta, Kind
from .feeds import KevCatalog
from .gate import GateReport, gate_script
from .ledger import Ledger
from .policy import Decision, ranked

EDITIONS = ("analyst", "executive")


class RedactionError(RuntimeError):
    """An executive artifact contained a tenant system identifier."""


@dataclass
class Episode:
    decision: Decision
    ledger: Ledger
    lines: list[dict]
    gate: GateReport | None
    card: dict
    edition: str
    notes: list[str] = field(default_factory=list)


class _Script:
    def __init__(self, ledger: Ledger) -> None:
        self.ledger = ledger
        self.lines: list[dict] = []

    def fixed(self, text: str, voice: str = "ANCHOR") -> None:
        self.lines.append({"voice": voice, "text": text, "template": None, "cites": []})

    def say(self, template_id: str, cve: str | None = None, **values) -> None:
        if cve:
            values["cve"] = cve
        text = render(template_id, **values)
        parsed = parse_sentence(text)
        cites = []
        for claim in parsed.claims if parsed else []:
            fact = self.ledger.find(claim.subject, claim.predicate)
            if fact:
                cites.append(fact.id)
        for predicate, _, _ in BY_ID[template_id].requires:
            subject = cve if predicate.startswith("cve.") else "tenant"
            fact = self.ledger.find(subject, predicate)
            if fact:
                cites.append(fact.id)
        self.lines.append({"voice": BY_ID[template_id].voice, "text": text, "template": template_id,
                           "cites": list(dict.fromkeys(cites))})


def _lead_block(s: _Script, L: Ledger, cve: str, full: bool) -> None:
    v = lambda p, d=None: L.value(cve, p, d)  # noqa: E731
    if v("cve.in_kev"):
        s.say("C_NAME", cve, name=v("cve.name"))        # CISA's name, not scanner text
    else:
        s.say("C_SEVERITY", cve, name=v("cve.severity"))
    if v("cve.kev_newly_listed"):
        s.say("C_KEV_NEW", cve)
    elif v("cve.in_kev"):
        s.say("C_KEV_ADDED", cve, date=v("cve.kev_added"))
    if v("cve.new_exposure_assets", 0):
        s.say("C_NEW_EXPOSURE", cve, n=v("cve.new_exposure_assets"))
    if v("cve.new_visibility_assets", 0):
        s.say("C_NEW_VISIBILITY", cve, n=v("cve.new_visibility_assets"))
    s.say("C_OPEN", cve, n=v("cve.open_assets", 0))
    if not full:
        return
    if v("cve.kev_ransomware"):
        s.say("C_RANSOMWARE", cve)
    if v("cve.epss_percent") is not None:
        s.say("C_EPSS", cve, n=v("cve.epss_percent"))
    if v("cve.overdue_assets", 0):
        s.say("C_AGE", cve, n=v("cve.oldest_open_days"))
        s.say("C_OVERDUE", cve, n=v("cve.overdue_assets"))
    elif v("cve.internal_due"):
        s.say("C_DUE", cve, date=v("cve.internal_due"))
    if v("cve.unverified_assets", 0):
        s.say("C_UNVERIFIED", cve, n=v("cve.unverified_assets"))


def _action(s: _Script, L: Ledger, cve: str) -> None:
    if not L.value(cve, "cve.open_assets", 0):
        return
    s.say("A_KEV_ACTION" if L.value(cve, "cve.in_kev") else "A_PATCH", cve)
    if L.value(cve, "cve.unverified_assets", 0):
        s.say("A_RESCAN", cve, n=L.value(cve, "cve.unverified_assets"))


def _changes(s: _Script, L: Ledger) -> None:
    t = lambda p: L.value("tenant", p, 0)  # noqa: E731
    s.fixed("Here is what changed since the last briefing.")
    if not L.value("tenant", "tenant.export_complete", True):
        s.say("T_INCOMPLETE")
    if t("tenant.new_exposure_findings"):
        s.say("T_EXPOSURE_GREW", n=t("tenant.new_exposure_findings"))
    else:
        s.say("T_EXPOSURE_FLAT")
    if t("tenant.new_visibility_assets"):
        s.say("T_VISIBILITY", n=t("tenant.new_visibility_findings"), m=t("tenant.new_visibility_assets"))
    if t("tenant.fixed_findings"):
        s.say("T_FIXED", n=t("tenant.fixed_findings"))
    if t("tenant.unverified_assets"):
        s.say("T_MISSED", n=t("tenant.unverified_assets"))
    if t("tenant.unverified_findings"):
        s.say("T_UNVERIFIED", n=t("tenant.unverified_findings"))
    s.say("T_COVERAGE", n=t("tenant.assets_scanned"), m=t("tenant.assets_total"))
    if t("tenant.new_visibility_assets"):
        s.say("A_REVIEW_NEW", n=t("tenant.new_visibility_assets"))


def build_script(decision: Decision, ledger: Ledger, order: list[str] | None = None) -> list[dict]:
    """Template edition. ``order`` lets an analyst choose which items lead."""
    if decision.kind == "SILENT":
        return []
    s = _Script(ledger)
    s.fixed("This is Exposure Radio.")
    lead = (order or [decision.lead])[0] if (order or decision.lead) else ""
    if decision.kind == "BREAK_IN":
        s.say("B_BREAK_IN", cve=lead)
    elif decision.kind == "HEALTH":
        s.say("B_HEALTH")
    elif lead:
        s.say("B_SCHEDULED", cve=lead)
    else:
        s.say("B_QUIET")
    if lead:
        _lead_block(s, ledger, lead, full=True)
        _action(s, ledger, lead)
    seconds = [c for c in (order or [a.cve for a in decision.fresh_alerts])[1:] if c != lead][:1]
    for cve in seconds:
        s.fixed("Second item.")
        _lead_block(s, ledger, cve, full=False)
        _action(s, ledger, cve)
    _changes(s, ledger)
    s.fixed("The action card has the affected assets, owners and evidence.")
    s.fixed("That is the bulletin.")
    return s.lines


# --- action card ------------------------------------------------------------------------------

def _asset_rows(delta: Delta, cve: str) -> list[dict]:
    rows = []
    for change in delta.changes:
        f = change.finding
        if cve not in f.cves or change.kind in (Kind.FIXED, Kind.NOT_DETECTED):
            continue
        asset = delta.curr.assets.get(f.asset_id) or delta.prev.assets.get(f.asset_id)
        status = {Kind.UNVERIFIED: "unverified (not rescanned)", Kind.ASSET_GONE: "unverified (left inventory)",
                  Kind.NEW_EXPOSURE: "open (new)", Kind.NEW_VISIBILITY: "open (newly visible)",
                  Kind.REOPENED: "open (reopened)"}.get(change.kind, "open")
        rows.append({"asset": asset.label, "owner": asset.owner or "unassigned", "site": asset.site,
                     "status": status, "port": f"{f.key[2]}/{f.key[3]}",
                     "first_found": f.first_found.date().isoformat() if f.first_found else ""})
    return sorted(rows, key=lambda r: (r["status"], r["asset"]))


def build_card(delta: Delta, decision: Decision, ledger: Ledger, kev: KevCatalog, edition: str = "analyst",
               limit: int = 5) -> dict:
    if edition not in EDITIONS:
        raise ValueError(f"edition must be one of {EDITIONS}")
    order = [a.cve for a in decision.fresh_alerts]
    for r in ranked(delta):
        if r.cve not in order:
            order.append(r.cve)
    if decision.lead and decision.lead in order:
        order.remove(decision.lead)
        order.insert(0, decision.lead)
    reasons = {a.cve: a.reasons for a in decision.alerts}
    items = []
    for cve in order[:limit]:
        v = lambda p, d=None: ledger.value(cve, p, d)  # noqa: E731
        entry = kev.get(cve)
        steps = []
        if v("cve.open_assets", 0):
            steps.append(("Follow CISA's required action" if entry else "Apply the vendor fix") +
                         f" for {cve}, then rescan the affected assets to confirm.")
        if v("cve.unverified_assets", 0):
            steps.append(f"Rescan the {v('cve.unverified_assets')} asset(s) that missed the last cycle before "
                         f"counting them as fixed.")
        if not v("cve.owners"):
            steps.append("Assign an owner: no Owner tag is set on the affected assets.")
        item = {
            "cve": cve, "name": v("cve.name"), "severity": v("cve.severity"),
            "why_now": reasons.get(cve, []),
            "open_assets": v("cve.open_assets", 0), "new_exposure_assets": v("cve.new_exposure_assets", 0),
            "new_visibility_assets": v("cve.new_visibility_assets", 0),
            "unverified_assets": v("cve.unverified_assets", 0), "fixed_assets": v("cve.fixed_assets", 0),
            "internal_deadline": v("cve.internal_due"), "overdue_assets": v("cve.overdue_assets", 0),
            "oldest_open_days": v("cve.oldest_open_days"),
            "owners": list(v("cve.owners", ())),
            "kev": {"listed": bool(entry), "date_added": entry.date_added if entry else None,
                    "known_ransomware_use": entry.ransomware if entry else None,
                    "required_action": entry.required_action if entry else None,
                    "catalog_due_date": entry.due_date if entry else None,
                    "catalog_due_date_note": "KEV catalog metadata; your deadline is the internal SLA date."
                    if entry else None},
            "epss_percent": v("cve.epss_percent"),
            "next_steps": steps,
            "evidence": [f.id for f in ledger.facts if f.subject == cve and
                         (edition == "analyst" or f.predicate != "cve.affected_hosts")],
        }
        if edition == "analyst":
            item["assets"] = _asset_rows(delta, cve)
        items.append(item)
    t = lambda p: ledger.value("tenant", p)  # noqa: E731
    card = {
        "product": "Exposure Radio", "edition": edition, "episode": decision.episode,
        "decision": decision.kind, "as_of": ledger.clock.isoformat(timespec="minutes"),
        "ledger": ledger.id, "items": items,
        "changes": {"new_exposure_findings": t("tenant.new_exposure_findings"),
                    "new_visibility_findings": t("tenant.new_visibility_findings"),
                    "newly_scanned_assets": t("tenant.new_visibility_assets"),
                    "verified_fixed_findings": t("tenant.fixed_findings"),
                    "unverified_findings": t("tenant.unverified_findings"),
                    "missed_assets": t("tenant.unverified_assets"),
                    "coverage": f"{t('tenant.assets_scanned')}/{t('tenant.assets_total')}",
                    "export_complete": t("tenant.export_complete")},
        "health": decision.health,
        "policy_log": decision.log,
        "sources": ledger.sources,
        "notes": ["Priority findings are critical or high severity.",
                  "A finding that disappears from an asset that was not rescanned is unverified, not fixed.",
                  "EPSS estimates the probability of exploitation activity in the next 30 days; "
                  "it is not the probability that this environment is breached."],
    }
    if edition == "executive":
        leaks = find_leaks(json.dumps(card), ledger)
        if leaks:
            raise RedactionError(f"executive card would expose {len(leaks)} system identifier(s)")
    return card


def find_leaks(text: str, ledger: Ledger) -> list[str]:
    return sorted(t for t in ledger.sensitive_terms
                  if len(t) >= 3 and re.search(rf"(?<![\w.-]){re.escape(t)}(?![\w-])", text, re.I))


def card_markdown(card: dict) -> str:
    out = [f"# Exposure Radio action card ({card['edition']} edition)", "",
           f"Decision: **{card['decision'].replace('_', ' ').title()}**  |  As of {card['as_of']}  |  "
           f"Episode `{card['episode']}`  |  Ledger `{card['ledger']}`", ""]
    for i, item in enumerate(card["items"], 1):
        kev = item["kev"]
        out += [f"## {i}. {item['cve']}: {item['name']}", ""]
        if item["why_now"]:
            out.append(f"Why now: {'; '.join(item['why_now'])}.")
        facts = [f"Open on {item['open_assets']}", f"unverified {item['unverified_assets']}",
                 f"verified fixed {item['fixed_assets']}"]
        out.append(f"Status: {', '.join(facts)}.")
        if kev["listed"]:
            out.append(f"CISA KEV: listed {kev['date_added']}"
                       f"{', known ransomware use' if kev['known_ransomware_use'] else ''}. "
                       f"Catalog due date {kev['catalog_due_date']} ({kev['catalog_due_date_note']})")
            out.append(f"CISA required action: {kev['required_action']}")
        if item["epss_percent"] is not None:
            out.append(f"EPSS: {item['epss_percent']}% (exploitation activity, next 30 days).")
        if item["internal_deadline"]:
            out.append(f"Internal deadline: {item['internal_deadline']}; overdue on {item['overdue_assets']} "
                       f"asset(s); oldest open {item['oldest_open_days']} day(s).")
        out.append(f"Owners: {', '.join(item['owners']) or 'unassigned'}.")
        out += ["", "Next steps:"] + [f"- [ ] {step}" for step in item["next_steps"]]
        if item.get("assets"):
            out += ["", "| Asset | Owner | Status | Port | First found |", "|---|---|---|---|---|"]
            out += [f"| {r['asset']} | {r['owner']} | {r['status']} | {r['port']} | {r['first_found']} |"
                    for r in item["assets"]]
        out += ["", f"Evidence: {', '.join(item['evidence'])}", ""]
    c = card["changes"]
    out += ["## What changed", "",
            f"- New exposure on already-scanned assets: {c['new_exposure_findings']} priority finding(s)",
            f"- New visibility: {c['new_visibility_findings']} priority finding(s) from "
            f"{c['newly_scanned_assets']} newly scanned asset(s)",
            f"- Verified fixed: {c['verified_fixed_findings']}",
            f"- Unverified: {c['unverified_findings']} on {c['missed_assets']} missed asset(s)",
            f"- Coverage: {c['coverage']} assets scanned this cycle; export complete: {c['export_complete']}", ""]
    if card["health"]:
        out += ["## Data health", ""] + [f"- {h}" for h in card["health"]] + [""]
    out += ["## Sources", ""] + [f"- {k}: {v}" for k, v in card["sources"].items()] + [""]
    out += [f"_{n}_" for n in card["notes"]]
    return "\n".join(out) + "\n"
