"""Deterministic briefing producer.

Builds the ordered list of segments (template + claims) for one episode
from the fact store alone. It never looks at the exports directly, so the
only way a number reaches the script is through a fact that the gate can
check. This is the default "template edition"; the optional analyst agent
may propose a different lead and angle, but it has to use the same
templates and the same facts.
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from .claims import claims_for
from .facts import FactStore
from .templates import Segment

MAX_ITEMS = 3


def _seg(store: FactStore, template_id: str, subject: str, predicates: Sequence[str]) -> Optional[Segment]:
    claims = claims_for(store, subject, predicates)
    if len(claims) != len(predicates):
        return None
    return Segment(template_id, tuple(claims))


def cve_segments(store: FactStore, cve: str, include_change: bool) -> List[Segment]:
    """Segments for one priority item, in speaking order."""
    subject = f"cve:{cve}"
    out: List[Segment] = []
    rank = store.value(subject, "priority_rank")
    head = _seg(store, "cve.lead" if rank == 1 else "cve.item", subject, ("priority_rank", "severity", "open_asset_count"))
    if head is None:
        return out
    out.append(head)
    if store.value(subject, "kev_listed") is True:
        kev = _seg(store, "cve.kev", subject, ("kev_listed", "kev_vendor", "kev_product", "kev_date_added"))
        if kev:
            out.append(kev)
        if store.value(subject, "kev_ransomware_use") is True:
            ransom = _seg(store, "cve.ransomware", subject, ("kev_ransomware_use",))
            if ransom:
                out.append(ransom)
    if store.get(subject, "epss_score") is not None:
        epss = _seg(store, "cve.epss", subject, ("epss_score",))
        if epss:
            out.append(epss)
    if store.value(subject, "exploit_available") is True:
        exploit = _seg(store, "cve.exploit", subject, ("exploit_available",))
        if exploit:
            out.append(exploit)
    if include_change:
        moved = any(
            int(store.value(subject, predicate, 0) or 0) > 0
            for predicate in ("new_exposure_count", "closed_asset_count", "unverified_absence_count")
        )
        change = _seg(store, "cve.change", subject, ("new_exposure_count", "closed_asset_count", "unverified_absence_count"))
        if change and moved:
            out.append(change)
    if int(store.value(subject, "research_count", 0) or 0) > 0:
        research = _seg(store, "cve.research", subject, ("research_count",))
        if research:
            out.append(research)
    action = _seg(store, "cve.action", subject, ("owner", "sla_deadline"))
    if action:
        out.append(action)
    return out


def build_segments(
    store: FactStore,
    synthetic_note: bool = True,
    items: Optional[Sequence[str]] = None,
    max_items: int = MAX_ITEMS,
) -> List[Segment]:
    held = store.value("episode", "held") is True
    has_previous = store.value("delta", "has_previous") is True
    segments: List[Segment] = [Segment("intro.station")]
    if synthetic_note:
        segments.append(Segment("intro.synthetic"))
    for template_id, predicates in (
        ("episode.date", ("export_date",)),
        ("episode.scope", ("asset_count", "finding_count")),
    ):
        seg = _seg(store, template_id, "episode", predicates)
        if seg:
            segments.append(seg)
    if held:
        segments.append(Segment("intro.held"))
    decision = store.value("episode", "decision")
    if isinstance(decision, str):
        template_id = {"BREAK_IN": "decision.break_in", "HEALTH": "decision.health", "SCHEDULED": "decision.scheduled"}.get(decision)
        if template_id:
            seg = _seg(store, template_id, "episode", ("decision",))
            if seg:
                segments.append(seg)
    if has_previous:
        cov = _seg(store, "episode.coverage", "episode", ("assets_rescanned", "assets_not_rescanned", "assets_newly_in_scope"))
        if cov:
            segments.append(cov)
    open_seg = _seg(store, "episode.open", "episode", ("open_critical_count", "open_high_count", "kev_open_cve_count", "kev_open_asset_count"))
    if open_seg:
        segments.append(open_seg)
    if has_previous and not held:
        for template_id, predicates in (
            ("delta.progress", ("critical_closed", "kev_new_entry_count")),
            ("delta.new", ("new_exposure_count", "new_visibility_count")),
        ):
            seg = _seg(store, template_id, "delta", predicates)
            if seg:
                segments.append(seg)
        if int(store.value("delta", "unverified_absence_count", 0) or 0) > 0:
            seg = _seg(store, "delta.unverified", "delta", ("unverified_absence_count",))
            if seg:
                segments.append(seg)
        if int(store.value("delta", "kev_new_entry_count", 0) or 0) > 0:
            seg = _seg(store, "delta.kev_entries", "delta", ("kev_new_entries",))
            if seg:
                segments.append(seg)
    priority = _seg(store, "priority.count", "priority", ("count",))
    if priority:
        segments.append(priority)
    ranked = list(items) if items is not None else list(store.value("priority", "items", ()) or ())
    for cve in ranked[:max_items]:
        segments.extend(cve_segments(store, cve, include_change=has_previous and not held))
    segments.append(Segment("outro.card"))
    segments.append(Segment("outro.end"))
    return segments
