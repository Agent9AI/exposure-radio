"""Narration templates and the fixed-intro allowlist.

Every spoken sentence is either one of the fixed strings in ``FIXED`` or
the output of exactly one template applied to validated claims. Templates
are written to stay clear of the text audit's banned vocabulary: no
negation words, no number words (digits only), no all-clear phrases and no
directive verbs other than "patch" and "update".

Adding a sentence type means adding a template here, a predicate in
``facts``, and tests. That is deliberate (ADR-0001).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Dict, Optional, Sequence, Tuple

from .claims import Claim

MONTHS = (
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
)


class TemplateError(ValueError):
    """A segment does not fit its template."""


def long_date(iso: object) -> str:
    text = str(iso)
    try:
        year, month, day = text[:10].split("-")
        return f"{int(day)} {MONTHS[int(month) - 1]} {int(year)}"
    except (ValueError, IndexError):
        raise TemplateError(f"bad date value {text!r}") from None


def count(n: object, singular: str, plural: Optional[str] = None) -> str:
    try:
        number = int(n)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise TemplateError(f"bad count {n!r}") from None
    if isinstance(n, bool) or number < 0:
        raise TemplateError(f"bad count {n!r}")
    word = singular if number == 1 else (plural or singular + "s")
    return f"{number} {word}"


def percent(score: object) -> str:
    try:
        value = float(score)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        raise TemplateError(f"bad score {score!r}") from None
    if value < 0 or value > 1:
        raise TemplateError(f"score {value} is outside 0..1")
    return f"{value * 100:.1f}"


def join_list(values: object) -> str:
    items = [str(v) for v in (values if isinstance(values, (tuple, list)) else [values])]
    if not items:
        raise TemplateError("empty list")
    if len(items) == 1:
        return items[0]
    return ", ".join(items[:-1]) + " and " + items[-1]


def subject_display(subject: str) -> str:
    if subject.startswith("cve:"):
        return subject[4:]
    return subject


Renderer = Callable[[str, Dict[str, object]], str]


@dataclass(frozen=True)
class Template:
    template_id: str
    subject_kind: str  # episode | delta | cve | priority
    slots: Tuple[str, ...]
    render: Renderer
    requires: Tuple[Tuple[str, object], ...] = ()


# Fixed sentences: the only speech that carries no claim.
FIXED: Dict[str, str] = {
    "intro.station": "This is Exposure Radio.",
    "intro.synthetic": "This episode covers a synthetic estate built for demonstration.",
    "intro.held": "The current export is incomplete, so this edition is held. Closures are withheld until a complete export arrives.",
    "outro.card": "The action card with evidence, owners and deadlines is in your packet.",
    "outro.end": "End of briefing.",
}


def _episode_date(_s: str, v: Dict[str, object]) -> str:
    return f"Your exposure briefing for {long_date(v['export_date'])}."


def _episode_scope(_s: str, v: Dict[str, object]) -> str:
    return (
        f"The current export covers {count(v['asset_count'], 'asset')} with "
        f"{count(v['finding_count'], 'open finding')} above informational."
    )


def _episode_coverage(_s: str, v: Dict[str, object]) -> str:
    return (
        f"{count(v['assets_rescanned'], 'asset was', 'assets were')} rescanned, "
        f"{count(v['assets_not_rescanned'], 'asset was', 'assets were')} absent from this scan, and "
        f"{count(v['assets_newly_in_scope'], 'asset is', 'assets are')} newly in scope."
    )


def _episode_critical(_s: str, v: Dict[str, object]) -> str:
    return (
        f"Open now: {count(v['open_critical_count'], 'critical finding')} and "
        f"{count(v['open_high_count'], 'high finding')}, with "
        f"{count(v['kev_open_cve_count'], 'KEV-listed CVE')} on {count(v['kev_open_asset_count'], 'asset')}."
    )


def _delta_progress(_s: str, v: Dict[str, object]) -> str:
    return (
        f"Since the previous export, {count(v['critical_closed'], 'critical finding was', 'critical findings were')} "
        f"closed on rescanned assets, and {count(v['kev_new_entry_count'], 'CVE', 'CVEs')} in your estate "
        f"{'was' if int(v['kev_new_entry_count']) == 1 else 'were'} added to the CISA KEV catalogue."
    )


def _delta_new(_s: str, v: Dict[str, object]) -> str:
    return (
        f"{count(v['new_exposure_count'], 'finding is', 'findings are')} new exposure on assets scanned before, and "
        f"{count(v['new_visibility_count'], 'finding is', 'findings are')} new visibility from assets new to the scan."
    )


def _delta_unverified(_s: str, v: Dict[str, object]) -> str:
    return (
        f"{count(v['unverified_absence_count'], 'finding', 'findings')} vanished from assets that were absent from "
        f"this scan; they stay open as unverified absences."
    )


def _delta_kev_entries(_s: str, v: Dict[str, object]) -> str:
    return f"KEV additions touching your estate since the previous export: {join_list(v['kev_new_entries'])}."


def _cve_lead(s: str, v: Dict[str, object]) -> str:
    return (
        f"Lead item: {subject_display(s)}, {v['severity']} severity, open on {count(v['open_asset_count'], 'asset')}."
    )


def _cve_item(s: str, v: Dict[str, object]) -> str:
    return (
        f"Item {int(v['priority_rank'])}: {subject_display(s)}, {v['severity']} severity, "
        f"open on {count(v['open_asset_count'], 'asset')}."
    )


def _cve_kev(s: str, v: Dict[str, object]) -> str:
    return (
        f"{subject_display(s)} affects {v['kev_vendor']} {v['kev_product']} and has been on the CISA KEV catalogue "
        f"since {long_date(v['kev_date_added'])}."
    )


def _cve_ransomware(s: str, _v: Dict[str, object]) -> str:
    return f"CISA records known ransomware campaign use for {subject_display(s)}."


def _cve_epss(s: str, v: Dict[str, object]) -> str:
    return f"EPSS puts {subject_display(s)} at {percent(v['epss_score'])} percent probability of exploitation within 30 days."


def _cve_exploit(s: str, _v: Dict[str, object]) -> str:
    return f"A public exploit is available for {subject_display(s)}."


def _cve_change(s: str, v: Dict[str, object]) -> str:
    return (
        f"For {subject_display(s)}: {count(v['new_exposure_count'], 'asset')} newly exposed, "
        f"{count(v['closed_asset_count'], 'asset')} closed, and "
        f"{count(v['unverified_absence_count'], 'absence')} unverified."
    )


def _cve_action(s: str, v: Dict[str, object]) -> str:
    return f"Action: {v['owner']} to patch {subject_display(s)} by {long_date(v['sla_deadline'])} under the internal SLA."


def _cve_research(s: str, v: Dict[str, object]) -> str:
    return f"Tenable Research has published {count(v['research_count'], 'analysis', 'analyses')} of {subject_display(s)}."


def _cve_first_seen(s: str, v: Dict[str, object]) -> str:
    return f"{subject_display(s)} was first seen in this estate on {long_date(v['first_seen'])}."


def _priority_count(_s: str, v: Dict[str, object]) -> str:
    return f"Today there {'is' if int(v['count']) == 1 else 'are'} {count(v['count'], 'priority item')}."


TEMPLATES: Dict[str, Template] = {
    t.template_id: t
    for t in (
        Template("episode.date", "episode", ("export_date",), _episode_date),
        Template("episode.scope", "episode", ("asset_count", "finding_count"), _episode_scope),
        Template(
            "episode.coverage",
            "episode",
            ("assets_rescanned", "assets_not_rescanned", "assets_newly_in_scope"),
            _episode_coverage,
        ),
        Template(
            "episode.open",
            "episode",
            ("open_critical_count", "open_high_count", "kev_open_cve_count", "kev_open_asset_count"),
            _episode_critical,
        ),
        Template("delta.progress", "delta", ("critical_closed", "kev_new_entry_count"), _delta_progress),
        Template("delta.new", "delta", ("new_exposure_count", "new_visibility_count"), _delta_new),
        Template("delta.unverified", "delta", ("unverified_absence_count",), _delta_unverified),
        Template("delta.kev_entries", "delta", ("kev_new_entries",), _delta_kev_entries),
        Template("cve.lead", "cve", ("priority_rank", "severity", "open_asset_count"), _cve_lead, (("priority_rank", 1),)),
        Template("cve.item", "cve", ("priority_rank", "severity", "open_asset_count"), _cve_item),
        Template(
            "cve.kev",
            "cve",
            ("kev_listed", "kev_vendor", "kev_product", "kev_date_added"),
            _cve_kev,
            (("kev_listed", True),),
        ),
        Template("cve.ransomware", "cve", ("kev_ransomware_use",), _cve_ransomware, (("kev_ransomware_use", True),)),
        Template("cve.epss", "cve", ("epss_score",), _cve_epss),
        Template("cve.exploit", "cve", ("exploit_available",), _cve_exploit, (("exploit_available", True),)),
        Template(
            "cve.change",
            "cve",
            ("new_exposure_count", "closed_asset_count", "unverified_absence_count"),
            _cve_change,
        ),
        Template("cve.action", "cve", ("owner", "sla_deadline"), _cve_action),
        Template("cve.research", "cve", ("research_count",), _cve_research),
        Template("cve.first_seen", "cve", ("first_seen",), _cve_first_seen),
        Template("priority.count", "priority", ("count",), _priority_count),
    )
}


@dataclass(frozen=True)
class Segment:
    template_id: str
    claims: Tuple[Claim, ...] = ()

    def to_dict(self) -> Dict[str, object]:
        return {"template": self.template_id, "claims": [c.to_dict() for c in self.claims]}

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> "Segment":
        if not isinstance(data, dict) or not isinstance(data.get("template"), str):
            raise TemplateError("segment needs a template id")
        raw_claims = data.get("claims") or []
        if not isinstance(raw_claims, list) or len(raw_claims) > 8:
            raise TemplateError("segment claims must be a short list")
        return cls(str(data["template"])[:64], tuple(Claim.from_dict(c) for c in raw_claims))


def _subject_matches(kind: str, subject: str) -> bool:
    if kind == "cve":
        return subject.startswith("cve:CVE-")
    return subject == kind


def render_segment(segment: Segment) -> str:
    """Render a segment or raise :class:`TemplateError`.

    The claims are expected to be validated already; this function checks
    only that they fit the template (right predicates, one subject, required
    values present).
    """
    if segment.template_id in FIXED:
        if segment.claims:
            raise TemplateError(f"{segment.template_id} takes no claims")
        return FIXED[segment.template_id]
    template = TEMPLATES.get(segment.template_id)
    if template is None:
        raise TemplateError(f"unknown template {segment.template_id!r}")
    predicates = tuple(c.predicate for c in segment.claims)
    if predicates != template.slots:
        raise TemplateError(f"{segment.template_id} expects {template.slots}, got {predicates}")
    subjects = {c.subject for c in segment.claims}
    if len(subjects) != 1:
        raise TemplateError(f"{segment.template_id} mixes subjects {sorted(subjects)}")
    subject = next(iter(subjects))
    if not _subject_matches(template.subject_kind, subject):
        raise TemplateError(f"{segment.template_id} is about a {template.subject_kind}, not {subject}")
    values = {c.predicate: c.value for c in segment.claims}
    for predicate, required in template.requires:
        if values.get(predicate) != required or type(values.get(predicate)) is not type(required):
            raise TemplateError(f"{segment.template_id} requires {predicate} == {required!r}")
    sentence = template.render(subject, values)
    if "\n" in sentence or not sentence.strip():
        raise TemplateError("template produced an empty or multi-line sentence")
    return sentence


def all_template_ids() -> Sequence[str]:
    return tuple(FIXED) + tuple(TEMPLATES)
