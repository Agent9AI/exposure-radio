"""Structured claims, their validation, and the controlled narration grammar.

A claim is ``(subject, predicate, value, cite)``. It passes only when the
cited fact exists, is about the same subject and predicate, and holds the same
value. Narration is rendered from validated claims through the templates
below, and any rendered sentence can be parsed back into the claims it makes,
so the final script is checked a second time as text.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

from .ledger import PREDICATES, Fact, Ledger
from .numbers import to_int

CVE_RE = r"CVE-\d{4}-\d{4,7}"


@dataclass(frozen=True)
class Claim:
    subject: str
    predicate: str
    value: object
    cite: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Claim":
        return cls(str(data.get("subject", "")), str(data.get("predicate", "")), data.get("value"),
                   data.get("cite") or None)

    def as_dict(self) -> dict:
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        return {"subject": self.subject, "predicate": self.predicate, "value": value, "cite": self.cite}


@dataclass
class Verdict:
    claim: Claim
    ok: bool
    reason: str
    fact: Fact | None = None

    def as_dict(self) -> dict:
        return {"claim": self.claim.as_dict(), "ok": self.ok, "reason": self.reason,
                "fact": self.fact.id if self.fact else None}


def _coerce(value: object, kind: type):
    if kind is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str) and value.strip().lower() in ("true", "yes"):
            return True
        if isinstance(value, str) and value.strip().lower() in ("false", "no"):
            return False
        raise ValueError
    if kind is int:
        if isinstance(value, bool):
            raise ValueError
        if isinstance(value, int):
            return value
        if isinstance(value, float) and value.is_integer():
            return int(value)
        number = to_int(str(value))
        if number is None:
            raise ValueError
        return number
    if kind is tuple:
        if isinstance(value, (list, tuple)):
            return tuple(str(v) for v in value)
        return (str(value),)
    if isinstance(value, (dict, list, tuple)) or value is None:
        raise ValueError
    return str(value).strip()


def _context(ledger: Ledger, subject: str) -> str:
    if not subject.startswith("CVE-"):
        return ""
    parts = []
    for pred, label in (("cve.open_assets", "open on"), ("cve.fixed_assets", "verified fixed on"),
                        ("cve.unverified_assets", "unverified on")):
        value = ledger.value(subject, pred)
        if value is not None:
            parts.append(f"{label} {value}")
    return f" (evidence: {', '.join(parts)})" if parts else ""


def validate_claim(claim: Claim, ledger: Ledger) -> Verdict:
    pred = claim.predicate
    if pred not in PREDICATES:
        return Verdict(claim, False, f"unknown predicate '{pred}'")
    kind = pred.split(".", 1)[0]
    if kind == "cve" and not re.fullmatch(CVE_RE, claim.subject or ""):
        return Verdict(claim, False, f"'{pred}' needs a CVE subject, got '{claim.subject}'")
    if kind in ("tenant", "bulletin") and claim.subject != kind:
        return Verdict(claim, False, f"'{pred}' needs subject '{kind}', got '{claim.subject}'")

    if claim.cite:
        fact = ledger.get(claim.cite)
        if fact is None:
            return Verdict(claim, False, f"cites {claim.cite}, which does not exist")
        if (fact.subject, fact.predicate) != (claim.subject, pred):
            return Verdict(claim, False, f"cites {fact.id}, which is evidence for {fact.subject} "
                                         f"{fact.predicate}, not {claim.subject} {pred}", fact)
    else:
        fact = ledger.find(claim.subject, pred)
        if fact is None:
            if claim.subject not in ledger.subjects:
                return Verdict(claim, False, f"no evidence about {claim.subject} in this tenant")
            return Verdict(claim, False, f"no {pred} evidence for {claim.subject}")

    try:
        value = _coerce(claim.value, PREDICATES[pred])
    except (ValueError, TypeError):
        return Verdict(claim, False, f"value {claim.value!r} is not a valid {PREDICATES[pred].__name__}", fact)

    if PREDICATES[pred] is tuple:
        if not value:
            return Verdict(claim, False, "empty collection is not a supported claim", fact)
        missing = [v for v in value if v not in fact.value]
        if missing:
            return Verdict(claim, False, f"{', '.join(missing)} not in evidence {fact.id}", fact)
    elif PREDICATES[pred] is str:
        if value.casefold() != str(fact.value).casefold():
            return Verdict(claim, False, f"evidence {fact.id} says {fact.value!r}, not {value!r}", fact)
    elif value != fact.value:
        return Verdict(claim, False, f"evidence {fact.id} says {fact.value}, not {value}"
                                     f"{_context(ledger, claim.subject)}", fact)
    return Verdict(claim, True, f"supported by {fact.id}", fact)


def validate_claims(claims: list[Claim], ledger: Ledger) -> list[Verdict]:
    return [validate_claim(c, ledger) for c in claims]


# --- controlled narration grammar ---------------------------------------------------------------

PLURALS = {
    "assets": ("asset", "assets"), "massets": ("asset", "assets"), "findings": ("finding", "findings"),
    "days": ("day", "days"), "were": ("was", "were"), "are": ("is", "are"), "them": ("it", "them"),
    "cves": ("CVE", "CVEs"),
}


@dataclass(frozen=True)
class Template:
    id: str
    text: str
    fields: dict[str, str] = field(default_factory=dict)     # placeholder -> predicate
    implies: tuple[tuple[str, object], ...] = ()              # (predicate, value) asserted
    requires: tuple[tuple[str, str, object], ...] = ()        # (predicate, op, value) preconditions
    subject: str = "cve"                                      # cve | tenant | bulletin
    voice: str = "ANALYST"
    counts: dict[str, str] = field(default_factory=dict)      # plural placeholder -> count field

    def count_field(self, placeholder: str) -> str:
        return self.counts.get(placeholder, "m" if placeholder.startswith("m") else "n")


def _t(id, text, fields=None, implies=(), requires=(), subject="cve", voice="ANALYST", counts=None):
    return Template(id, text, fields or {}, tuple(implies), tuple(requires), subject, voice, counts or {})


TEMPLATES: list[Template] = [
    # bulletin framing (anchor)
    _t("B_BREAK_IN", "Priority bulletin: {cve} needs action today.", {"cve": "bulletin.lead"},
       [("bulletin.decision", "BREAK_IN")], subject="bulletin", voice="ANCHOR"),
    _t("B_SCHEDULED", "Scheduled briefing. The lead item is {cve}.", {"cve": "bulletin.lead"},
       [("bulletin.decision", "SCHEDULED")], subject="bulletin", voice="ANCHOR"),
    _t("B_QUIET", "Scheduled briefing. No item needs action today.", {},
       [("bulletin.decision", "SCHEDULED"), ("bulletin.lead", "")], subject="bulletin", voice="ANCHOR"),
    _t("B_HEALTH", "Data health notice: this edition cannot confirm fixes.", {},
       [("bulletin.decision", "HEALTH")], subject="bulletin", voice="ANCHOR"),
    # per-CVE evidence (analyst)
    _t("C_NAME", "{cve} is listed as {name}.", {"name": "cve.name"}),
    _t("C_SEVERITY", "The scanner rates {cve} as {name} severity.", {"name": "cve.severity"}),
    _t("C_KEV_NEW", "CISA listed {cve} as exploited since the last briefing.", {},
       [("cve.kev_newly_listed", True)]),
    _t("C_KEV_ADDED", "CISA added {cve} to its Known Exploited Vulnerabilities catalog on {date}.",
       {"date": "cve.kev_added"}, [("cve.in_kev", True)]),
    _t("C_KEV_TRUE", "{cve} is in CISA's Known Exploited Vulnerabilities catalog.", {}, [("cve.in_kev", True)]),
    _t("C_KEV_FALSE", "{cve} is not in CISA's Known Exploited Vulnerabilities catalog.", {},
       [("cve.in_kev", False)]),
    _t("C_RANSOMWARE", "CISA reports known ransomware use of {cve}.", {}, [("cve.kev_ransomware", True)]),
    _t("C_OPEN", "{cve} is open on {n} {assets}.", {"n": "cve.open_assets"}),
    _t("C_NEW_EXPOSURE", "{cve} newly appeared on {n} {assets} that were already being scanned.",
       {"n": "cve.new_exposure_assets"}, requires=[("cve.new_exposure_assets", ">", 0)]),
    _t("C_NEW_VISIBILITY", "{cve} was found on {n} {assets} newly scanned or newly credentialed.",
       {"n": "cve.new_visibility_assets"}, requires=[("cve.new_visibility_assets", ">", 0)]),
    _t("C_FIXED", "{cve} was verified fixed on {n} {assets} by a rescan.", {"n": "cve.fixed_assets"}, requires=[("cve.fixed_assets", ">", 0)]),
    _t("C_UNVERIFIED", "{cve} was not re-checked on {n} {assets}; treat {them} as unverified, not fixed.",
       {"n": "cve.unverified_assets"}, requires=[("cve.unverified_assets", ">", 0)]),
    _t("C_EPSS", "FIRST's EPSS model puts the chance of exploitation activity for {cve} in the next 30 days "
                 "at {n} percent.", {"n": "cve.epss_percent"}),
    _t("C_AGE", "{cve} has been open for {n} {days} on the longest-exposed asset.", {"n": "cve.oldest_open_days"}),
    _t("C_OVERDUE", "{cve} is past your internal deadline on {n} {assets}.", {"n": "cve.overdue_assets"}, requires=[("cve.overdue_assets", ">", 0)]),
    _t("C_DUE", "Your internal deadline for {cve} is {date}.", {"date": "cve.internal_due"}),
    # what changed (analyst)
    _t("T_EXPOSURE_GREW", "Exposure grew by {n} priority {findings} on assets that were already being scanned.",
       {"n": "tenant.new_exposure_findings"}, subject="tenant"),
    _t("T_EXPOSURE_FLAT", "No new priority findings appeared on assets that were already being scanned.", {},
       [("tenant.new_exposure_findings", 0)], subject="tenant"),
    _t("T_VISIBILITY", "Visibility grew: {n} priority {findings} came from {m} newly scanned or newly credentialed {massets}.",
       {"n": "tenant.new_visibility_findings", "m": "tenant.new_visibility_assets"}, subject="tenant"),
    _t("T_FIXED", "{n} priority {findings} {were} verified fixed by a rescan.", {"n": "tenant.fixed_findings"},
       subject="tenant"),
    _t("T_MISSED", "{n} {assets} missed this scan cycle.", {"n": "tenant.unverified_assets"}, subject="tenant"),
    _t("T_UNVERIFIED", "{n} open priority {findings} on missed assets {are} unverified, not fixed.",
       {"n": "tenant.unverified_findings"}, subject="tenant"),
    _t("T_COVERAGE", "This cycle scanned {n} of {m} known assets.",
       {"n": "tenant.assets_scanned", "m": "tenant.assets_total"}, subject="tenant"),
    _t("T_PRIORITY_OPEN", "{n} priority {findings} {are} open.", {"n": "tenant.open_priority_findings"},
       subject="tenant"),
    _t("T_KEV_OPEN", "{n} {cves} on CISA's exploited list {are} open in your environment.",
       {"n": "tenant.open_kev_cves"}, subject="tenant"),
    _t("T_INCOMPLETE", "The latest export is incomplete, so this edition confirms no fixes.", {},
       [("tenant.export_complete", False)], subject="tenant"),
    # actions (anchor); each is valid only when its precondition holds in the evidence
    _t("A_KEV_ACTION", "Next step: follow CISA's required action for {cve}, then rescan to confirm.", {}, (),
       [("cve.in_kev", "==", True), ("cve.open_assets", ">", 0)], voice="ANCHOR"),
    _t("A_PATCH", "Next step: apply the vendor fix for {cve}, then rescan to confirm.", {}, (),
       [("cve.open_assets", ">", 0)], voice="ANCHOR"),
    _t("A_RESCAN", "Then rescan the {n} {assets} where {cve} was not re-checked.", {"n": "cve.unverified_assets"},
       (), [("cve.unverified_assets", ">", 0)], voice="ANCHOR"),
    _t("A_REVIEW_NEW", "Review the {n} newly scanned {assets} before the next cycle.",
       {"n": "tenant.new_visibility_assets"}, (), [("tenant.new_visibility_assets", ">", 0)],
       subject="tenant", voice="ANCHOR"),
]
BY_ID = {t.id: t for t in TEMPLATES}

# The only sentences that may air without a citation.
FIXED_LINES = {
    "This is Exposure Radio.",
    "Here is what changed since the last briefing.",
    "Second item.",
    "The action card has the affected assets, owners and evidence.",
    "That is the bulletin.",
}

_NUM = r"[0-9]+|[a-z]+(?:[ -]+[a-z]+)*"


def _compile(t: Template) -> re.Pattern:
    out, pos = [], 0
    for m in re.finditer(r"\{(\w+)\}", t.text):
        out.append(re.escape(t.text[pos:m.start()]))
        name = m.group(1)
        if name == "cve":
            out.append(f"(?P<cve>{CVE_RE})")
        elif name in ("n", "m"):
            out.append(f"(?P<{name}>{_NUM})")
        elif name == "date":
            out.append(r"(?P<date>\d{4}-\d{2}-\d{2})")
        elif name == "name":
            out.append(r"(?P<name>.+?)")
        elif name in PLURALS:
            one, many = PLURALS[name]
            out.append(f"(?P<{name}>{re.escape(one)}|{re.escape(many)})")
        pos = m.end()
    out.append(re.escape(t.text[pos:]))
    return re.compile("".join(out), re.IGNORECASE)


_PATTERNS = [(t, _compile(t)) for t in TEMPLATES]


def normalize_sentence(text: str) -> str:
    text = "".join(c for c in unicodedata.normalize("NFKC", text) if unicodedata.category(c) != "Cf")
    text = text.replace("’", "'").replace("‘", "'").replace("“", '"').replace("”", '"')
    return re.sub(r"\s+", " ", text).strip()


def render(template_id: str, **values) -> str:
    t = BY_ID[template_id]

    def sub(m: re.Match) -> str:
        name = m.group(1)
        if name in PLURALS:
            one, many = PLURALS[name]
            return one if int(values[t.count_field(name)]) == 1 else many
        return str(values[name])

    return re.sub(r"\{(\w+)\}", sub, t.text)


@dataclass
class Parsed:
    template: Template
    claims: list[Claim]
    subject: str


def parse_sentence(sentence: str) -> Parsed | None:
    """Map a sentence back to the claims it makes, if it is template output."""
    s = normalize_sentence(sentence)
    for t, pattern in _PATTERNS:
        m = pattern.fullmatch(s)
        if not m:
            continue
        groups = m.groupdict()
        subject = groups.get("cve", "").upper() if t.subject == "cve" else t.subject
        agreement_ok = True
        for placeholder in PLURALS:
            if groups.get(placeholder):
                count = to_int(groups.get(t.count_field(placeholder), ""))
                if count is None or groups[placeholder].lower() != PLURALS[placeholder][count != 1].lower():
                    agreement_ok = False
                    break
        if not agreement_ok:
            continue
        claims = []
        for placeholder, predicate in t.fields.items():
            raw = groups.get(placeholder)
            if placeholder == "cve":
                raw = raw.upper()
            claims.append(Claim(subject, predicate, raw))
        for predicate, value in t.implies:
            claims.append(Claim(subject, predicate, value))
        return Parsed(t, claims, subject)
    return None


def check_requires(parsed: Parsed, ledger: Ledger) -> str | None:
    """Return a failure reason when an action's precondition does not hold."""
    for predicate, op, expected in parsed.template.requires:
        actual = ledger.value(parsed.subject, predicate)
        if actual is None:
            return f"no {predicate} evidence for {parsed.subject}"
        if op == ">" and not actual > expected:
            return f"action needs {predicate} > {expected}; evidence says {actual}"
        if op == "==" and actual != expected:
            return f"action needs {predicate} = {expected}; evidence says {actual}"
    return None
