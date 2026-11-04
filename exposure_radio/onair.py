"""On-air layer: gated captions become a natural two-host conversation.

The claim gate checks the caption, which is the canonical template sentence.
The spoken line is a deterministic rendition of the same template and the
same ledger values, so it makes exactly the same claims in plainer English:
contractions, numbers as words, and a product name instead of a CVE ID read
digit by digit. The ID stays on screen and on the action card.

``verify_segment`` rebuilds every spoken line from the ledger and refuses the
segment if a single word differs, so the rendition cannot drift from evidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

from .claims import BY_ID, PLURALS, parse_sentence
from .feeds import KevCatalog
from .gate import gate_script
from .ledger import Ledger
from .numbers import spoken as words

HOSTS = {
    "avery": {"name": "Avery", "role": "Host", "kokoro": "af_heart", "gemini": "en-us-jori"},
    "cole": {"name": "Cole", "role": "Exposure analyst", "kokoro": "am_michael", "gemini": "en-us-podcaster-1"},
}
VOICE_HOST = {"ANCHOR": "avery", "ANALYST": "cole"}

# Each CVE template has a first-mention and a later-mention rendition.
# {ref} is "the <product> flaw" on first mention; later lines say "it".
SPOKEN: dict[str, str | tuple[str, str]] = {
    "B_BREAK_IN": "We're starting with a priority. One item needs action today: {ref}.",
    "B_SCHEDULED": "Here's your exposure briefing. Leading today: {ref}.",
    "B_QUIET": "Here's your exposure briefing, and nothing needs action today.",
    "B_HEALTH": "A data health note first: this edition can't confirm fixes.",
    "C_NAME": ("CISA lists {ref} as {name}.", "CISA lists it as {name}."),
    "C_SEVERITY": ("The scanner rates {ref} {name}.", "The scanner rates it {name}."),
    "C_KEV_NEW": ("CISA added {ref} to its known exploited list since our last briefing. "
                  "That means attackers are already using it.",
                  "CISA added it to the known exploited list since our last briefing. "
                  "That means attackers are already using it."),
    "C_KEV_ADDED": ("{Ref} has been on CISA's known exploited list since {date}.",
                    "It's been on CISA's known exploited list since {date}."),
    "C_KEV_TRUE": ("{Ref} is on CISA's known exploited list.", "It's on CISA's known exploited list."),
    "C_KEV_FALSE": ("{Ref} isn't on CISA's known exploited list.", "It isn't on CISA's known exploited list."),
    "C_RANSOMWARE": ("CISA says ransomware crews have used {ref}.", "CISA says ransomware crews have used it."),
    "C_OPEN": ("{Ref} is open on {n} {assets} right now.", "It's open on {n} {assets} right now."),
    "C_NEW_EXPOSURE": ("{Ref} showed up on {n} {assets} we were already scanning.",
                       "It showed up on {n} {assets} we were already scanning."),
    "C_NEW_VISIBILITY": ("{Ref} turned up on {n} {assets} we only just started scanning.",
                         "It turned up on {n} {assets} we only just started scanning."),
    "C_FIXED": ("{Ref} is verified fixed on {n} {assets}.", "It's verified fixed on {n} {assets}."),
    "C_UNVERIFIED": ("{n} {assets} with {ref} weren't re-checked, so treat {them} as unverified, not fixed.",
                     "{N} {assets} weren't re-checked, so treat {them} as unverified, not fixed."),
    "C_EPSS": ("EPSS puts the odds of exploitation activity for {ref} in the next thirty days at {n} percent.",
               "EPSS puts the odds of exploitation activity in the next thirty days at {n} percent."),
    "C_AGE": ("{Ref} has been open {n} {days} on the longest-exposed machine.",
              "The oldest one's been open {n} {days}."),
    "C_OVERDUE": ("{Ref} is past our internal deadline on {n} {assets}.",
                  "It's past our internal deadline on {n} {assets}."),
    "C_DUE": ("Our internal deadline for {ref} is {date}.", "Our internal deadline is {date}."),
    "T_EXPOSURE_GREW": "Since the last scan, exposure grew by {n} priority {findings} on machines we already scan.",
    "T_EXPOSURE_FLAT": "No new priority findings on the machines we already scan. That's the good kind of quiet.",
    "T_VISIBILITY": "Visibility's up: {m} newly scanned {massets} brought in {n} priority {findings}. "
                    "That's us seeing more, not things getting worse.",
    "T_FIXED": "{N} priority {findings} {were} verified fixed by a rescan. Nice work, everyone.",
    "T_MISSED": "{N} {assets} missed this scan cycle.",
    "T_UNVERIFIED": "That leaves {n} open priority {findings} we can't verify, so they're not counted as fixed.",
    "T_COVERAGE": "We scanned {n} of {m} known assets this cycle.",
    "T_PRIORITY_OPEN": "{N} priority {findings} {are} open.",
    "T_KEV_OPEN": "{N} {cves} from CISA's exploited list {are} open in our environment.",
    "T_INCOMPLETE": "Heads up: the latest export is incomplete, so we're not confirming any fixes today.",
    "A_KEV_ACTION": ("The move today: follow CISA's required action for {ref}, then rescan to confirm.",
                     "The move today: follow CISA's required action, then rescan to confirm."),
    "A_PATCH": ("The move: apply the vendor fix for {ref}, then rescan to confirm.",
                "The move: apply the vendor fix, then rescan to confirm."),
    "A_RESCAN": ("Then rescan the {n} {assets} where {ref} wasn't re-checked.",
                 "Then rescan the {n} {assets} that weren't re-checked."),
    "A_REVIEW_NEW": "Worth a look before the next cycle: the {n} newly scanned {assets}.",
}

# Claim-free connective lines. Nothing here states a fact about the tenant.
BANTER = {
    "exposure_open": ("avery", "Morning, team. Avery here, with Cole on the exposure desk."),
    "priority_hand": ("avery", "Cole, what are we looking at?"),
    "card": ("avery", "The CVE, the affected machines and the owners are on your action card."),
    "watch_open": ("avery", "What else is on the board, Cole?"),
    "watch_more": ("cole", "The rest of the list is on the action card, ranked."),
    "watch_close": ("avery", "Good. Let's keep moving."),
    "wins_open": ("avery", "Some good news now: the wins."),
    "blind_open": ("avery", "Now the blind spots, because what we can't see matters too."),
    "blind_close": ("cole", "That's the exposure desk. Back to you, Avery."),
    "next_item": ("cole", "Also worth a look."),
}

_MONTHS = ("January February March April May June July August September October November December").split()
_ORD = {1: "first", 2: "second", 3: "third", 5: "fifth", 8: "eighth", 9: "ninth", 12: "twelfth"}


def ordinal(n: int) -> str:
    if n in _ORD:
        return _ORD[n]
    if n < 20:
        return words(n) + "th"
    tens, unit = divmod(n, 10)
    if not unit:
        return words(n)[:-1] + "ieth"
    return words(tens * 10) + "-" + ordinal(unit)


def spoken_date(iso: str, today: date | None = None) -> str:
    d = date.fromisoformat(str(iso)[:10])
    text = f"{_MONTHS[d.month - 1]} {ordinal(d.day)}"
    if today is None or d.year != today.year:
        text += f", {d.year}"
    return text


def product_ref(cve: str, kev: KevCatalog, ledger: Ledger) -> str:
    entry = kev.get(cve)
    if entry and entry.product:
        product = entry.product
        if entry.vendor and not product.lower().startswith(entry.vendor.lower()):
            product = f"{entry.vendor} {product}"
        return f"the {product} flaw"
    severity = ledger.value(cve, "cve.severity") or "priority"
    return f"a {str(severity).lower()} scanner finding"


def _n(value) -> str:
    n = int(value)
    return words(n) if 0 <= n < 1000 else f"{n:,}"


@dataclass
class Turn:
    host: str
    text: str
    caption: str
    template: str | None = None
    subject: str | None = None
    cites: list[str] = field(default_factory=list)
    banter: str | None = None

    def as_dict(self) -> dict:
        return {"host": self.host, "text": self.text, "caption": self.caption, "template": self.template,
                "subject": self.subject, "cites": self.cites, "banter": self.banter}


class _Speaker:
    """Renders spoken lines; tracks which CVEs this segment has already named."""

    def __init__(self, ledger: Ledger, kev: KevCatalog, today: date | None):
        self.ledger, self.kev, self.today = ledger, kev, today
        self.named: set[str] = set()

    def speak(self, template_id: str, subject: str | None) -> str:
        t = BY_ID[template_id]
        form = SPOKEN[template_id]
        later = subject in self.named
        text = form[1 if later else 0] if isinstance(form, tuple) else form
        values: dict[str, object] = {}
        for placeholder, predicate in t.fields.items():
            owner = subject if predicate.startswith("cve.") else predicate.split(".", 1)[0]
            values[placeholder] = self.ledger.value(owner, predicate)
        out = text
        cve = subject if subject and subject.startswith("CVE-") else values.get("cve")
        if isinstance(cve, str) and cve.startswith("CVE-"):
            ref = product_ref(cve, self.kev, self.ledger)
            out = out.replace("{ref}", ref).replace("{Ref}", ref[0].upper() + ref[1:])
            self.named.add(cve)
        for placeholder in PLURALS:
            token = "{" + placeholder + "}"
            if token in out:
                count = int(values[t.count_field(placeholder)])
                one, many = PLURALS[placeholder]
                out = out.replace(token, one if count == 1 else many)
        for name, value in values.items():
            if name in ("n", "m"):
                out = out.replace("{" + name.upper() + "}", _n(value).capitalize())
                out = out.replace("{" + name + "}", _n(value))
            elif name == "date":
                out = out.replace("{date}", spoken_date(value, self.today))
            elif name == "name":
                out = out.replace("{name}", str(value).lower() if template_id == "C_SEVERITY" else str(value))
        if "{" in out:
            raise ValueError(f"unrendered placeholder in {template_id}: {out}")
        return out


def _turn_for(line: dict, speaker: _Speaker) -> Turn:
    parsed = parse_sentence(line["text"])
    if not parsed or parsed.template.id != line["template"]:
        raise ValueError(f"caption is not template output: {line['text']}")
    subject = parsed.subject if parsed.template.subject == "cve" else None
    return Turn(VOICE_HOST[parsed.template.voice], speaker.speak(line["template"], subject), line["text"],
                line["template"], subject, list(line.get("cites", [])))


def _banter(key: str) -> Turn:
    host, text = BANTER[key]
    return Turn(host, text, text, banter=key)


def _cve_blocks(lines: list[dict]) -> tuple[list[dict], list[list[dict]], list[dict]]:
    """Split the template script into its opening, per-CVE blocks and the changes section."""
    head, blocks, tail, current, in_tail = [], [], [], None, False
    for line in lines:
        text = line["text"]
        if text == "Here is what changed since the last briefing.":
            in_tail = True
            continue
        if line["template"] is None:
            if text == "Second item.":
                current = []
                blocks.append(current)
            continue
        if in_tail:
            tail.append(line)
        elif current is None:
            head.append(line)
        else:
            current.append(line)
    return head, blocks, tail


_WATCH_KEEP = {"C_NEW_EXPOSURE", "C_NEW_VISIBILITY", "C_OPEN", "C_RANSOMWARE", "C_OVERDUE"}
_LEAD_SKIP = {"C_NAME"}   # the full catalog name reads badly aloud; it is on screen


def _count(line: dict, ledger: Ledger):
    parsed = parse_sentence(line["text"])
    predicate = parsed.template.fields.get("n") if parsed else None
    if not predicate:
        return None
    owner = parsed.subject if predicate.startswith("cve.") else predicate.split(".", 1)[0]
    return ledger.value(owner, predicate)


def build_segments(lines: list[dict], ledger: Ledger, kev: KevCatalog, decision_kind: str,
                   watch_items: int = 2, today: date | None = None) -> list[dict]:
    """Turn the gated template script into on-air exposure segments."""
    if not lines:
        return []
    head, blocks, tail = _cve_blocks(lines)
    segments = []

    sp = _Speaker(ledger, kev, today)
    turns = [_banter("exposure_open")]
    intro = [l for l in head if l["template"].startswith("B_")]
    turns += [_turn_for(l, sp) for l in intro]
    body = [l for l in head if not l["template"].startswith("B_") and l["template"] not in _LEAD_SKIP]
    if body:
        turns.append(_banter("priority_hand"))
        turns += [_turn_for(l, sp) for l in body]
        turns.append(_banter("card"))
    segments.append({"kind": "exposure", "priority": decision_kind == "BREAK_IN",
                     "title": "Priority: needs action today" if decision_kind == "BREAK_IN" else "Exposure briefing",
                     "turns": turns})

    if blocks:
        sp = _Speaker(ledger, kev, today)
        turns = [_banter("watch_open")]
        for i, block in enumerate(blocks[:watch_items]):
            if i:
                turns.append(_banter("next_item"))
            kept = [l for l in block if l["template"] in _WATCH_KEEP]
            seen = {_count(l, ledger) for l in kept if l["template"] in ("C_NEW_EXPOSURE", "C_NEW_VISIBILITY")}
            # "showed up on three assets" already says how many; skip "open on three assets" when equal
            kept = [l for l in kept if not (l["template"] == "C_OPEN" and _count(l, ledger) in seen)]
            turns += [_turn_for(l, sp) for l in kept]
        if len(blocks) > watch_items:
            turns.append(_banter("watch_more"))
        turns.append(_banter("watch_close"))
        grew = [l for l in tail if l["template"] in ("T_INCOMPLETE", "T_EXPOSURE_GREW", "T_EXPOSURE_FLAT")]
        turns[1:1] = [_turn_for(l, sp) for l in grew]
        segments.append({"kind": "exposure", "priority": False, "title": "The watch list", "turns": turns})

    sp = _Speaker(ledger, kev, today)
    fixed = [l for l in tail if l["template"] == "T_FIXED"]
    if fixed:
        segments.append({"kind": "wins", "priority": False, "title": "Wins: verified fixed",
                         "turns": [_banter("wins_open")] + [_turn_for(l, sp) for l in fixed]})
    order = ("T_MISSED", "T_UNVERIFIED", "T_COVERAGE", "T_VISIBILITY", "A_REVIEW_NEW")
    blind = sorted((l for l in tail if l["template"] in order), key=lambda l: order.index(l["template"]))
    if blind:
        segments.append({"kind": "blindspots", "priority": False, "title": "Blind spots and coverage",
                         "turns": [_banter("blind_open")] + [_turn_for(l, sp) for l in blind]
                         + [_banter("blind_close")]})
    for seg in segments:
        verify_segment(seg, ledger, kev, today)
        seg["turns"] = [t.as_dict() for t in seg["turns"]]
    return segments


class OnAirError(RuntimeError):
    pass


def verify_segment(segment: dict, ledger: Ledger, kev: KevCatalog, today: date | None = None) -> None:
    """Fresh gate on the captions, then rebuild every spoken line and compare."""
    turns = [t if isinstance(t, Turn) else Turn(**t) for t in segment["turns"]]
    captions = []
    sp = _Speaker(ledger, kev, today)
    for turn in turns:
        if turn.banter is not None:
            if BANTER.get(turn.banter) != (turn.host, turn.text) or turn.caption != turn.text:
                raise OnAirError(f"unrecognised connective line: {turn.text!r}")
            if re.search(r"\d|CVE-", turn.text):
                raise OnAirError("connective lines may not carry numbers or identifiers")
            continue
        parsed = parse_sentence(turn.caption)
        if not parsed or parsed.template.id != turn.template:
            raise OnAirError(f"caption is not template output: {turn.caption!r}")
        subject = parsed.subject if parsed.template.subject == "cve" else None
        if subject != turn.subject or VOICE_HOST[parsed.template.voice] != turn.host:
            raise OnAirError(f"subject or voice mismatch: {turn.caption!r}")
        if sp.speak(turn.template, subject) != turn.text:
            raise OnAirError(f"spoken line drifted from its evidence: {turn.text!r}")
        captions.append({"voice": parsed.template.voice, "text": turn.caption, "template": turn.template,
                         "cites": turn.cites})
    if captions:
        report = gate_script(captions, ledger)
        if not report.passed:
            raise OnAirError("segment captions failed the claim gate")
