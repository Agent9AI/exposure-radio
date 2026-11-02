"""Second-pass audit of rendered narration text.

The structural gate (claims validated, templates rendered) is the primary
control. This module is the belt to that brace: it looks at the finished
sentences as text and rejects anything that does not belong in a spoken
security briefing, whatever produced it.

Checks:

* STRUCTURE: every sentence is exactly the output of its segment's
  template applied to its validated claims; nothing else is speech.
* IDENTIFIER_LEAK / HOSTNAME_LEAK / IP_LEAK / ASSET_ID_LEAK: tenant
  identifiers from the exports (exact dictionary) and anything shaped like a
  DNS name, an IP address or a UUID.
* PLUGIN_TEXT_LEAK: scanner-supplied plugin names.
* UNKNOWN_CVE: a CVE identifier the ledger has no facts about.
* NUMBER_WORD: numbers spelled as words (templates use digits, so a number
  word means the sentence did not come from a template).
* NEGATION: negation tokens; the vocabulary states what is, never what is
  not, because a dropped "not" inverts a sentence.
* ALL_CLEAR: reassurance phrases that no fact can support.
* DIRECTIVE: operational instructions other than patch/update.
* EMPTY / LENGTH / CONTROL: hygiene.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence

from .claims import validate_claim
from .facts import FactStore
from .model import Export
from .templates import Segment, TemplateError, all_template_ids, render_segment

STRUCTURE = "STRUCTURE"
IDENTIFIER_LEAK = "IDENTIFIER_LEAK"
HOSTNAME_LEAK = "HOSTNAME_LEAK"
IP_LEAK = "IP_LEAK"
ASSET_ID_LEAK = "ASSET_ID_LEAK"
PLUGIN_TEXT_LEAK = "PLUGIN_TEXT_LEAK"
UNKNOWN_CVE = "UNKNOWN_CVE"
NUMBER_WORD = "NUMBER_WORD"
NEGATION = "NEGATION"
ALL_CLEAR = "ALL_CLEAR"
DIRECTIVE = "DIRECTIVE"
EMPTY = "EMPTY"
LENGTH = "LENGTH"
CONTROL = "CONTROL"
CVE_PRESENT = "CVE_PRESENT"

MAX_SENTENCE_CHARS = 400

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_HOSTNAME_RE = re.compile(
    r"(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}(?![\w-])",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(
    r"(?<![\w:.])(?:"
    r"(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}"  # full form
    r"|(?:[0-9a-f]{1,4}:){1,7}:(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})?"  # compressed, groups before ::
    r"|::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6})"  # compressed, leading ::
    r")(?![\w:])",
    re.IGNORECASE,
)
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.IGNORECASE)

_NUMBER_WORDS = (
    "zero one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen sixteen "
    "seventeen eighteen nineteen twenty thirty forty fifty sixty seventy eighty ninety hundred thousand "
    "million billion dozen dozens half twice couple several few many most none"
).split()
_NUMBER_RE = re.compile(r"\b(?:" + "|".join(_NUMBER_WORDS) + r")\b", re.IGNORECASE)

_NEGATION_RE = re.compile(
    r"\b(?:not|no|never|none|nothing|neither|nor|cannot|without|unaffected|unexposed|unexploited|"
    r"isn't|aren't|wasn't|weren't|doesn't|don't|didn't|won't|can't|hasn't|haven't|shouldn't|needn't|"
    r"n't)\b",
    re.IGNORECASE,
)

_ALL_CLEAR_RE = re.compile(
    r"\ball[- ]clear\b|\bfully (?:patched|remediated|fixed|resolved|secured?|protected|compliant)\b|"
    r"\b(?:is|are|you're|we're|everything is|everything's|all|you are|we are) (?:safe|secure|fine|clean|protected|"
    r"covered|good|ok|okay)\b|\bnothing (?:to|left|remains?|else)\b|\bno (?:action|further|critical|open|risk|exposure|"
    r"issues?|concerns?|threat|problems?)\b|\bzero (?:risk|exposure|open|critical|issues?)\b|\brisk[- ]free\b|"
    r"\bclean bill\b|\brelax\b|\bstand down\b",
    re.IGNORECASE,
)

_DIRECTIVE_RE = re.compile(
    r"\b(?:disable|disabling|turn off|switch off|shut down|ignore|ignoring|skip|skipping|stop|suspend|pause|delete|"
    r"remove|uninstall|bypass|whitelist|allow[- ]?list|exempt|suppress|downgrade|accept the risk|roll ?back|defer|"
    r"postpone|silence|mute|do nothing|wait|hold off|decommission|open the firewall|grant|escalate privileges)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Issue:
    code: str
    detail: str
    index: int = -1

    def to_dict(self) -> Dict[str, object]:
        return {"code": self.code, "detail": self.detail, "sentence": self.index}


_TOKEN_RE = re.compile(r"[a-z0-9]+(?:[.:\-][a-z0-9]+)*")
_SEPARATOR_RE = re.compile(r"[.:\-]")


class ForbiddenTerms:
    """Tenant identifiers and scanner text that must never be spoken.

    Identifiers (hostnames, FQDNs, IPs, asset ids) are matched as whole
    tokens bounded by non-alphanumerics, including as a run of parts inside
    a dotted or hyphenated token, so ``fw-edge-01`` is found inside
    ``fw-edge-01.northwind.internal`` and inside ``fw-edge-01-backup``.
    Plugin names are matched with one combined, case-insensitive pattern.
    """

    def __init__(self, identifiers: Iterable[str], plugin_names: Iterable[str]) -> None:
        self.identifiers = tuple(sorted({i for i in identifiers if i}))
        self.plugin_names = tuple(sorted({p for p in plugin_names if p}))
        self._identifier_set = frozenset(i.lower() for i in self.identifiers if len(i) >= 3)
        names = [re.escape(p) for p in self.plugin_names if len(p) >= 3]
        self._plugin_pattern = (
            re.compile(r"(?<![a-z0-9])(?:" + "|".join(sorted(names, key=len, reverse=True)) + r")(?![a-z0-9])", re.IGNORECASE)
            if names
            else None
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, ForbiddenTerms) and (self.identifiers, self.plugin_names) == (other.identifiers, other.plugin_names)

    def __hash__(self) -> int:
        return hash((self.identifiers, self.plugin_names))

    @classmethod
    def from_exports(cls, *exports: Optional[Export], trusted: Iterable[str] = ()) -> ForbiddenTerms:
        """Collect identifiers and plugin names from exports.

        ``trusted`` holds phrases from trusted sources (CISA vendor, product
        and vulnerability names). A plugin name that repeats one of them
        verbatim is CISA's wording, not scanner prose, and is not blocked.
        """
        trusted_lower = {t.strip().lower() for t in trusted if t and t.strip()}
        identifiers = set()
        plugin_names = set()
        for export in exports:
            if export is None:
                continue
            identifiers.update(export.identifiers())
            for finding in export.findings:
                if len(finding.plugin_name) >= 12 and finding.plugin_name.strip().lower() not in trusted_lower:
                    plugin_names.add(finding.plugin_name)
        return cls(identifiers, plugin_names)

    def identifier_in(self, text: str) -> bool:
        if not self._identifier_set:
            return False
        for match in _TOKEN_RE.finditer(text.lower()):
            token = match.group(0)
            if token in self._identifier_set:
                return True
            parts = _SEPARATOR_RE.split(token)
            if len(parts) == 1:
                continue
            separators = _SEPARATOR_RE.findall(token)
            for start in range(len(parts)):
                span = parts[start]
                if span in self._identifier_set:
                    return True
                for end in range(start + 1, len(parts)):
                    span += separators[end - 1] + parts[end]
                    if span in self._identifier_set:
                        return True
        return False

    def plugin_text_in(self, text: str) -> bool:
        return bool(self._plugin_pattern and self._plugin_pattern.search(text))


def audit_sentences(
    sentences: Sequence[str],
    store: FactStore,
    forbidden: Optional[ForbiddenTerms] = None,
    segments: Optional[Sequence[Segment]] = None,
) -> List[Issue]:
    issues: List[Issue] = []
    if not sentences:
        issues.append(Issue(EMPTY, "the script has no sentences"))

    if segments is not None:
        if len(segments) != len(sentences):
            issues.append(Issue(STRUCTURE, f"{len(sentences)} sentences but {len(segments)} segments"))
        for index, segment in enumerate(segments):
            for claim in segment.claims:
                rejection = validate_claim(claim, store)
                if rejection is not None:
                    issues.append(Issue(STRUCTURE, f"segment {index}: {rejection.code}: {rejection.detail}", index))
            try:
                expected = render_segment(segment)
            except TemplateError as exc:
                issues.append(Issue(STRUCTURE, f"segment {index}: {exc}", index))
                continue
            if index < len(sentences) and sentences[index] != expected:
                issues.append(Issue(STRUCTURE, f"sentence {index} is not the output of its template", index))

    known_cves = {cve.upper() for cve in store.cves()}

    for index, sentence in enumerate(sentences):
        if not sentence.strip():
            issues.append(Issue(EMPTY, "empty sentence", index))
            continue
        if len(sentence) > MAX_SENTENCE_CHARS:
            issues.append(Issue(LENGTH, f"sentence has {len(sentence)} characters", index))
        if any(unicodedata.category(ch)[0] == "C" for ch in sentence):
            issues.append(Issue(CONTROL, "control characters in sentence", index))
        if forbidden is not None and forbidden.identifier_in(sentence):
            issues.append(Issue(IDENTIFIER_LEAK, "sentence contains a tenant identifier from the export", index))
        if forbidden is not None and forbidden.plugin_text_in(sentence):
            issues.append(Issue(PLUGIN_TEXT_LEAK, "sentence contains scanner-supplied plugin text", index))
        if _HOSTNAME_RE.search(sentence):
            issues.append(Issue(HOSTNAME_LEAK, "sentence contains a DNS-style name", index))
        if _IPV4_RE.search(sentence) or _IPV6_RE.search(sentence):
            issues.append(Issue(IP_LEAK, "sentence contains an IP address", index))
        if _UUID_RE.search(sentence):
            issues.append(Issue(ASSET_ID_LEAK, "sentence contains a UUID", index))
        for match in _CVE_RE.finditer(sentence):
            if match.group(0).upper() not in known_cves:
                issues.append(Issue(UNKNOWN_CVE, f"{match.group(0)} has no facts in the ledger", index))
        match = _NUMBER_RE.search(sentence)
        if match:
            issues.append(Issue(NUMBER_WORD, f"number word {match.group(0)!r}", index))
        match = _NEGATION_RE.search(sentence)
        if match:
            issues.append(Issue(NEGATION, f"negation {match.group(0)!r}", index))
        match = _ALL_CLEAR_RE.search(sentence)
        if match:
            issues.append(Issue(ALL_CLEAR, f"all-clear phrase {match.group(0)!r}", index))
        match = _DIRECTIVE_RE.search(sentence)
        if match:
            issues.append(Issue(DIRECTIVE, f"directive {match.group(0)!r}", index))
    return issues


# Public reference sites that may appear in packets as citations. Anything
# else shaped like a DNS name is treated as a tenant identifier.
CITATION_HOSTS = frozenset(
    {
        "nvd.nist.gov",
        "www.cisa.gov",
        "cisa.gov",
        "www.tenable.com",
        "tenable.com",
        "epss.empiricalsecurity.com",
        "www.first.org",
        "api.first.org",
        "www.cve.org",
    }
)


def audit_free_text(
    text: str,
    forbidden: Optional[ForbiddenTerms] = None,
    allow_cves: bool = True,
    allowed_hosts: Iterable[str] = CITATION_HOSTS,
) -> List[Issue]:
    """Zero-PII audit for non-narration outputs (alerts, CISO edition, JSON).

    Flags tenant identifiers, DNS names, IPs and UUIDs. With
    ``allow_cves=False`` it also flags CVE identifiers (for alert text).
    DNS names in ``allowed_hosts`` (public citation sites) are permitted.
    """
    issues: List[Issue] = []
    allowed = {h.lower() for h in allowed_hosts}
    allowed.update(t.lower() for t in all_template_ids())  # template ids look like "cve.action"
    if forbidden is not None and forbidden.identifier_in(text):
        issues.append(Issue(IDENTIFIER_LEAK, "text contains a tenant identifier from the export"))
    if forbidden is not None and forbidden.plugin_text_in(text):
        issues.append(Issue(PLUGIN_TEXT_LEAK, "text contains scanner-supplied plugin text"))
    for match in _HOSTNAME_RE.finditer(text):
        token = match.group(0).lower()
        if token.endswith((".json", ".csv", ".py", ".md", ".html", ".mp3", ".vtt", ".nessus", ".txt")):
            continue  # file names in the packet are not hostnames
        if token in allowed:
            continue
        issues.append(Issue(HOSTNAME_LEAK, f"DNS-style name {token!r}"))
        break
    if _IPV4_RE.search(text) or _IPV6_RE.search(text):
        issues.append(Issue(IP_LEAK, "text contains an IP address"))
    if _UUID_RE.search(text):
        issues.append(Issue(ASSET_ID_LEAK, "text contains a UUID"))
    if not allow_cves and _CVE_RE.search(text):
        issues.append(Issue(CVE_PRESENT, "text contains a CVE identifier"))
    return issues
