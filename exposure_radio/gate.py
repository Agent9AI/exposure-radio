"""The claim gate: nothing is spoken unless every sentence is supported.

Two paths reach the same ledger:

1. Template sentences are parsed back into structured claims and validated.
2. Any other text (model prose, a pasted summary, a hand edit) goes through an
   extractor that recognises the failure shapes that slip past token matching:
   wrong relation ("fixed" where the evidence says open), number words,
   negation, all-clear statements and directives. In strict mode, a sentence
   that makes no checkable claim and is not on the fixed allowlist is blocked.

A script that passes gets a receipt bound to the ledger and the exact text.
Audio is only rendered for a script whose receipt matches.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from .claims import (CVE_RE, FIXED_LINES, Claim, Verdict, check_requires, normalize_sentence, parse_sentence,
                     validate_claim)
from .ledger import Ledger
from .numbers import NUMBER_RE, to_int

SUPPORTED, BLOCKED, UNVERIFIABLE = "supported", "blocked", "unverifiable"

_FIX = r"(?:fixed|patched|remediated|resolved|closed|mitigated|cleared|cleaned up|addressed|eliminated)"
_OPEN = r"(?:open|vulnerable|exposed|unpatched|affected|outstanding|present|detected|found|unresolved)"
_NEW = r"(?:new|newly|appeared|introduced)"
_KEV = r"(?:\bKEV\b|known[- ]exploited|exploited (?:list|catalog|vulnerabilit(?:y|ies))|CISA(?:'s)? (?:list|catalog))"
_NEG = re.compile(r"\b(?:not|isn't|aren't|wasn't|weren't|never|no longer|nor)\b", re.I)
_UNIT = r"(?:assets?|hosts?|systems?|servers?|devices?|machines?|endpoints?|boxes|nodes?)"
_DIRECTIVE = re.compile(
    r"^(?:please\s+|so\s+|now\s+|just\s+)?(?:disable|turn off|switch off|ignore|stop|skip|delete|remove|uninstall|"
    r"shut down|pause|suspend|deprioriti[sz]e|suppress|mute|silence|accept|exempt|whitelist|allowlist|bypass|"
    r"close|defer|postpone|forget|drop)\b"
    r"|\byou (?:can|could|should|may|must|might) (?:now |safely |simply |just )?(?:disable|turn off|ignore|stop|skip|"
    r"delete|remove|uninstall|pause|suppress|mute|accept|defer|postpone|close|relax|forget)\b"
    r"|\bno need to\b|\bnothing (?:needs|to do)\b|\b(?:safe|okay|ok) to (?:ignore|disable|defer|skip)\b"
    r"|\b(?:ignore|disregard|forget) (?:all |any |the )?(?:prior|previous|above|earlier) (?:instructions|rules)\b",
    re.I)
_ALL_CLEAR = re.compile(
    r"\b(?:everything|all|it|we|you|the (?:environment|network|estate|tenant))(?:'s| is| are| looks?| seems?)"
    r" (?:now |all |fully |completely )?(?:safe|fine|secure|clear|clean|good|ok|okay|protected|patched|green)\b"
    r"|\ball clear\b|\bnothing to worry\b|\bno (?:further )?action (?:is )?(?:needed|required)\b"
    r"|\b(?:fully|completely) (?:patched|remediated|secured?)\b"
    r"|\bno (?:open |known |remaining |outstanding |critical |exploitable )*(?:risks?|issues|vulnerabilit(?:y|ies)|"
    r"exposures?|criticals|kevs?|threats?|problems)\b"
    r"|\bnot (?:at risk|exposed|vulnerable)\b|\bzero risk\b|\brisk[- ]free\b", re.I)


@dataclass
class SentenceVerdict:
    text: str
    status: str
    reasons: list[str] = field(default_factory=list)
    claims: list[Verdict] = field(default_factory=list)
    template: str | None = None

    @property
    def ok(self) -> bool:
        return self.status == SUPPORTED

    def as_dict(self) -> dict:
        return {"text": self.text, "status": self.status, "reasons": self.reasons,
                "template": self.template, "claims": [c.as_dict() for c in self.claims]}


def split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z\"'(])", normalize_sentence(text))
    return [p for p in parts if p]


def _mentions(term: str, text: str) -> bool:
    return re.search(rf"(?<![\w.-]){re.escape(term)}(?![\w-])", text, re.I) is not None


def _named_systems(text: str, ledger: Ledger) -> list[str]:
    return sorted(t for t in ledger.sensitive_terms if len(t) >= 3 and _mentions(t, text))


def _count_near_unit(text: str) -> int | None:
    m = re.search(rf"({NUMBER_RE.pattern})\s+(?:\w+\s+){{0,2}}?{_UNIT}\b", text, re.I)
    if m:
        return to_int(m.group(1))
    m = re.search(rf"\b(?:all|every|each)\b(?:\s+\w+){{0,2}}?\s+{_UNIT}\b|\beverywhere\b", text, re.I)
    if m:
        return -1   # "all"
    return None


def _extract(sentence: str, ledger: Ledger) -> tuple[list[Claim], list[str], bool]:
    """Heuristic extraction for text that is not template output.

    Returns (claims to validate, direct rejection reasons, made_checkable_statement).
    """
    claims: list[Claim] = []
    reasons: list[str] = []
    factual = False
    s = sentence

    if _DIRECTIVE.search(s):
        reasons.append("directive outside the action catalog")
        factual = True
    if _ALL_CLEAR.search(s):
        open_kev = ledger.value("tenant", "tenant.open_kev_cves", 0)
        open_pri = ledger.value("tenant", "tenant.open_priority_findings", 0)
        reasons.append(f"all-clear statement; evidence shows {open_pri} open priority findings and "
                       f"{open_kev} exploited CVEs open")
        factual = True

    cves = list(dict.fromkeys(c.upper() for c in re.findall(CVE_RE, s, re.I)))
    known = ledger.subjects
    for cve in cves:
        if cve not in known:
            reasons.append(f"no evidence about {cve} in this tenant")
            factual = True
    cves = [c for c in cves if c in known]
    negated = bool(_NEG.search(s))

    for cve in cves:
        factual = True
        count = _count_near_unit(s)
        if re.search(_FIX, s, re.I):
            if negated:
                if count is not None and count >= 0:
                    claims.append(Claim(cve, "cve.open_assets", count))
            elif count == -1:
                open_now = ledger.value(cve, "cve.open_assets", 0)
                if open_now:
                    reasons.append(f"says {cve} is fixed everywhere; evidence says still open on {open_now}")
            elif count is not None:
                claims.append(Claim(cve, "cve.fixed_assets", count))
            else:
                open_now = ledger.value(cve, "cve.open_assets", 0)
                if open_now:
                    reasons.append(f"says {cve} is fixed; evidence says still open on {open_now}")
        elif re.search(_NEW, s, re.I) and count is not None and count >= 0:
            claims.append(Claim(cve, "cve.new_exposure_assets", count))
        elif re.search(_OPEN, s, re.I) and count is not None and count >= 0:
            claims.append(Claim(cve, "cve.open_assets", count))
        if re.search(_KEV, s, re.I):
            m = re.search(r"\b(\d{4}-\d{2}-\d{2})\b", s)
            if m and re.search(r"\badded\b", s, re.I):
                claims.append(Claim(cve, "cve.kev_added", m.group(1)))
            claims.append(Claim(cve, "cve.in_kev", not negated))
        if re.search(r"ransomware", s, re.I):
            claims.append(Claim(cve, "cve.kev_ransomware", not negated))
        if re.search(r"\bEPSS\b", s, re.I):
            m = re.search(r"(\d+(?:\.\d+)?)\s*(?:%|percent)", s, re.I)
            if m:
                claims.append(Claim(cve, "cve.epss_percent", int(round(float(m.group(1))))))
        m = re.search(rf"({NUMBER_RE.pattern})\s+days?\b", s, re.I)
        if m and re.search(r"\bopen\b", s, re.I):
            claims.append(Claim(cve, "cve.oldest_open_days", to_int(m.group(1))))
        hosts = [h for h in _named_systems(s, ledger)]
        if hosts:
            claims.append(Claim(cve, "cve.affected_hosts", tuple(hosts)))

    if not cves and not reasons:
        number = NUMBER_RE.search(s)
        if number and re.search(r"\b(?:priority|critical or high)\b", s, re.I) and re.search(_OPEN, s, re.I):
            claims.append(Claim("tenant", "tenant.open_priority_findings", number.group(0)))
            factual = True
        elif number or re.search(r"\b(?:CVE|vulnerab|exploit|patch|fix|asset|host|finding)", s, re.I):
            factual = True
    return claims, reasons, factual


def audit_sentence(sentence: str, ledger: Ledger, strict: bool = True, allow_hosts: bool = False) -> SentenceVerdict:
    s = normalize_sentence(sentence)
    if s in FIXED_LINES:
        return SentenceVerdict(s, SUPPORTED, ["fixed line"])
    reasons: list[str] = []
    if not allow_hosts:
        named = _named_systems(s, ledger)
        if named:
            reasons.append(f"names tenant systems ({len(named)}); hostnames, IPs and asset IDs never air")

    parsed = parse_sentence(s)
    if parsed:
        verdicts = [validate_claim(c, ledger) for c in parsed.claims]
        reasons += [v.reason for v in verdicts if not v.ok]
        for claim in parsed.claims:
            # Names can originate in scanner text; a true "name" may still carry an instruction.
            if claim.predicate == "cve.name" and (_DIRECTIVE.search(str(claim.value)) or
                                                  _ALL_CLEAR.search(str(claim.value))):
                reasons.append("name text carries an instruction or all-clear; not spoken")
        missing = check_requires(parsed, ledger)
        if missing:
            reasons.append(missing)
        return SentenceVerdict(s, BLOCKED if reasons else SUPPORTED, reasons or ["template claims supported"],
                               verdicts, parsed.template.id)

    claims, direct, factual = _extract(s, ledger)
    verdicts = [validate_claim(c, ledger) for c in claims]
    reasons += direct + [v.reason for v in verdicts if not v.ok]
    if strict:
        reasons.append("free text outside the controlled vocabulary")
        return SentenceVerdict(s, BLOCKED, reasons, verdicts)
    if reasons:
        return SentenceVerdict(s, BLOCKED, reasons, verdicts)
    if not verdicts:
        why = "factual statement that cannot be checked" if factual else "no checkable claim"
        return SentenceVerdict(s, UNVERIFIABLE, [why], verdicts)
    return SentenceVerdict(s, SUPPORTED, ["extracted claims supported"], verdicts)


def audit_text(text: str, ledger: Ledger, strict: bool = True, allow_hosts: bool = False) -> list[SentenceVerdict]:
    return [audit_sentence(s, ledger, strict, allow_hosts) for s in split_sentences(text)]


def script_sha256(lines: list[dict]) -> str:
    body = json.dumps([{"voice": l["voice"], "text": l["text"]} for l in lines], ensure_ascii=False)
    return hashlib.sha256(body.encode()).hexdigest()


@dataclass
class GateReport:
    passed: bool
    ledger_id: str
    script_sha: str
    lines: list[list[SentenceVerdict]]

    @property
    def blocked(self) -> list[SentenceVerdict]:
        return [v for line in self.lines for v in line if not v.ok]

    def receipt(self) -> dict:
        checked = sum(len(line) for line in self.lines)
        return {"passed": self.passed, "ledger": self.ledger_id, "script_sha256": self.script_sha,
                "sentences_checked": checked, "sentences_blocked": len(self.blocked)}


def gate_script(lines: list[dict], ledger: Ledger) -> GateReport:
    """Strict check of a spoken script: every sentence must be supported."""
    verdicts = [audit_text(line["text"], ledger, strict=True, allow_hosts=False) for line in lines]
    passed = bool(lines) and all(v.ok for line in verdicts for v in line)
    return GateReport(passed, ledger.id, script_sha256(lines), verdicts)


def receipt_matches(receipt: dict, lines: list[dict], ledger: Ledger) -> bool:
    return (bool(receipt.get("passed")) and receipt.get("ledger") == ledger.id
            and receipt.get("script_sha256") == script_sha256(lines))
