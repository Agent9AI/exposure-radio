"""The gate: claims in, a script and a receipt out.

Order of operations (ADR-0001):

1. every claim in every segment is validated against the fact store;
2. segments whose claims all pass are rendered through their template;
3. the rendered sentences are audited as text (structure, leaks, banned
   vocabulary);
4. a receipt is written. It carries the SHA-256 of the script it approved,
   and audio generation refuses any script whose hash differs.

The gate is strict: one rejected claim or one text issue and ``passed`` is
false. Callers that want to recover (the analyst agent) rewrite and run the
gate again; nothing is "fixed up" inside the gate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple

from .claims import Rejection, validate
from .facts import FactStore
from .templates import Segment, TemplateError, render_segment
from .textaudit import ForbiddenTerms, Issue, audit_sentences


def script_hash(sentences: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(sentences).encode("utf-8")).hexdigest()


@dataclass
class GateReceipt:
    passed: bool
    edition: str
    script_sha256: str
    generated_at: str
    sentence_count: int
    claims_total: int
    claims_accepted: int
    checks: Dict[str, bool]
    rejections: List[Dict[str, object]] = field(default_factory=list)
    issues: List[Dict[str, object]] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    templates_used: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "passed": self.passed,
            "edition": self.edition,
            "script_sha256": self.script_sha256,
            "generated_at": self.generated_at,
            "sentence_count": self.sentence_count,
            "claims_total": self.claims_total,
            "claims_accepted": self.claims_accepted,
            "checks": dict(self.checks),
            "rejections": list(self.rejections),
            "issues": list(self.issues),
            "sources": list(self.sources),
            "templates_used": list(self.templates_used),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def covers(self, sentences: Sequence[str]) -> bool:
        """True when this receipt approved exactly these sentences."""
        return self.passed and script_hash(sentences) == self.script_sha256

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> GateReceipt:
        return cls(
            passed=bool(data.get("passed")),
            edition=str(data.get("edition", "")),
            script_sha256=str(data.get("script_sha256", "")),
            generated_at=str(data.get("generated_at", "")),
            sentence_count=int(data.get("sentence_count", 0) or 0),
            claims_total=int(data.get("claims_total", 0) or 0),
            claims_accepted=int(data.get("claims_accepted", 0) or 0),
            checks={str(k): bool(v) for k, v in (data.get("checks") or {}).items()},  # type: ignore[union-attr]
            rejections=list(data.get("rejections") or []),  # type: ignore[arg-type]
            issues=list(data.get("issues") or []),  # type: ignore[arg-type]
            sources=[str(s) for s in (data.get("sources") or [])],  # type: ignore[union-attr]
            templates_used=[str(s) for s in (data.get("templates_used") or [])],  # type: ignore[union-attr]
        )


@dataclass
class GateResult:
    receipt: GateReceipt
    segments: List[Segment]
    sentences: List[str]
    rejected_segments: List[Tuple[Segment, List[Rejection], Optional[str]]]
    issues: List[Issue]

    @property
    def passed(self) -> bool:
        return self.receipt.passed

    def script_text(self) -> str:
        return "\n".join(self.sentences)


def run_gate(
    segments: Sequence[Segment],
    store: FactStore,
    forbidden: Optional[ForbiddenTerms] = None,
    edition: str = "full",
    now: Optional[str] = None,
) -> GateResult:
    accepted_segments: List[Segment] = []
    sentences: List[str] = []
    rejected: List[Tuple[Segment, List[Rejection], Optional[str]]] = []
    claims_total = 0
    claims_accepted = 0
    sources: Dict[str, None] = {}

    for segment in segments:
        claims_total += len(segment.claims)
        ok_claims, rejections = validate(segment.claims, store)
        if rejections:
            rejected.append((segment, rejections, None))
            continue
        try:
            sentence = render_segment(segment)
        except TemplateError as exc:
            rejected.append((segment, [], str(exc)))
            continue
        claims_accepted += len(ok_claims)
        for claim in ok_claims:
            fact = store.by_id(claim.cite)
            if fact is not None:
                sources.setdefault(fact.source, None)
        accepted_segments.append(segment)
        sentences.append(sentence)

    issues = audit_sentences(sentences, store, forbidden, accepted_segments)
    checks = {
        "claims_validated": not rejected,
        "templates_rendered": all(err is None for _, _, err in rejected) and bool(accepted_segments),
        "text_audit_clean": not issues,
        "identifier_dictionary_applied": forbidden is not None,
        "nonempty": bool(sentences),
    }
    passed = bool(sentences) and not rejected and not issues
    receipt = GateReceipt(
        passed=passed,
        edition=edition,
        script_sha256=script_hash(sentences),
        generated_at=now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        sentence_count=len(sentences),
        claims_total=claims_total,
        claims_accepted=claims_accepted,
        checks=checks,
        rejections=[
            {
                "template": seg.template_id,
                "claims": [c.to_dict() for c in seg.claims],
                "reasons": [r.to_dict() for r in rej] + ([{"code": "TEMPLATE", "detail": err}] if err else []),
            }
            for seg, rej, err in rejected
        ],
        issues=[i.to_dict() for i in issues],
        sources=sorted(sources),
        templates_used=sorted({s.template_id for s in accepted_segments}),
    )
    return GateResult(receipt, accepted_segments, sentences, rejected, issues)
