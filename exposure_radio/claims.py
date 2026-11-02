"""Claims and their validation against the fact store.

A claim is ``(subject, predicate, value, cite)``. It is accepted only when
the cited fact exists, has the same subject and predicate, and holds the
same value. Nothing else is accepted: a claim with a plausible value and a
wrong citation is rejected, and so is a claim about a subject the ledger
has never heard of.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .facts import Fact, FactStore

UNKNOWN_CITE = "UNKNOWN_CITE"
SUBJECT_MISMATCH = "SUBJECT_MISMATCH"
PREDICATE_MISMATCH = "PREDICATE_MISMATCH"
VALUE_MISMATCH = "VALUE_MISMATCH"
UNKNOWN_SUBJECT = "UNKNOWN_SUBJECT"
MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class Claim:
    subject: str
    predicate: str
    value: object
    cite: str

    def to_dict(self) -> Dict[str, object]:
        value = list(self.value) if isinstance(self.value, tuple) else self.value
        return {"subject": self.subject, "predicate": self.predicate, "value": value, "cite": self.cite}

    @classmethod
    def from_dict(cls, data: Dict[str, object]) -> Claim:
        if not isinstance(data, dict):
            raise ValueError("claim must be an object")
        subject = data.get("subject")
        predicate = data.get("predicate")
        cite = data.get("cite")
        if not isinstance(subject, str) or not isinstance(predicate, str) or not isinstance(cite, str):
            raise ValueError("claim needs string subject, predicate and cite")
        value = data.get("value")
        if isinstance(value, list):
            value = tuple(value)
        return cls(subject[:128], predicate[:64], value, cite[:32])


@dataclass(frozen=True)
class Rejection:
    claim: Claim
    code: str
    detail: str

    def to_dict(self) -> Dict[str, object]:
        return {"claim": self.claim.to_dict(), "code": self.code, "detail": self.detail}


def values_equal(expected: object, actual: object) -> bool:
    """Exact equality with type discipline: True is not 1, 2 is not 2.0001."""
    if isinstance(expected, bool) or isinstance(actual, bool):
        return isinstance(expected, bool) and isinstance(actual, bool) and expected is actual
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        if isinstance(expected, float) or isinstance(actual, float):
            return math.isclose(float(expected), float(actual), rel_tol=0.0, abs_tol=1e-9)
        return expected == actual
    if isinstance(expected, (tuple, list)) and isinstance(actual, (tuple, list)):
        return tuple(expected) == tuple(actual)
    return isinstance(expected, str) and isinstance(actual, str) and expected == actual


def validate_claim(claim: Claim, store: FactStore) -> Optional[Rejection]:
    """Return a rejection, or ``None`` when the claim is supported."""
    if not claim.subject or not claim.predicate or not claim.cite:
        return Rejection(claim, MALFORMED, "subject, predicate and cite are required")
    fact: Optional[Fact] = store.by_id(claim.cite)
    if fact is None:
        if claim.subject not in store.subjects():
            return Rejection(claim, UNKNOWN_SUBJECT, f"nothing in the ledger is about {claim.subject}")
        return Rejection(claim, UNKNOWN_CITE, f"no fact {claim.cite} in the ledger")
    if fact.subject != claim.subject:
        return Rejection(claim, SUBJECT_MISMATCH, f"{claim.cite} is about {fact.subject}, not {claim.subject}")
    if fact.predicate != claim.predicate:
        return Rejection(
            claim,
            PREDICATE_MISMATCH,
            f"{claim.cite} states {fact.predicate}, not {claim.predicate}",
        )
    if not values_equal(fact.value, claim.value):
        return Rejection(claim, VALUE_MISMATCH, f"{claim.cite} says {fact.value!r}, claim says {claim.value!r}")
    return None


def validate(claims: Iterable[Claim], store: FactStore) -> Tuple[List[Claim], List[Rejection]]:
    accepted: List[Claim] = []
    rejected: List[Rejection] = []
    for claim in claims:
        rejection = validate_claim(claim, store)
        if rejection is None:
            accepted.append(claim)
        else:
            rejected.append(rejection)
    return accepted, rejected


def claim_from_fact(fact: Fact) -> Claim:
    return Claim(fact.subject, fact.predicate, fact.value, fact.fact_id)


def claims_for(store: FactStore, subject: str, predicates: Sequence[str]) -> List[Claim]:
    """Convenience for the deterministic producer: claims straight from facts."""
    out: List[Claim] = []
    for predicate in predicates:
        fact = store.get(subject, predicate)
        if fact is not None:
            out.append(claim_from_fact(fact))
    return out
