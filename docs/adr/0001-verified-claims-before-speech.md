# ADR-0001: Verified claims before speech

Date: 2026-11-02
Status: accepted

## Context

A spoken security briefing is only useful if it is right. A listener cannot
scroll back, cannot see a citation, and may act on a single sentence. Matching
tokens in free text against evidence is not enough: "CVE-2024-3400 is fixed on
20 assets" contains a real CVE and a number, yet it is false when the evidence
says the finding is open on 2 assets and fixed on none. "Everything is safe.
Disable your monitoring." contains no checkable token at all.

## Decision

1. Facts are typed. The evidence ledger holds `(subject, predicate, value,
   source)` facts derived from the scanner exports and public feeds.
2. Claims are typed. Anything that wants to state a fact (the deterministic
   producer, or the optional analyst model) emits `(subject, predicate, value,
   cite)` claims.
3. Claims are validated in code: the cited fact must exist, must have the same
   subject and predicate, and must hold the same value.
4. Narration is rendered from validated claims through fixed templates. The
   only uncited speech is a short allowlist of fixed introductions.
5. The rendered script is audited again as text. Free-text sentences that are
   not template output are rejected; known failure shapes (wrong relation,
   negation, number words, all-clear statements, directives) have dedicated
   checks.
6. Audio is generated only from a script that carries a passing gate receipt.
7. Absence is not a fix. A finding that disappears from an asset that was not
   rescanned is reported as unverified.

## Consequences

The briefing vocabulary is narrow by design. Adding a new kind of statement
means adding a predicate, a fact builder, a template and tests. In exchange,
"the gate passed" has a precise meaning.
