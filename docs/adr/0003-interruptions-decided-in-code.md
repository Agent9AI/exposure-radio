# ADR-0003: Interruptions are decided in code and remembered

Date: 2026-11-02
Status: accepted

## Context

A briefing that breaks in whenever anything changed trains its listeners to
ignore it. A model deciding when to interrupt is a model deciding what the
security team hears first, with no audit trail. Re-running the pipeline on
unchanged data should not produce a second alert.

## Decision

1. The decision is a deterministic function of the fact store and the
   episode memory, with four outcomes:
   - **BREAK_IN**: a KEV-listed CVE is open on assets it was not announced
     for before (newly listed by CISA since the previous export, newly
     exposed on rescanned assets, found on assets new to the scan, or
     reopened);
   - **HEALTH**: nothing to announce, but the evidence itself is in doubt
     (incomplete export, assets missed by the scan);
   - **SCHEDULED**: changes exist, none warrants interruption;
   - **SILENT**: this exact evidence was already briefed.
2. Alerts are keyed by CVE and the set of affected asset identifiers. The
   key and the episode fingerprint (open rows, KEV set, hold state) are
   stored in sqlite3. A repeated key never alerts again; a new asset
   joining an exploited CVE produces a new key and does.
3. The decision becomes facts (`episode.decision` and its reasons), so the
   sentence that announces it passes through the same gate as every other
   sentence, and the alert title follows it. A SILENT decision suppresses
   the push notification entirely.
4. The optional analyst agent may propose a break-in, but its proposal is a
   claim like any other; the deterministic decision is what the receipt and
   the alert carry.

## Consequences

Interruptions are explainable line by line ("newly listed by CISA since the
previous export") and reproducible. The memory holds asset identifiers and
plugin numbers only, never hostnames.
