# Build log

Times are US Eastern. Each entry records what landed and what was measured.
Hardware for all timings: Raspberry Pi 4 Model B (4 GB), Python 3.13.

## Mon 2 Nov, 14:52 — S0 scaffold

- Repository, MIT license, security policy, `make check` entry point.
- ADR-0001: verified claims before speech.
- Raw material pulled for the offline snapshots: CISA KEV catalog version
  2026.10.30 (1,766 entries) and FIRST EPSS scores for 29 and 30 Oct.

## Mon 2 Nov, 15:20 — S1 to S3: evidence spine, claim gate, alert policy (v0.1.0)

Landed:
- Tenable VM export loader (export status, vulns chunks, assets) that reads only
  allowlisted structured fields; plugin output and other free text are never read.
- KEV catalog reconstructed as of each export date; EPSS from the bundled
  snapshot, the FIRST API format or the FIRST daily CSV.
- Coverage-aware delta: new exposure, new visibility, persisting, reopened,
  verified fixed, not detected, unverified (missed scan), asset gone. An
  incomplete export fails closed: nothing counts as fixed.
- Evidence ledger of 32 typed predicates; structured claim validation with
  citation checks; controlled narration grammar of 34 templates that parse
  back into claims; strict script gate with receipts.
- Deterministic alert policy (break in / health / scheduled / silent) with
  SQLite alert memory keyed by CVE and affected-asset set.
- Action card (analyst and executive editions), fail-closed redaction, generic
  push payload, CLI: `demo`, `brief`, `check`, `gate-demo`, `audit`.
- Deterministic synthetic tenant generator: 64 -> 76 assets, 455 -> 545
  findings, planted instructions in plugin output, a plugin name and a hostname.

Measured:

| Check | Result |
|---|---|
| Unit tests | 49 pass, 0 fail (18.0 s) |
| Gate adversarial suite | 17/17 false statements blocked on evidence, 5/5 controls supported |
| Tampered script (one false line inserted) | refused |
| Hostname audit | 0 of 304 tenant identifiers in executive card, script, push payload or model view |
| Demo wall time | 1.42 s median of 5 runs; 32 MB peak RSS |
| Rerun with unchanged evidence | SILENT; no duplicate alert |
