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

## Integration and adversarial hardening — 2026-11-02

The evidence gate, bounded analyst, four read-only MCP tools, listener and local audio renderer are integrated on the project branch. The independent Argon review drove regression coverage for false claims, scanner-text disclosure, incomplete exports, lost authenticated coverage and missing/duplicate alerts. A second review of the model and output boundaries drove additional tests for private-fact probes, provider-error disclosure, output failure and omitted alerts.

The analyst demonstration records a real GPT-6.1 Terra tool session on synthetic evidence. A false fixed count is rejected, corrected cited claims pass, and replay recomputes every tool result without a model key. Five model-step decisions and four read-only tool calls complete; provider token usage was not measured.

The reproducible preparation benchmark compares 455 and 545 findings, builds 304 facts and 54 narration lines, and confirms silence on unchanged evidence. Five runs measure 2.0607 seconds median; every run finishes below ten seconds. This measures software preparation, not a human-time or remediation-speed multiplier.

The runtime API adapter counts input before generation, reserves output, and disables parallel model tool calls. The command adapter caps captured output while reading, terminates its own process on budget exhaustion and exposes only generic failure categories. Private scanner fact values cannot be retrieved through claim-verdict error messages.

Final acceptance evidence is recorded in `docs/qa/` and the audio manifest. No repository CI workflow is used.

## Media and listener acceptance — 2026-11-02

The first-play priority break is 89.184 seconds by FFprobe (89.153 seconds after browser gapless decoding). It retains 14 complete, freshly validated narration lines from the full 54-line episode. The full episode remains available separately. No source sentence was rewritten during the edit. The priority manifest records the selected indices, source hash, fresh script receipt, exact caption cues and output hash.

The encoded priority break measures -16.53 LUFS and -1.83 dBTP at 48 kHz; the Kokoro synthesis rate is 24 kHz. Desktop playback progressed in 376 ms and mobile playback in 313 ms. Both browser checks passed responsive layout, transcript/citation expansion, clipboard, download, full-episode/caption links, and zero JavaScript or HTTP errors. These figures verify playback and signal levels; no comparative listening score is claimed.

The official Exchange Agent schema validator accepted the listing draft using its current Python 3.14 environment. Agreement acceptance, public visibility, Exchange submission and Discord posting remain the publication checkpoint recorded in `submission/RELEASE-CHECKLIST.md`.
