# Build log

Times are US Eastern. Each entry records what landed and what was measured.
Hardware for the S0 to S3 timings: Raspberry Pi 4 Model B (4 GB), Python 3.13.
Hardware for the S4 onward timings: 4-vCPU x86-64 cloud container, 15 GB RAM,
Python 3.13.18 (system) and 3.10 (conda-forge build), ffmpeg 6, no GPU.

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

## Mon 2 Nov, 15:55 — S4: parsers, gate, delta memory, card, CLI, MCP (branch `claude/fable-build`)

Landed on a parallel branch from the scaffold:
- Three parsers: Tenable VM JSON (array or wrapper with export status),
  hardened `.nessus` (expat streaming, DOCTYPE and entity declarations
  rejected, parameter entities off, depth/byte/element caps, only allowlisted
  elements read) and Tenable CSV (header aliases, 4 MB field cap, short final
  row marks truncation). Free text fields are counted and never stored.
- Per-port dedupe, primary CVE rule, partial-export hold.
- Structured-fact gate: typed facts with sources, claims validated in code
  (type-strict), 19 fixed templates plus a five-sentence intro/outro
  allowlist, second-pass text audit (structure, identifier dictionary, DNS/IP/
  UUID shapes, unknown CVEs, number words, negation, all-clear, directives),
  receipt with the script hash.
- Coverage-aware delta with sqlite3 episode memory; ticket-ready remediation
  packet in full and CISO editions; zero-PII alert; read-only stdio MCP server
  with three tools; planted-case gate demo; 500-finding benchmark fixture.
- 154 tests.

## Mon 2 Nov, 16:20 — S5: analyst agent and audio pipeline

- Bounded analyst agent: one tool-use loop over redacted evidence, caps on
  calls (6), tokens (60k), wall clock (90 s) and rewrites (2); scripted and
  replay transports that need no key; Claude API transport through the
  optional `anthropic` SDK (`claude-opus-5-5`, adaptive thinking, no forced
  tool choice, server-side refusal fallback). Recorded trace shows a claim
  rejected for an asset count one too high and the corrected resubmission.
- Audio: spoken-form lexicon (`data/lexicon.json`), WebVTT builder, ffmpeg
  `ebur128` measurement and two-pass `loudnorm`, Kokoro-82M synthesis through
  onnxruntime behind optional imports.
- Kokoro weights: `model_quantized.onnx` from the onnx-community export
  (sha256 `fbae9257…1478`, Apache-2.0) and the 28 English voice vectors. The
  q8 model returns NaN and overflow on onnxruntime 1.23.2 (CPU); it is clean
  on onnxruntime 1.20.1, which the audio run uses.

## Mon 2 Nov, 16:45 — S6: merge of `main` (v0.1.0) and the stale-row case

- Merged `origin/main`. Kept the branch's package as the base and carried the
  stronger parts across: the complete KEV catalogue replaces the seven-entry
  subset (the dates in the subset matched the catalogue entry for entry),
  the FIRST EPSS snapshot (19 CVEs, score date 2026-10-30) lands as
  `data/feeds/epss.json`, the second synthetic tenant is kept under
  `data/fixtures/tenant-b` in the real Tenable layout and a directory loader
  reads it, the alert policy (break in / health / scheduled / silent) with
  sqlite alert memory is ported with its own tests, and CISA `requiredAction`
  text joins the action card. The parallel top-level package was retired
  after the port; its 49 tests targeted modules that no longer exist and were
  replaced by equivalent tests against the merged code.
- The second tenant exposed a real case: a Tenable export lists every open
  finding, so an asset's presence is not proof it was scanned. Coverage now
  comes from each asset's latest scan activity (ADR-0002) and open rows on
  assets outside the scanned scope are a new category, unverified open, with
  its own gated sentence.
- Found and fixed on the way: typographic quotes and dashes now fold to ASCII
  before the allowlist (CISA's `requiredAction` was losing its apostrophes),
  vendor names are not doubled when the catalogue product already carries
  them ("Collabora Collabora Online"), EPSS percentages round down so 0.99999
  never reads as 100 percent, the default owner label no longer looks like a
  DNS name (the gate caught it), exports given as directories get a directory
  digest in the ledger.
- Performance: identifier audits use a token scan instead of one compiled
  regex per identifier, and dates take an ISO fast path. The 500-finding
  benchmark pipeline went from 2.47 s to 0.30 s median.

## Mon 2 Nov, 17:35 — S7: listen page, README, verification

- Static listen page (`scripts/build_site.py` -> `site/index.html`): press-play
  sample synced to the WebVTT cues, citations drawer, CISO edition toggle
  (fail-closed), zero-PII alert preview, gate receipt and planted cases, agent
  replay, sources ledger. No external resources; checked in headless Chromium
  at 1280 px and 390 px: no script errors, no horizontal scroll, CISO view
  contains no identifier.
- Package moved to the repository root so `python3 -m exposure_radio demo`
  runs from a fresh clone with no `PYTHONPATH`.

Measured (fresh clone of commit `3b2f15b` into an empty directory, every
README command run verbatim; wall-clock seconds):

| Command | Seconds | Exit |
|---|---|---|
| `python3 -m exposure_radio demo` | 0.32 (pipeline itself 0.19) | 0 |
| `make check` (Python 3.13) | 5.93 | 0 |
| `make gate-demo` | 0.30 | 0 |
| `make audit` | 0.27 | 0 |
| `make agent-replay` | 0.31 | 0 |
| `make bench` | 1.67 | 0 |
| `briefing` on tenant-b (directory layout) | 0.34 | 0 |
| `packet --edition ciso` | 0.26 | 0 |
| `feeds status` | 0.28 | 0 |
| `briefing` on `current.nessus`, `current.csv`, `current_partial.json` | 0.25 each | 0 |
| MCP stdio smoke (initialize, tools/list, two tools/call) | 0.28 | 0 |
| `make check PY=<python3.10>` | 6.48 | 0 |
| `python3 scripts/build_site.py` | 0.30 | 0 |
| `pip install .` with Python 3.10, then `exposure-radio --version` | 2.62 | 0 |

| Check | Result |
|---|---|
| Tests | 194 pass, 0 fail, 0 errors (4.9 s on 3.13, 5.4 s on 3.10) |
| Gate demo | 16/16 planted cases blocked; clean briefing 59/59 claims, 33 sentences |
| Zero-PII audit | clean on CISO packet, alert, redacted facts and narration against 216 tenant identifiers and 16 plugin names |
| Agent replay | recorded run replayed through a live gate: 1 rejection (`VALUE_MISMATCH`), then accepted; 3 calls, 6,540 tokens counted |
| Tenant-b (76 inventory assets, 65 scanned, 11 stale, 12 new) | gate passed, BREAK_IN on CVE-2026-118527, unverified-open sentence present |
| Benchmark (500-finding pair: 1,459 raw rows, 223 assets, 510 pairs) | pipeline 0.31 s median of 5 (0.296 to 0.341); manual model 3 h 33 m 58 s; prep time saved 3 h 30 m 58 s per episode |
| Audio (`out/audio`, Kokoro-82M q8, voice af_heart, onnxruntime 1.20.1) | 33 cues, 245.2 s; raw -22.7 LUFS / +0.3 dBTP; after two-pass loudnorm and MP3 (64 kb/s mono): integrated -16.4 LUFS, true peak -1.1 dBTP, LRA 2.5 LU, measured with `ffmpeg ebur128` on the MP3; receipt hash in the VTT matches the script |
| Intelligibility proxy | pocketsphinx 5 (default en-us model, no tuning) transcribes the normalised WAV cue by cue at 21.4% word error rate over 641 reference words; 3 of 33 cues verbatim, errors concentrated on spelled acronyms ("K E V") and the CVE digit groups. A floor, not a quality claim |
| Python 3.10 | `vermin -t=3.10-` reports minimum 3.10 for `exposure_radio` and `scripts`; full suite green on the 3.10 interpreter |
| Secret scan | `gitleaks git` over the full history: 17 commits, 7.1 MB scanned, no leaks; `gitleaks dir` over the working tree: no leaks |
| Lint | `ruff check` (E, F, W, B, UP) clean |

Limits recorded with the measurements: the EPSS snapshot covers the fixture
CVEs only; the analyst agent's live transport is exercised with a fake SDK
client in tests, not against the API; the build host could not reach
cisa.gov, first.org or tenable.com, so the KEV entries used by the demo were
cross-checked against public mirrors before the full catalogue arrived from
`main`.
