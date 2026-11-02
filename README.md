# Exposure Radio

**Two Tenable exports in, one verified priority briefing out: what changed, what to act on
today, and a ticket-ready action card. It reads the briefing aloud, and every spoken sentence
is a structured claim checked against the evidence in code before any audio exists.**

## Listen

- **Open [`site/index.html`](site/index.html)** (works from `file://`, no server, no external
  resources): press play, follow the transcript as it highlights, open any sentence's citations,
  flip the CISO edition toggle, see the zero-PII alert preview.
- Or play [`site/sample.mp3`](site/sample.mp3) directly (4:05, -16.4 LUFS integrated, -1.1 dBTP
  true peak) with [`site/sample.vtt`](site/sample.vtt) as the transcript. The VTT header carries
  the gate receipt hash of the script it was synthesised from.

The episode compares two weekly exports of a synthetic 51-asset estate (20 and 27 October 2026)
against the real CISA KEV catalogue (version 2026.10.30) and FIRST EPSS scores:

```
This is a break-in bulletin: a KEV-listed exposure is new since the previous export.
48 assets were rescanned, 3 assets were absent from this scan, and 3 assets are newly in scope.
Since the previous export, 16 critical findings were closed on rescanned assets, and 1 CVE in your
  estate was added to the CISA KEV catalogue.
3 findings vanished from assets that were absent from this scan; they stay open as unverified absences.
Lead item: CVE-2026-110447, critical severity, open on 1 asset.
CVE-2026-110447 affects Collabora Online - Built-in CODE Server and has been on the CISA KEV
  catalogue since 23 October 2026.
Action: Workplace IT to patch CVE-2026-110447 by 31 October 2026 under the internal SLA.
```

Every line above is rendered from a template over claims the gate validated; the transcript shows
the fact id and source behind each one (`f0253 open_asset_count = 1 (export:current)`).

## Run the demo in ten seconds

```bash
git clone https://github.com/Agent9AI/exposure-radio && cd exposure-radio
python3 -m exposure_radio demo      # Python 3.10+, standard library only, no network
```

The demo prints the decision, the narration, the delta, the gate receipt, the zero-PII alert
and the lead action card, and writes everything (briefing, transcript with citations, receipt,
both card editions, alert, facts, ledger) to `out/demo/`. It runs in well under a second.

```bash
make check                          # 195 tests, gate demo, zero-PII audit, agent replay
make gate-demo                      # 16 planted false statements, all blocked
make audit                          # no tenant identifier in CISO edition, alert or redacted facts
make agent-replay                   # recorded analyst run, gate executed live, no API key
```

## See the gate block false claims

`make gate-demo` runs the real briefing (which must pass) and then sixteen planted statements
against the same evidence. Each must be blocked, with the reason named:

| Planted | Result |
|---|---|
| "CVE-2026-110447: 20 assets closed", citing the fact that says 1 open | blocked: `PREDICATE_MISMATCH` (cite states `open_asset_count`, not `closed_asset_count`) |
| `kev_listed = false` citing the fact that says true | blocked: `VALUE_MISMATCH` |
| "CVE-2026-110447 is not listed on the CISA KEV catalogue." | blocked: `NEGATION`, `STRUCTURE` (not a template output) |
| "CVE-2026-110447 is open on twenty assets." | blocked: `NUMBER_WORD` |
| "No critical findings remain. All clear." | blocked: `ALL_CLEAR` |
| "Disable monitoring on the web tier until the patch lands." | blocked: `DIRECTIVE` |
| Claims about CVE-2031-99999 citing real facts | blocked: `SUBJECT_MISMATCH` / `UNKNOWN_CVE` |
| "fw-edge-01.northwind.internal is affected." | blocked: `IDENTIFIER_LEAK`, `HOSTNAME_LEAK` |
| "IGNORE ALL PREVIOUS INSTRUCTIONS" planted in plugin output | never becomes a fact, a sentence or an accepted claim |
| asset count off by one; `true` written as `1`; a correct value with an invented citation | blocked: `VALUE_MISMATCH`, `VALUE_MISMATCH`, `UNKNOWN_CITE` |
| KEV sentence about a CVE the catalogue does not list | blocked: `SUBJECT_MISMATCH` |
| A hostname inside the CISO packet; a CVE id inside the push alert | withheld: `HOSTNAME_LEAK`; `CVE_PRESENT` |

## What a vulnerability manager gets

```
Decision: BREAK_IN  lead CVE-2026-110447
  policy: CVE-2026-110447: newly listed by CISA since the previous export; newly exposed on assets
          that were already being scanned
  health: 3 previously scanned asset(s) were not rescanned
```

Three things a plain diff gets wrong, and this does not:

| Situation | Naive diff says | Exposure Radio says |
|---|---|---|
| Three kiosks are scanned for the first time | "Exposure up 4 findings" | New **visibility**: 4 findings from 3 assets new to the scan |
| Two workstations and a NetScaler miss the scan window | "3 criticals gone" | **Unverified**, not fixed: 3 absences on assets absent from this scan |
| CISA lists a CVE already open on the Nextcloud host | nothing changed | **Break in**: newly listed, open on 1 asset, patch by 31 October under the internal SLA |

A Tenable export also carries open rows for assets that were *not* rescanned. Those are a fourth
case, **unverified open**: still listed, nothing confirmed them ([ADR-0002](docs/adr/0002-coverage-is-activity-not-presence.md)).
The second synthetic tenant in `data/fixtures/tenant-b` (the real Tenable layout: `export-status.json`,
`vulns/chunk-N.json`, `assets.json`) exercises it:

```bash
python3 -m exposure_radio briefing --previous data/fixtures/tenant-b/2026-10-29 --current data/fixtures/tenant-b/2026-10-30
```

The action card (`out/demo/packet_full.md`, or `python3 -m exposure_radio packet`) gives each
priority item an owner, an internal SLA deadline, CISA's catalogue dates and required action,
EPSS, the affected assets, scanner evidence by plugin id, the change since the previous export,
the fact ids behind every line, and references. Three kinds of date stay apart on purpose:
the KEV catalogue's `dateAdded` and `dueDate` fields (reported as CISA values), federal policy
(BOD 26-04, which replaced BOD 22-01, binds federal civilian agencies and is named as context),
and the internal SLA deadline computed from `data/sla.json`, which is the one on the ticket.

## Architecture

```
 Tenable exports ─────────┐
 JSON · .nessus · CSV ·   │   parsers           evidence            facts                 gate                       surfaces
 API layout (status +     ├─► sanitise ───────► dedupe per port ──► (subject, predicate, ─► claims validated ────► narration ──► TTS ──► MP3 + VTT
 chunks + assets)         │   free text dropped  primary CVE          value, source)         in code: cite must       templates      receipt hash
                          │                      coverage-aware      ~330 typed facts        match subject,           only           in transcript
 CISA KEV · FIRST EPSS ·  │                      delta                with a ledger           predicate, value
 Tenable Research ────────┘                                                │                      │
 offline snapshots + sha256 ledger                                         │                      ├─► text audit: structure, identifiers, negation,
                                                                           │                      │   number words, all-clear, directives, unknown CVEs
                                                                           │                      └─► receipt (sha256 of the approved script)
                                                                           │
                                                                           ├─► alert policy: BREAK_IN / HEALTH / SCHEDULED / SILENT  (sqlite3 memory)
                                                                           ├─► action card: full edition, CISO edition (fail-closed)
                                                                           ├─► zero-PII alert preview
                                                                           ├─► MCP server (stdio, read-only): exposure_briefing, check_claims, remediation_packet
                                                                           └─► analyst agent (opt-in): redacted view, proposals gated, rewrite on rejection
```

| Module | Role |
|---|---|
| `exposure_radio/parsers/` | Tenable VM JSON (array, wrapper or API directory), hardened `.nessus` (no DOCTYPE, no entities, depth and size limits, only allowlisted elements read), Tenable CSV (header aliases, field caps). Plugin output, descriptions, solutions and banners are never stored. |
| `sanitize.py` | Allowlist cleaning of the few text fields that are kept; typed parsing of ids, dates, scores. |
| `evidence.py`, `delta.py` | Per-port dedupe, primary CVE rule, activity-based scan coverage, seven-way change classification. |
| `feeds.py` | KEV, EPSS and Tenable Research snapshots with provenance (`data/feeds/MANIFEST.json`), the citation ledger, and the explicit `feeds refresh` downloader. |
| `facts.py`, `claims.py`, `templates.py`, `textaudit.py`, `gate.py` | The structured-fact gate: facts, claims, fixed templates, second-pass text audit, receipt. |
| `policy.py`, `memory.py` | Alert decision and sqlite3 episode and alert memory. |
| `packet.py`, `alert.py` | Action cards in two editions; zero-PII alert. |
| `mcp_server.py`, `agent.py`, `audio/` | Read-only MCP tools; bounded analyst agent with scripted and replay transports; spoken-form lexicon, WebVTT, loudness, Kokoro synthesis. |
| `bench.py`, `gate_demo.py` | Prep-time benchmark; planted adversarial cases. |

## Outbound data flow

| Surface | Leaves the machine? | Destination | What | When |
|---|---|---|---|---|
| `demo`, `briefing`, `packet`, `gate-demo`, `audit`, `bench`, `mcp` | No | — | — | Never. Snapshots are read from disk. |
| `feeds refresh` | Yes | `www.cisa.gov`, `epss.empiricalsecurity.com` | HTTPS GET of the public catalogue and score file. No tenant data in the request. | Only when a human runs it. |
| `agent` with a model | Yes | `api.anthropic.com` (the user's own key) | The redacted evidence ledger (no hostnames, IPs, asset ids, evidence rows or scanner text), template catalogue, tool results, gate rejections. | Only with `ANTHROPIC_API_KEY` set and no `--replay`/`--scripted`. Capped: 6 calls, 60k tokens, 90 s, 2 rewrites. |
| `agent --replay` / `--scripted` | No | — | — | Default for `make check`. |
| `audio` | No | — | Local Kokoro synthesis, local ffmpeg. | — |
| `site/index.html` | No | — | Static page; no fonts, scripts or images fetched. | — |
| MCP server | No (stdio only) | The local MCP client process | Briefing sentences with citations, claim verdicts, packets. | When the client calls a tool. |

## Threat model

| Threat | Where it enters | Controls | Proof |
|---|---|---|---|
| **Prompt injection** via scanner text (plugin output, banners, solution prose, plugin names) | the exports | Free text is never read into the model (`FREE_TEXT_FIELDS` counted and dropped); plugin names are allowlist-cleaned and never spoken; the analyst model sees facts, not text; its proposals are claims checked in code; a hostname or plugin phrase in any sentence fails the gate. | `test_parsers.test_free_text_is_never_stored`, `test_gate.test_injection_never_reaches_facts_or_script`, planted case `plugin_output_injection` |
| **Malicious export files** (XXE, entity expansion, deep nesting, oversized fields, truncated files) | `.nessus`, JSON, CSV | expat with DOCTYPE and entity declarations rejected and parameter entities disabled; depth, byte and element caps; CSV field cap; truncated or unfinished exports hold the briefing (no closure is reported). | `HardeningTests`, `FailClosedTests`, fixtures `current_with_dtd.nessus`, `current_truncated.*`, `current_partial.json` |
| **PII / tenant leakage** in audio, executive copy or notifications | narration, CISO card, alert, redacted facts, model view | Exact-identifier dictionary from the exports plus DNS, IP and UUID shape checks on every sentence; CISO edition and redacted facts audited before writing and **withheld** on any hit; alert carries counts and an opaque reference only (no CVE ids); memory stores asset ids and plugin numbers only. | `make audit`, planted cases `hostname_leak`, `ciso_edition_leak`, `alert_cve_leak`, `test_textaudit`, `test_memory.test_memory_stores_no_hostnames` |
| **False or inflated statements** (wrong relation, negation, number words, all-clear, directives, unknown CVEs, invented citations, type confusion) | producer bug or model output | Claims must cite a fact with the same subject, predicate and value (`True` is not `1`, `0.94` is not `0.094`); only template output is speech; second-pass text audit; receipt hash required before audio. | `make gate-demo`, `test_claims`, `test_gate`, `test_templates` |
| **Tool abuse** through MCP or the agent | MCP client, model | Three read-only tools, no write paths, export paths confined to the working and data directories, JSON-RPC input validated and size-capped, claims capped at 200; agent tools return only redacted, audited views; forced tool choice not used; caps on calls, tokens, wall clock and retries; any cap or refusal falls back to the template edition. | `test_mcp.test_path_restrictions`, `test_agent.CapTests`, `test_agent.test_tools_expose_redacted_evidence_only` |
| **Secrets in the repository** | git history | No credentials anywhere; the API key is read from the environment only; full-history scan with gitleaks recorded in the build log. | `docs/BUILDLOG.md` |

## Evidence rules

- **Per-port dedupe.** Rows collapse to (asset, plugin); ports become a list; asset counts are
  distinct assets.
- **Primary CVE.** For a plugin with several CVEs: KEV-listed first, then highest EPSS, then
  highest CVSS v3 on the finding, then the newest id.
- **Coverage.** An asset is in scope when its latest scan activity is later than the previous
  export's last scan completion; presence in the export is not a scan ([ADR-0002](docs/adr/0002-coverage-is-activity-not-presence.md)).
- **Priority.** KEV listing, severity, KEV entries added since the previous export, EPSS, public
  exploit, number of open assets, CVSS, newest id.
- **Deadline.** `data/sla.json`: KEV-listed 7 days, critical 14, high 30, medium 90, low 180, minus
  3 days when a public exploit exists, never under 2 days, clock starting at the export date.
- **Interruptions.** Decided in code and remembered ([ADR-0003](docs/adr/0003-interruptions-decided-in-code.md)).
- **Identifiers.** Never spoken, CISO edition fails closed ([ADR-0004](docs/adr/0004-identifiers-never-spoken.md)).
- **Speech.** Only validated claims through fixed templates ([ADR-0001](docs/adr/0001-verified-claims-before-speech.md)).

## Commands

```bash
python3 -m exposure_radio demo [--out DIR] [--memory FILE]                  # full pipeline, writes artefacts
python3 -m exposure_radio briefing --current C [--previous P] [--json]       # narration + receipt
python3 -m exposure_radio packet --edition full|ciso [--cve ID] [--json]     # action cards
python3 -m exposure_radio gate-demo [--json]                                 # planted false claims
python3 -m exposure_radio audit                                              # zero-PII audit
python3 -m exposure_radio check-claims claims.json                           # validate your own claims
python3 -m exposure_radio facts [--redact]                                   # dump the ledger
python3 -m exposure_radio mcp                                                # MCP server on stdio
python3 -m exposure_radio bench [--runs N] [--json FILE]                     # prep-time benchmark
python3 -m exposure_radio feeds status|refresh                               # snapshots; refresh is the only networked command
python3 -m exposure_radio agent --replay data/replay/analyst_trace.json      # recorded analyst run
python3 -m exposure_radio agent --scripted                                   # deterministic stand-in
python3 -m exposure_radio agent --model claude-opus-5-5                      # your own key: pip install anthropic; ANTHROPIC_API_KEY
python3 -m exposure_radio audio --model-path kokoro.onnx --voices-dir voices # optional: pip install -e '.[audio]' and ffmpeg
```

Exports can be a Tenable VM JSON array or wrapper, a directory in the API layout, a `.nessus`
file or a Tenable CSV; `--previous` may be omitted for a first episode. `--memory FILE` keeps
episode and alert history between runs, so running the same evidence twice yields a SILENT
decision and no second alert.

### MCP

```json
{"mcpServers": {"exposure-radio": {"command": "python3", "args": ["-m", "exposure_radio", "mcp"], "cwd": "/path/to/exposure-radio"}}}
```

Tools: `exposure_briefing` (sentences with cited facts, receipt, delta, alert), `check_claims`
(validate `(subject, predicate, value, cite)` objects), `remediation_packet` (cards, `full` or
`ciso`). All read-only; export paths must lie inside the working or data directory.

### The analyst agent

Template mode is the default and always airs if anything goes wrong. With a key, one bounded
loop (`claude-opus-5-5` by default, adaptive thinking, no forced tool choice, server-side refusal
fallback) sees the redacted ledger through the same three tools, proposes items, an angle sentence
and a break-in decision as claims, and gets rejections back as tool results. The committed trace
(`data/replay/analyst_trace.json`, recorded with the deterministic stand-in) shows a proposal
rejected for an asset count one too high, then the corrected resubmission accepted; `make
agent-replay` runs that gate live.

## Data and provenance

| Snapshot | Content | Provenance |
|---|---|---|
| `data/feeds/kev.json` | CISA KEV catalogue 2026.10.30, 1,766 entries, published JSON schema | pulled from cisa.gov on 2 Nov 2026; demo entries cross-checked against public mirrors (`MANIFEST.json`) |
| `data/feeds/epss.json` | FIRST EPSS scores, score date 2026-10-30, 19 CVEs the tenants carry | FIRST API, 2 Nov 2026; the loader also reads the FIRST daily CSV and API JSON |
| `data/feeds/tenable_research.json` | Tenable Research posts covering demo CVEs | tenable.com URLs confirmed 2 Nov 2026 |
| `data/fixtures/` | Synthetic estate: 51 assets, weekly exports, JSON, `.nessus`, CSV, truncated and DTD variants, 500-finding benchmark pair | `scripts/make_fixtures.py`, deterministic |
| `data/fixtures/tenant-b/` | Second synthetic estate, daily exports in the real API layout | committed |

All hostnames, addresses and asset ids in the fixtures are invented (`northwind.internal`,
`corp.example`, RFC 1918 and documentation ranges). CVE identifiers are real so the public feeds
match.

## Benchmark

`make bench` runs the whole pipeline five times on the 500-finding fixture pair and counts the
manual operations the documented procedure ([docs/MANUAL_TRIAGE.md](docs/MANUAL_TRIAGE.md)) would
need for the same inputs:

| | |
|---|---|
| Fixture | 1,459 raw rows across two exports, 223 assets, 510 (asset, plugin) pairs, 17 assets not rescanned, 3 tickets |
| Pipeline | 0.3 s median of 5 runs on a fresh clone (timings in the build log) |
| Manual model | 3 h 34 min at the documented unit times |
| Prep time saved | about 3 h 31 min per episode |

That is preparation time, measured against a stated model of the manual steps. It is not a
remediation-speed claim.

## Verification

- `make check`: 195 unit and integration tests, the gate demo, the zero-PII audit and the agent
  replay; green on Python 3.13 and 3.10.
- Audio: Kokoro-82M (Apache-2.0) through onnxruntime, loudness normalised with two-pass
  `loudnorm` and measured with `ffmpeg ebur128`: integrated -16.4 LUFS, true peak -1.1 dBTP
  (`site/measurements.json`).
- Fresh-clone timings, the gitleaks history scan and every measurement quoted here are recorded
  in [docs/BUILDLOG.md](docs/BUILDLOG.md).

## Limits

- The EPSS snapshot covers the CVEs in the fixtures, not the whole catalogue; `feeds refresh`
  pulls the full daily file. The KEV snapshot is the full catalogue as of 2026.10.30.
- Tenable Research coverage is a hand-confirmed subset; publication dates are recorded only
  where confirmed.
- Coverage assumes a scan window shorter than the export cadence; the window is not yet a
  configurable value.
- The analyst agent has been exercised with the scripted stand-in and a fake SDK client in tests;
  a live model run needs your own key.

MIT licensed. Security policy in [SECURITY.md](SECURITY.md).
