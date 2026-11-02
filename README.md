# Exposure Radio

**Turn two Tenable exports into a cited priority briefing and a remediation handoff.**
Hear what changed, distinguish new exposure from new visibility, and act on a checked action card.

[Listen to the synthetic sample](web/assets/briefing.mp3) · [Read the transcript](web/assets/briefing.vtt) · [Inspect the evidence](web/data/facts.json)

![Exposure Radio listener](docs/qa/desktop.png)

## Run in two minutes

Python 3.10+ is sufficient. The core, demo, replay and MCP server use only the standard library.

```bash
git clone https://github.com/Agent9AI/exposure-radio
cd exposure-radio
python3 -m exposure_radio demo
python3 -m exposure_radio demo --analyst replay
make check
python3 -m http.server 8080 --bind 127.0.0.1 --directory web
```

Open **http://127.0.0.1:8080** for the listener, transcript, evidence drawer, action-card download and claim-gate demonstration. The included MP3 plays without a model key, network feed or TTS installation.

## The decision, then the evidence

The synthetic scenario compares **455 findings with 545 findings across 76 assets**. It uses a pinned CISA KEV catalog and FIRST EPSS snapshot dated 30 October 2026.

| Situation | Result |
|---|---|
| A previously unscanned segment enters coverage | New visibility, distinct from a regression |
| An asset misses its scan or loses authenticated coverage | Unverified exposure; no confirmed fix |
| An exploited vulnerability is newly discovered or reopens | A priority interruption with cited next steps |
| Identical evidence is processed again | Silence; no duplicate alert |
| A verified fix closes an announced exposure | The same exposure can alert again if it reopens |

The private analyst card includes affected assets and owners. The executive card and public sample exclude tenant identifiers. Notification previews use generic text and an opaque reference.

## A bounded analyst, a deterministic producer

The optional analyst reads allowlisted facts through `list_candidates`, `get_facts` and `check_claims`, then submits a ranked rundown. Code retains the interruption decision and policy lead. The model cannot write remediation state, execute scanner instructions or put free text into speech.

The recorded demonstration contains a model's actual tool decisions on synthetic evidence, including a rejected false count and corrected cited claims. Replay recomputes tool results and fails over to the template edition if evidence differs. Its model and transport are recorded in [the trace](exposure_radio/data/demo/analyst-trace.json); provider token usage was not measured.

For a live API-backed analyst, explicitly opt in with your own Anthropic key:

```bash
export EXPOSURE_RADIO_MODEL=claude-sonnet-5-5
# Set ANTHROPIC_API_KEY in your environment; never put it in a file in this repository.
python3 -m exposure_radio demo --analyst anthropic
```

The API adapter counts input before dispatch and reserves output within its configured budget. The default loop permits six model steps, eight read-only tool calls, one revision and 90 seconds. Provider failure or invalid output selects the checked template edition. The optional command adapter is an operator-trusted process; configure its own native tools and provider spending controls separately.

## Facts must pass before speech

1. Exports and public feeds produce typed `(subject, predicate, value, source)` facts.
2. Model submissions require exact public fact citations already returned by a tool.
3. Controlled templates render narration; the entire sentence is parsed and checked again.
4. A receipt binds the script, voices and ledger. The audio renderer rechecks it before loading TTS.
5. The site builder verifies the audio hash, receipt and exact caption text before publishing data.

`make gate-demo` rejects **27 of 27 adversarial statements**, accepts **five true controls**, and refuses a script with a false line inserted. Cases include wrong fixed counts, negation, phonetic number tricks, multiple-CVE claims, scanner instructions and unsupported all-clears. Free text outside the controlled grammar cannot authorize speech.

## Use your own Tenable VM exports

Place each complete export in its own directory:

```text
export-status.json   assets.json   vulns/chunk-1.json   vulns/chunk-2.json ...
```

Include OPEN, REOPENED and FIXED states. The loader validates completion metadata, chunks and asset scan timestamps. Incomplete evidence confirms no fixes.

```bash
python3 -m exposure_radio brief --prev exports/day1 --curr exports/day2 \
  --kev feeds/kev-current.json --prev-kev feeds/kev-previous.json \
  --epss feeds/epss.csv.gz --state private-state.sqlite3 --out private-brief
python3 -m exposure_radio check --strict --text "CVE-2024-3400 is fixed on 20 assets."
```

The last command is an intentional negative control and exits with status 1. An actual previous KEV catalog establishes changes in membership; export dates alone cannot establish when a same-day feed changed. Internal remediation deadlines and CISA catalog dates are separate fields.

## Use as MCP tools

```bash
python3 -m exposure_radio mcp
```

Configure that command in an MCP client with this repository as its working directory. The four read-only tools are `exposure_briefing`, `check_claims`, `remediation_packet` and `explain_priority`. Custom export directories must remain within `EXPOSURE_RADIO_DATA_ROOT`; symbolic-link exports are refused. Use executive editions for model-safe results, and request private analyst packets only within your own data boundary.

## Verification and audio

```bash
make check
python3 scripts/build_site.py
python3 scripts/benchmark.py --runs 5
```

The [recorded preparation benchmark](docs/benchmark.json) measures a complete briefing plus an unchanged rerun: **2.06 seconds median across five runs** on an ARM64 Raspberry Pi. It measures software preparation, with no claimed human-time multiplier.

Audio uses local Kokoro voices and two-pass normalization. [The manifest](web/assets/audio.json) records the exact script receipt, audio hash, duration, loudness and true peak. To render your own sample, install `kokoro-onnx`, `numpy`, `soundfile` and FFmpeg in a separate environment, supply the model and voice files, then run:

```bash
python3 scripts/render_audio.py --model /path/to/kokoro.onnx \
  --voices /path/to/voices.bin --output rendered-audio
```

The core does not install or download those dependencies. See [security boundaries](SECURITY.md), [build evidence](docs/BUILDLOG.md) and [third-party notices](THIRD_PARTY_NOTICES.md).

MIT licensed.
