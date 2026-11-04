# Contributing to Exposure Radio

Exposure Radio is an MIT-licensed open-source project built on the Python 3.10+ standard library. Every contribution must preserve the project's core security and evidence guarantees:

1. **Zero external runtime dependencies:** The CLI, delta engine, evidence ledger, claim gate, station host, and MCP server use the Python standard library only. Optional audio synthesis (`kokoro-onnx`, `soundfile`, `numpy`, `ffmpeg`) runs only during station-hour audio rendering (`scripts/build_station.py`).
2. **Verified claims before speech ([ADR-0001](docs/adr/0001-verified-claims-before-speech.md)):** Every factual sentence on a tenant exposure desk must derive from a typed `(subject, predicate, value, source)` fact in the ledger, render through a deterministic template, and pass both structured claim validation and text-level script gating before speech synthesis.
3. **Fail-closed privacy and redaction:** Never read free-text scanner fields (`plugin_output`, banners). Executive outputs, spoken lines, and push notifications must pass `python3 -m exposure_radio audit` with zero leaked tenant hostnames, FQDNs, IP addresses, or asset UUIDs.
4. **Safe DOM rendering in `web/`:** Browser scripts (`web/player.js`, `web/admin.js`, `web/briefing.js`) must render data via `textContent` and DOM node construction—never `innerHTML`—under the strict Content Security Policy.

## Running the verification suite

Before opening a pull request, run the full verification suite from the repository root:

```bash
make check
```

`make check` executes three mandatory gates:

| Target | Command | Requirement |
|---|---|---|
| `make test` | `python3 -m unittest discover -s tests -t . -q` | All 118 unit and integration tests pass |
| `make gate-demo` | `python3 -m exposure_radio gate-demo` | All 27 adversarial false claims blocked; 5 true controls supported; tampered script refused |
| `make audit` | `python3 -m exposure_radio audit` | 0 of 304 synthetic tenant identifiers appear in executive outputs, spoken script, push payload, or model view |

## Adding a new claim predicate or narration template

1. Define the typed predicate and fact builder in `exposure_radio/ledger.py`.
2. Add the template and reverse-parser in `exposure_radio/claims.py` and `exposure_radio/onair.py`.
3. Add positive control and adversarial negative test cases in `exposure_radio/adversarial.py` and `tests/test_gate.py`.
4. Run `make check` and confirm zero regressions.
