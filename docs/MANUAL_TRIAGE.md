# The manual triage procedure the benchmark models

`python3 -m exposure_radio bench` compares Exposure Radio's wall-clock time on
the 500-finding fixture pair with the time an analyst would spend producing
the same briefing by hand. The tool side is measured. The manual side is a
model: each step below is a discrete operation whose *count* is measured from
the fixture and whose *unit time* is a stated assumption. The benchmark prints
both so a reader can substitute their own numbers.

The claim this supports is **briefing preparation time**. Nothing here says
vulnerabilities get fixed faster.

## Inputs

Two Tenable Vulnerability Management exports, previous and current, each a
list of finding rows (one per asset, plugin, port and protocol), plus the
CISA KEV catalogue and FIRST EPSS scores.

## Steps and unit times

| Step | What the analyst does | Count measured from the fixture | Unit time |
|---|---|---|---|
| open_exports | Download both exports, open them in a spreadsheet, freeze headers, sanity-check the row counts | fixed | 5 min |
| dedupe | Sort by asset and plugin, spot per-port duplicates, collapse them so counts are per asset | raw rows in both exports | 2 s per row |
| delta | VLOOKUP each (asset, plugin) pair both ways between the sheets, read the result, decide if it is new, gone or unchanged | distinct (asset, plugin) pairs across both exports, informational rows excluded | 10 s per pair |
| coverage_check | For each asset present last time but absent now, open the scan log and confirm whether it was scanned (absent is not fixed) | assets in the previous export missing from the current one | 60 s per asset |
| kev_lookups | Search the CISA KEV catalogue page for one CVE, note date added, due date and ransomware flag | distinct CVE ids across both exports | 30 s per CVE |
| epss_lookups | Query EPSS for one CVE, note score and percentile | distinct CVE ids across both exports | 20 s per CVE |
| summary | Rank the items and write the weekly summary paragraph with the coverage caveats | fixed | 15 min |
| tickets | Write one ticket with owner, deadline, affected assets, evidence and references | priority items | 10 min each |
| executive_scrub | Produce a copy with hostnames removed and re-read it for leaks | fixed | 5 min |

The unit times are mirrored in `MANUAL_UNIT_SECONDS` in
`src/exposure_radio/bench.py`; a test keeps the two in sync.

## Tool path

The pipeline time is the median of five runs of the whole chain (parse,
dedupe, delta, feeds, facts, gate, cards, alert) on the fixture pair. To that
the benchmark adds a fixed 3 minutes for a human to read the briefing and the
cards before sending them on, because a verified briefing still deserves a
reader.

## What is not modelled

* Time spent remediating anything.
* Time spent arguing about priorities.
* Organisations whose analysts already script parts of this; for them the
  saving is smaller and the gate is the point.
