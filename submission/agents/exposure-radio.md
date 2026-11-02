---
name: "Exposure Radio"
author: "Agent9AI"
github_url: "https://github.com/Agent9AI/exposure-radio"
description: "Turns two Tenable exports into a verified spoken priority briefing, a coverage-aware delta and a ticket-ready action card; every sentence is a claim checked against evidence before audio."
license: "MIT"
tier: "contributed"
tags: ["exposure-management", "audio", "evidence", "remediation", "read-only", "mcp"]
domains: ["vulnerability-management", "security-operations"]
integrations: ["Tenable", "Anthropic"]
date_added: 2026-11-02
works_with_tenable_hexa_mcp: false
---

# Exposure Radio

Exposure Radio compares two Tenable Vulnerability Management exports (JSON, the API
directory layout, `.nessus` or CSV), joins them with offline CISA KEV and FIRST EPSS
snapshots and Tenable Research references, and produces a spoken priority briefing, a
coverage-aware delta and a remediation action card. A deterministic policy decides
whether the episode breaks in, and a structured-fact gate checks every spoken
sentence against typed evidence before any audio exists.

## What it does

- Separates new exposure from new visibility (assets new to the scan) and from
  unverified absence or unverified open rows (assets not rescanned). An incomplete
  export holds the briefing: nothing counts as fixed.
- Renders speech only from fixed templates over claims whose cited facts match in
  subject, predicate and value; audits the text again for identifiers, negation,
  number words, all-clear phrases and directives; binds the audio and captions to the
  approved script's receipt hash.
- Produces a ticket per priority item with owner, internal SLA deadline, CISA
  catalogue dates and required action, EPSS, cited fact ids and references, in a full
  edition and a CISO edition that withholds identifiers and fails closed.
- Exposes three read-only MCP tools over stdio: `exposure_briefing`, `check_claims`
  and `remediation_packet`.
- Ships a synthetic estate with a four-minute sample episode, a recorded analyst run
  replayed through a live gate, a sixteen-case false-claim demonstration and a
  reproducible preparation-time benchmark.

## Run

Python 3.10 or later; standard library only for the core, the demo and the tests:

```bash
git clone https://github.com/Agent9AI/exposure-radio && cd exposure-radio
python3 -m exposure_radio demo
make check
python3 -m exposure_radio mcp        # MCP server on stdio
```

Open `site/index.html` for the listen page. The optional analyst agent uses the
operator's own Anthropic API key and sees redacted evidence only; optional speech
synthesis runs locally with Kokoro and FFmpeg. No network call is made unless the
operator runs `feeds refresh` or the live agent. All sample data is synthetic.
