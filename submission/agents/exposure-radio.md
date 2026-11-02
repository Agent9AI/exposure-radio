---
name: "Exposure Radio"
author: "Agent9AI"
github_url: "https://github.com/Agent9AI/exposure-radio"
description: "Turn Tenable exports into cited priority decisions, receipt-gated audio, and ticket-ready remediation handoffs."
license: "MIT"
tier: "contributed"
tags: ["exposure-management", "audio", "evidence", "remediation", "read-only"]
domains: ["vulnerability-management", "security-operations"]
integrations: ["Tenable", "Anthropic"]
date_added: 2026-11-02
works_with_tenable_hexa_mcp: false
---

# Exposure Radio

Exposure Radio compares two Tenable Vulnerability Management exports, combines them with local CISA KEV and FIRST EPSS evidence, and produces a cited priority briefing plus a remediation action card. A bounded analyst can select the rundown; deterministic policy controls interruptions and controlled templates produce speech.

## What it does

- Distinguishes new exposure from newly scanned or newly credentialed visibility.
- Retains missing or insufficiently rescanned findings as unverified; incomplete exports confirm no fixes.
- Checks whole narration sentences against typed evidence before speech, binding audio and captions to the accepted script receipt.
- Returns read-only tools through stdio MCP: exposure_briefing, check_claims, remediation_packet and explain_priority.
- Supplies a synthetic sample, actual recorded analyst decisions, adversarial claim-gate demonstration and reproducible preparation benchmark.

## Run

Python 3.10+; standard library only for the core and recorded demonstration:

```bash
python3 -m exposure_radio demo
python3 -m exposure_radio demo --analyst replay
make check
```

The repository includes the local listener, MP3, transcript and evidence. A live analyst uses the user's own Anthropic API key; optional speech generation uses local Kokoro and FFmpeg. Private analyst packets remain within the operator's data boundary. Hosted sample data is synthetic.
