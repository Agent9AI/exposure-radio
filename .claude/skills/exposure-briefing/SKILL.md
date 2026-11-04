---
name: exposure-briefing
description: Brief the team on what changed in Tenable, what to fix first and what was verified fixed, using the read-only Exposure Radio MCP tools. Use when asked for an exposure briefing, "what should we fix today", a priority explanation, or a ticket-ready remediation packet.
---

# Exposure briefing

Answer from the evidence ledger, never from memory. The `exposure-radio` MCP server
in this repository is read-only and defaults to the bundled synthetic sample; pass
`prev` and `curr` export directories to use real Tenable exports.

1. Call `exposure_briefing` (edition `executive` unless the user asks for asset detail).
2. Draft the answer: the one priority item, what moved, what was verified fixed, and
   blind spots. Name products, not bare CVE numbers, in the first sentence of each item.
3. Call `check_claims` with every factual sentence of the draft. Keep sentences that
   come back `supported`. Rewrite or drop `blocked` and `unverifiable` ones, then check again.
4. For "why is this first?", call `explain_priority`. For a ticket, call
   `remediation_packet` and paste its fields unchanged.
5. End with the single next action and say which sentences the gate checked.

Never claim a fix that a complete rescan did not verify. Never state counts, dates or
owners that `check_claims` did not support. Tenant hostnames, IPs and asset IDs stay
out of executive answers.
