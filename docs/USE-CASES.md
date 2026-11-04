# Operational Use Cases & Deployment Workflows

Exposure Radio turns vulnerability exports and public advisories into a verification-gated audio station and copyable action cards. Every spoken sentence on an exposure desk is rebuilt from typed `(subject, predicate, value, source)` facts in the evidence ledger and checked against the claim gate before text-to-speech runs.

This guide documents the six primary operational workflows teams use in production and evaluation environments.

| # | Use case | Primary audience | Trigger / cadence | Key output |
|---|---|---|---|---|
| **01** | [9:00 AM Zero-Meeting Security Standup](#1-the-900-am-zero-meeting-security-standup) | Small IT & lean SecOps (2–15 engineers) | Daily after overnight Tenable scan | 4 spoken Tenable desks + copyable Action Card |
| **02** | [CISA KEV & Zero Wire Priority Break-In](#2-cisa-kev--cloudflare-zero-wire-priority-break-in) | Vulnerability & patch owners | Immediate on new/reopened KEV exposure | Red priority interruption + local Zero Wire caveats |
| **03** | [Claude Code & MCP Evidence-Gated Triage](#3-claude-code--mcp-evidence-gated-triage) | Security engineers & incident responders | Interactive on-demand Q&A | Claim-checked answers + ticket remediation packets |
| **04** | [Executive vs. Analyst Dual-Edition Handoff](#4-executive-vs-analyst-dual-edition-handoff) | CISOs, IT directors, MSP leads | Weekly/daily leadership & ticket sync | Redacted executive brief (`0/304` leaks) + asset table |
| **05** | [Scanner Hygiene & Blind-Spot Auditing](#5-scanner-hygiene--blind-spot-auditing) | Platform & scanner administrators | Post-scan coverage verification | Verified fixes vs. unverified/credential-drop report |
| **06** | [SOC / NOC Ambient Wallboard & Shift Handover](#6-soc--noc-ambient-wallboard--shift-handover) | 24/7 operations desks & helpdesks | Continuous station rotation + quiet hours | Live loopback/SSO station + 60-second Learn segments |

---

## 1. The 9:00 AM Zero-Meeting Security Standup

**Problem:** Small IT teams rarely hold a dedicated daily vulnerability standup. Tenable dashboards sit unread between audits, or raw finding counts jump when new subnets enter scan scope—making improved visibility look like a worse security week.

**Workflow:**
1. Pull a complete, read-only Tenable Vulnerability Management export after your scheduled scan window:
   ```bash
   python3 -m exposure_radio station keys set tenable
   python3 -m exposure_radio station pull --out exports/2026-11-04
   ```
2. Build the daily briefing against the previous export and serve the station:
   ```bash
   python3 -m exposure_radio brief \
     --prev exports/2026-11-03 \
     --curr exports/2026-11-04 \
     --edition executive \
     --state station-memory.sqlite3 \
     --out latest-brief
   python3 -m exposure_radio station serve
   ```
3. Press **Tune In** at `http://127.0.0.1:8080`. Between music breaks, two hosts (**Avery** and **Cole**) deliver four structured Tenable segments:
   - **Priority (`02`):** The single item requiring action today, spoken in plain product names (*"the Ivanti Connect Secure flaw is open on two assets"*), never digit-by-digit CVE strings.
   - **Watch list (`04`):** Top-ranked movement since the last scan, ordering *new exposure* (a vulnerability appearing on an already-scanned machine) ahead of *new visibility* (a machine entering scan coverage).
   - **Wins (`09`):** Findings confirmed in the `FIXED` state by a completed rescan.
   - **Blind spots (`10`):** Machines that missed the scan window or lost credentialed access.

---

## 2. CISA KEV & Cloudflare Zero Wire Priority Break-In

**Problem:** When CISA adds a vulnerability to the Known Exploited Vulnerabilities (KEV) catalog or Cloudflare Radar publishes an active Zero Wire threat briefing, operators must manually cross-check advisories against their latest scan exports and determine whether compensating controls apply.

**Workflow:**
- **Deterministic interruption (`BREAK_IN`):** During each cycle, `exposure_radio/policy.py` compares the current export against the CISA KEV catalog and the SQLite alert memory (`exposure-radio.sqlite3`). If an open or reopened finding is on CISA's exploited list, the station flags the lead segment with `"priority": true` (`PRIORITY BREAK`).
- **Alert deduplication (`SILENT` on unchanged evidence):** Identical evidence never triggers a duplicate interruption. Re-running the pipeline against unchanged exports yields `Decision: SILENT` until a new asset is affected or a fixed finding reopens:
  ```bash
  python3 -m exposure_radio demo
  # First cycle -> BREAK_IN (lead CVE-2026-118527)
  # Same evidence again -> SILENT (already alerted in memory)
  ```
- **Local Zero Wire enrichment:** `exposure_radio/zero_wire.py` parses active Cloudflare Radar Zero Wire briefings without an account or API key. Exact CVE matches are joined locally onto open action cards with explicit product-coverage caveats. No tenant CVEs are transmitted to Cloudflare, and public briefings never alter KEV status, priority ranking, or verified-fix gates.

---

## 3. Claude Code & MCP Evidence-Gated Triage

**Problem:** Pasting raw vulnerability exports into an LLM risks hallucinated asset counts, fabricated fix confirmations, and prompt injection from untrusted scanner plugin text.

**Workflow:**
1. Open the repository in **Claude Code**. The `.mcp.json` manifest automatically registers the read-only `exposure-radio` stdio MCP server (`python3 -m exposure_radio mcp`).
2. Run the bundled `/exposure-briefing` skill:
   ```text
   /exposure-briefing what should we fix first today, and why?
   ```
3. Under the hood, Claude uses four read-only tools bounded to structured ledger facts:
   - `exposure_briefing` — returns the policy decision, priority lead, and validated narration lines.
   - `explain_priority` — returns the exact ledger facts (`cve.kev`, `cve.open_assets`, `cve.new_exposure_assets`, `cve.epss`, `cve.internal_deadline`) that placed the lead CVE first.
   - `remediation_packet` — produces a copy-ready ticket payload with owners, deadlines, and next steps.
   - `check_claims` — parses candidate prose or structured `(subject, predicate, value, cite)` claims against the evidence ledger and rejects any unsupported statement before it is shown.

You can also run the claim gate directly from the CLI in CI or shell scripts:
```bash
python3 -m exposure_radio check --strict --text "CVE-2024-3400 is open on two assets."
python3 -m exposure_radio gate-demo
```

---

## 4. Executive vs. Analyst Dual-Edition Handoff

**Problem:** Leadership, auditors, and MSP clients need an accurate posture summary without internal hostnames, RFC1918 IP addresses, FQDNs, or asset UUIDs leaking into shared documents—while the patching engineer needs the exact list of affected hosts and owners.

**Workflow:**
- **Executive edition (`--edition executive`):** Strips all asset-level identifiers and runs `find_leaks()` fail-closed against every hostname, FQDN, IPv4/IPv6 address, and asset UUID in the tenant ledger (304 identifiers in the bundled synthetic benchmark):
  ```bash
  python3 -m exposure_radio brief \
    --prev exports/day1 --curr exports/day2 \
    --edition executive --out handoff-executive
  python3 -m exposure_radio audit
  ```
- **Analyst edition (`--edition analyst`):** Produces `card.md` and `card.json` with the per-asset remediation table (`asset`, `owner`, `status`) so the system owner can patch and trigger a verification rescan:
  ```bash
  python3 -m exposure_radio brief \
    --prev exports/day1 --curr exports/day2 \
    --edition analyst --out handoff-analyst
  ```

---

## 5. Scanner Hygiene & Blind-Spot Auditing

**Problem:** In traditional dashboards, a drop in open vulnerability counts often means an SSH/SMB credential expired or a firewall blocked the scanner—not that systems were patched.

**Workflow:**
- **Fail-closed export check:** If `export-status.json` is missing or its status is not `FINISHED`, `exposure_radio/delta.py` marks the export incomplete and refuses to verify *any* fixes (`incomplete export fails closed`).
- **Rescan requirement for `Wins`:** A finding only enters the **Wins: verified fixed** segment when Tenable reports it in the `FIXED` state on an asset that completed a fresh scan in the current window.
- **Unverified & credential-drop tracking:** Findings on assets that disappeared from the scan window or lost credentialed checks (`credentialed_checks: false`) are isolated into the **Blind spots and coverage** desk and trigger a `HEALTH` alert when coverage regresses.

---

## 6. SOC / NOC Ambient Wallboard & Shift Handover

**Problem:** Shift handovers between operations rotations lose track of overnight changes, while standalone threat-intel feeds create noise disconnected from what the team runs.

**Workflow:**
- Run the station host on a dedicated workstation (`python3 -m exposure_radio station serve`) and open the **Station Console** at `http://127.0.0.1:8080/admin.html` using the admin token printed at startup.
- **Customize the hourly clock (`Segments` tab):** Configure how many times per hour each desk airs (`Exposure`, `Wins`, `Blind spots`, `Learn`, `Weather & local`, `News`, `Music`), set **Quiet hours** (e.g., `22:00` to `06:00` so only priority interruptions air overnight), and toggle **Priority findings interrupt music**.
- **Queue team training (`Learn` tab):** Rotate 60-second explainers (*EPSS in sixty seconds*, *New exposure vs. new visibility*, *Why KEV listings change your patch order*) or use a bring-your-own Gemini key to suggest Search-grounded topics for operator approval.
- **Bring-your-own media (`On air` & `Connections` tabs):** Keep the bundled MIT-licensed house beats (`scripts/make_beats.py`), queue official embedded YouTube videos in the signal window (compliant with YouTube Required Minimum Functionality—video visible, never stripped or backgrounded), or enable paid-tier Gemini TTS voices while keeping free-tier projects strictly on local Kokoro voices for tenant exposure segments.
