# Tenable segments: keeping a small team on the same page

A small IT team rarely has a security standup. Exposure Radio gives them one they can
hear while they work. Each Tenable segment answers one question a teammate would
otherwise ask in chat, and each one is built from the difference between two complete
Tenable Vulnerability Management exports.

| Segment | Question it answers | Built from | When it airs |
|---|---|---|---|
| **Priority** | Is there anything we must fix today? | A finding newly on CISA's exploited list, newly exposed, or reopened | Interrupts the music as soon as the export lands |
| **Watch list** | What else moved since the last scan? | Top-ranked open findings: new exposure first, then new visibility | Start of the day, then after each scan |
| **Wins** | What did we close? | Findings in the FIXED state, confirmed by a rescan in this cycle | Once a day, after the watch list |
| **Blind spots** | What can't we see? | Assets that missed the cycle, lost credentialed scanning, or newly entered coverage | Once a day |

## Why these four

- **Priority** is the only interruption. It is rare by design: identical evidence never airs
  twice, and a fix closes the alert until the finding reopens.
- **Watch list** separates *new exposure* (something changed on a machine we already scan)
  from *new visibility* (a machine we just started scanning). Without that distinction,
  better coverage sounds like a worse week, and teams learn to ignore the number.
- **Wins** keeps the team motivated and stops duplicate work. Only a rescan counts as a fix.
  A finding that disappears because the scan missed the machine is reported as unverified.
- **Blind spots** is the segment teams skip in a dashboard and need most. Missed scans and
  lost credentials are where a "clean" report lies.

## What is spoken, and what stays on screen

The hosts say product names and counts ("the Ivanti Connect Secure flaw is open on one
asset"). CVE identifiers, asset names, owners and deadlines are on the action card and
the screen, where they can be copied. Nothing about a specific machine is spoken.

Every spoken sentence is rebuilt from the evidence ledger and checked by the claim gate
before a voice engine sees it (see [ADR 0001](adr/0001-verified-claims-before-speech.md)).

## Connecting Tenable

1. In Tenable Vulnerability Management, create API keys for a user with read access to
   vulnerabilities and assets (Settings → My Account → API Keys, or a dedicated service user).
2. On the station host: `python3 -m exposure_radio station keys set tenable`.
3. Pull an export: `python3 -m exposure_radio station pull`. It uses the read-only export
   APIs and writes `export-status.json`, `assets.json` and `vulns/chunk-N.json`.
4. Brief on two pulls: `python3 -m exposure_radio brief --prev exports/DAY1 --curr exports/DAY2 --kev feeds/kev.json`.
   Schedule `station pull` after your scan window (cron or a systemd timer) so each morning has a fresh pair.

The bundled demo uses synthetic exports in exactly this format, so the same code path
runs with or without a Tenable tenant.
