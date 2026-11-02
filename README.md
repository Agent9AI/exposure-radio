# Exposure Radio

**Two Tenable exports in, one verified priority briefing out: what changed, what to act on
today, and a ticket-ready action card. It can read the briefing aloud, and every factual
sentence is checked against the evidence before any audio is made.**

```bash
git clone https://github.com/Agent9AI/exposure-radio && cd exposure-radio
python3 -m exposure_radio demo      # Python 3.10+, standard library only, no network
make check                          # tests + false-claim gate demo + hostname audit
```

## What a vulnerability manager gets

The demo compares two daily exports from a synthetic 76-asset tenant (455 and 545 findings)
against the real CISA KEV catalog (version 2026.10.30) and real FIRST EPSS scores:

```
Decision: BREAK_IN  lead CVE-2026-118527
  policy: CVE-2026-118527: newly listed by CISA
  policy: CVE-2026-41709: newly appeared on scanned assets
  policy: CVE-2021-44228: found on newly scanned assets
  health: 11 of 64 previously scanned assets were not rescanned

 ✓ ANCHOR  Priority bulletin: CVE-2026-118527 needs action today.  [F013, F012]
 ✓ ANALYST CISA listed CVE-2026-118527 as exploited since the last briefing.  [F230]
 ✓ ANALYST CVE-2026-118527 is open on 1 asset.  [F223]
 ✓ ANALYST Your internal deadline for CVE-2026-118527 is 2026-11-06.  [F235]
 ✓ ANCHOR  Next step: follow CISA's required action for CVE-2026-118527, then rescan to confirm.
 ...
 ✓ ANALYST Exposure grew by 4 priority findings on assets that were already being scanned.
 ✓ ANALYST Visibility grew: 2 priority findings came from 12 newly scanned assets.
 ✓ ANALYST 3 open priority findings on missed assets are unverified, not fixed.

Gate: PASSED  23 sentences checked, 0 blocked
Push payload: {"title": "Exposure Radio", "body": "Priority bulletin ready.", "ref": "21b83de056a4"}

Same evidence again:
Decision: SILENT
  policy: episode 21b83de056a4 was already briefed; evidence unchanged, nothing repeated
```

Three things a plain diff gets wrong, and this does not:

| Situation | Naive diff says | Exposure Radio says |
|---|---|---|
| A lab segment is scanned for the first time | "Exposure up 86 findings" | New **visibility**: 2 priority findings from 12 newly scanned assets |
| A branch scanner misses its window | "BlueKeep gone from 3 hosts" | **Unverified**, not fixed: 11 assets missed the cycle |
| CISA lists a CVE you already had | Nothing changed | **Break in**: newly exploited, open on the VPN gateway since 21 Oct |

The action card (`--out DIR` writes `card.md` and `card.json`) gives each item its affected
assets, owners, internal deadline, CISA's required action, the next steps as a checklist,
and the fact IDs that back every line.

## The claim gate

Matching CVE IDs and numbers in generated text is not verification. "CVE-2024-3400 is fixed
on 20 assets" contains a real CVE and a number, and it is false when the evidence says the
finding is open on 2 assets and fixed on none.

1. **Typed facts.** Exports and feeds become `(subject, predicate, value, source)` facts.
2. **Typed claims.** Anything that wants to state a fact emits `(subject, predicate, value,
   cite)`. A claim passes only if the cited fact exists, is about the same subject and
   predicate, and holds the same value.
3. **Controlled narration.** Speech is rendered from validated claims through fixed
   templates, then parsed back into claims and checked again as text.
4. **Receipts.** A passing script gets a receipt bound to the ledger and the exact text;
   audio is rendered only for a matching receipt.

`make gate-demo` runs 22 adversarial cases against the demo evidence:

| Case | Result |
|---|---|
| "CVE-2024-3400 is fixed on 20 assets." | blocked: evidence says 0 fixed, open on 2 |
| "CVE-2024-3400 is not on CISA's KEV list." | blocked: evidence says listed |
| "Everything is safe." / "Disable your monitoring." | blocked: all-clear / directive |
| "CVE-2019-0708 has been fixed." | blocked: still open on 3 (not rescanned) |
| "...newly appeared on two assets..." | blocked: evidence says 3 |
| Real fact cited for the wrong CVE | blocked: citation mismatch |
| Instruction planted in a scanner plugin name | blocked, and never shown to a model |
| 5 true controls, including number words | supported |

Result: 17 of 17 false statements blocked, 5 of 5 controls supported, and a script with
one false line inserted is refused.

## Data boundary

- Plugin output, synopsis, description and solution text are never read.
- Kept names are length-capped and reduced to a safe character set; invalid hostnames are
  dropped.
- Executive editions, the spoken script and push payloads are checked fail-closed for every
  tenant hostname, FQDN, IP address and asset ID (`make audit`: 0 of 304 leaked).
- Push payloads carry generic text and an opaque reference only.
- The core makes no network calls. The bundled KEV and EPSS snapshots keep your CVE list
  on your machine.

## Use your own exports

Export with the Tenable VM API (`POST /vulns/export` with states OPEN, REOPENED and FIXED,
plus `POST /assets/export`) into a directory per cycle:

```
2026-11-02/export-status.json   vulns/chunk-1.json ...   assets.json
```

```bash
python3 -m exposure_radio brief --prev exports/2026-11-01 --curr exports/2026-11-02 \
    --epss epss_scores-2026-11-02.csv.gz --out out/ --edition analyst
python3 -m exposure_radio check --text "CVE-2024-3400 is fixed on 20 assets."
```

An incomplete export (failed chunks, missing files) fails closed: no fix is confirmed.

## Measured

| Check | Result |
|---|---|
| `make test` | 49 tests pass |
| `make gate-demo` | 17/17 false statements blocked, 5/5 controls supported |
| `make audit` | 0 tenant identifiers in executive outputs, script, push or model view |
| Demo wall time, Raspberry Pi 4 | 1.42 s median of 5 runs, 32 MB peak memory |

MIT licensed. See [SECURITY.md](SECURITY.md) and [docs/adr](docs/adr).
