# ADR-0002: Coverage is scan activity, not presence in the export

Date: 2026-11-02
Status: accepted

## Context

A Tenable Vulnerability Management export is a state dump, not a scan
result. It lists every open finding the platform knows about, including
findings on assets that were last scanned weeks ago. A `.nessus` file is the
opposite: it contains only the hosts one scan touched. A delta engine that
treats "the asset appears in the current export" as "the asset was scanned
this cycle" will call a finding fixed when the asset was merely skipped, and
will call a stale row current.

## Decision

1. Every asset carries a `last_activity` stamp: the latest scan completion
   or last-found time seen for it in the export, or `last_scan_time` from an
   asset inventory file when one is present.
2. The current scope is the set of assets whose `last_activity` is later
   than the previous export's latest scan completion. With no previous
   export, or no stamps at all, every asset is in scope.
3. The delta classifies against that scope:
   - open before, open now, asset in scope: persisting;
   - open before, open now, asset out of scope: **unverified open** (the row
     was carried forward, nothing confirmed it);
   - open before, absent now, asset in scope: closed;
   - open before, absent now, asset out of scope: **unverified absence**;
   - open now, absent before, asset previously known: new exposure;
   - open now, asset never seen before: new visibility;
   - fixed before, open now: reopened.
4. The spoken briefing names both unverified categories and never counts
   either as fixed. The asset count it states is the scanned scope, and the
   inventory size is kept as a separate fact.

## Consequences

Running the same export twice marks every asset as not rescanned, which is
correct: no new scan happened. Organisations whose scans span more than one
day see assets in scope as long as their activity is later than the previous
export; cadences shorter than a scan window would need the window made
explicit. The second synthetic tenant in `data/fixtures/tenant-b` exercises
the stale-row case; the first exercises the missing-asset case.
