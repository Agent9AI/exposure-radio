"""Prep-time benchmark.

Measures how long Exposure Radio takes to turn the 500-finding fixture pair
into a verified briefing and action cards, and counts the discrete manual
operations the documented triage procedure (``docs/MANUAL_TRIAGE.md``)
would need for the same inputs. The manual side is a model: operation
counts are measured from the data, unit times are the documented
assumptions, and both are printed so a reader can substitute their own.

The claim this supports is "briefing preparation time", never "faster
remediation".
"""

from __future__ import annotations

import statistics
import time
from typing import Dict, List, Optional

from .pipeline import run_episode

# Unit times for the manual procedure, in seconds. Mirrored in docs/MANUAL_TRIAGE.md.
MANUAL_UNIT_SECONDS: Dict[str, float] = {
    "open_exports_fixed": 300.0,  # download both exports, open in a spreadsheet, freeze headers
    "dedupe_per_raw_row": 2.0,  # sort, spot and collapse per-port duplicates
    "delta_per_pair": 10.0,  # VLOOKUP both ways and read the result for one (asset, plugin)
    "coverage_per_missing_asset": 60.0,  # check scan logs for an asset absent from the new export
    "kev_lookup_per_cve": 30.0,  # search the KEV catalogue page for one CVE and note dates
    "epss_lookup_per_cve": 20.0,  # query EPSS for one CVE and note score and percentile
    "summary_fixed": 900.0,  # rank items and write the weekly summary paragraph
    "ticket_per_item": 600.0,  # write one ticket with owner, deadline and evidence
    "executive_scrub_fixed": 300.0,  # strip hostnames for the executive copy and re-read it
}

# Reading the generated briefing and action cards before sending them on.
TOOL_REVIEW_SECONDS = 180.0


def run_benchmark(current: str, previous: str, data_dir: Optional[str] = None, runs: int = 5) -> Dict[str, object]:
    runs = max(1, int(runs))
    timings: List[float] = []
    episode = None
    for _ in range(runs):
        started = time.perf_counter()
        episode = run_episode(current, previous, data_dir=data_dir, synthetic_note=False)
        timings.append(time.perf_counter() - started)
    assert episode is not None
    prev_findings = episode.previous_findings or []
    cur_findings = episode.current_findings
    raw_rows = len(episode.current.findings) + (len(episode.previous.findings) if episode.previous else 0)
    pairs = {f.key for f in prev_findings if f.severity > 0} | {f.key for f in cur_findings if f.severity > 0}
    cves = {c for f in cur_findings for c in f.cves} | {c for f in prev_findings for c in f.cves}
    missing_assets = len(episode.delta.coverage.not_rescanned) if episode.delta.coverage else 0
    tickets = int(episode.facts.value("priority", "count", 0) or 0)
    identifiers = len(episode.forbidden.identifiers)

    counts = {
        "raw_rows_both_exports": raw_rows,
        "deduped_pairs_compared": len(pairs),
        "unique_cves": len(cves),
        "assets_not_rescanned": missing_assets,
        "priority_tickets": tickets,
        "tenant_identifiers_scrubbed": identifiers,
        "assets_current": len(episode.current.assets),
        "open_findings_current": int(episode.facts.value("episode", "finding_count", 0) or 0),
    }
    unit = MANUAL_UNIT_SECONDS
    manual_steps = {
        "open_exports": unit["open_exports_fixed"],
        "dedupe": unit["dedupe_per_raw_row"] * raw_rows,
        "delta": unit["delta_per_pair"] * len(pairs),
        "coverage_check": unit["coverage_per_missing_asset"] * missing_assets,
        "kev_lookups": unit["kev_lookup_per_cve"] * len(cves),
        "epss_lookups": unit["epss_lookup_per_cve"] * len(cves),
        "summary": unit["summary_fixed"],
        "tickets": unit["ticket_per_item"] * tickets,
        "executive_scrub": unit["executive_scrub_fixed"],
    }
    manual_total = sum(manual_steps.values())
    tool_median = statistics.median(timings)
    tool_total = tool_median + TOOL_REVIEW_SECONDS
    return {
        "fixture": {"current": current, "previous": previous},
        "runs": runs,
        "pipeline_seconds": {
            "median": round(tool_median, 3),
            "min": round(min(timings), 3),
            "max": round(max(timings), 3),
            "all": [round(t, 3) for t in timings],
        },
        "counts": counts,
        "manual_unit_seconds": dict(unit),
        "manual_step_seconds": {k: round(v, 1) for k, v in manual_steps.items()},
        "manual_total_seconds": round(manual_total, 1),
        "tool_review_seconds": TOOL_REVIEW_SECONDS,
        "tool_total_seconds": round(tool_total, 1),
        "prep_time_saved_seconds": round(manual_total - tool_total, 1),
        "prep_time_ratio": round(manual_total / tool_total, 1) if tool_total else None,
        "gate_passed": episode.gate.passed,
        "claims_checked": episode.gate.receipt.claims_total,
        "note": "Manual times are modelled from documented unit costs applied to measured operation counts; see docs/MANUAL_TRIAGE.md.",
    }


def _hms(seconds: float) -> str:
    seconds = int(round(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {secs:02d}s"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def render_report(report: Dict[str, object]) -> str:
    counts = report["counts"]  # type: ignore[index]
    steps = report["manual_step_seconds"]  # type: ignore[index]
    timing = report["pipeline_seconds"]  # type: ignore[index]
    lines = [
        "Exposure Radio prep-time benchmark",
        "",
        f"Fixture: {counts['raw_rows_both_exports']} raw finding rows across two exports, "  # type: ignore[index]
        f"{counts['assets_current']} assets, {counts['unique_cves']} unique CVEs, "  # type: ignore[index]
        f"{counts['deduped_pairs_compared']} (asset, plugin) pairs compared, "  # type: ignore[index]
        f"{counts['assets_not_rescanned']} assets not rescanned, {counts['priority_tickets']} tickets.",  # type: ignore[index]
        "",
        f"Pipeline wall-clock over {report['runs']} runs: median {timing['median']}s "  # type: ignore[index]
        f"(min {timing['min']}s, max {timing['max']}s); gate {'passed' if report['gate_passed'] else 'FAILED'}, "  # type: ignore[index]
        f"{report['claims_checked']} claims checked.",
        "",
        "Manual procedure (docs/MANUAL_TRIAGE.md), modelled from unit times x measured counts:",
    ]
    for name, seconds in steps.items():  # type: ignore[union-attr]
        lines.append(f"  {name:16} {_hms(float(seconds)):>10}")
    lines.append(f"  {'TOTAL':16} {_hms(float(report['manual_total_seconds'])):>10}")  # type: ignore[arg-type]
    lines.append("")
    lines.append(
        f"Tool path: {timing['median']}s pipeline + {_hms(float(report['tool_review_seconds']))} human review "  # type: ignore[index]
        f"= {_hms(float(report['tool_total_seconds']))}."  # type: ignore[arg-type]
    )
    lines.append(
        f"Prep time saved: {_hms(float(report['prep_time_saved_seconds']))} per episode "  # type: ignore[arg-type]
        f"({report['prep_time_ratio']}x). This is preparation time, not remediation time."
    )
    return "\n".join(lines)
