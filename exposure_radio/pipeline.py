"""One briefing cycle: snapshots -> delta -> decision -> ledger -> script -> gate -> card."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .analyst import Rundown, run_analyst
from .delta import Delta, compute_delta
from .feeds import DATA, DEFAULT_KEV, EpssScores, KevCatalog, load_epss, load_kev
from .gate import gate_script
from .ledger import Ledger, build_ledger
from .policy import Decision, Memory, decide
from .rundown import Episode, build_card, build_script
from .snapshot import load_snapshot

DEMO = DATA / "demo"
DEMO_PREV = DEMO / "2026-10-29"
DEMO_CURR = DEMO / "2026-10-30"
DEMO_EPSS = DATA / "feeds" / "epss-2026-10-30.json"


@dataclass
class Cycle:
    delta: Delta
    decision: Decision
    ledger: Ledger
    kev: KevCatalog
    epss: EpssScores | None
    episode: Episode
    rundown: Rundown | None = None


def run_cycle(prev_dir: str | Path = DEMO_PREV, curr_dir: str | Path = DEMO_CURR,
              kev_path: str | Path = DEFAULT_KEV, epss_path: str | Path | None = DEMO_EPSS,
              memory: Memory | None = None, edition: str = "analyst", window_hours: float = 24.0,
              order: list[str] | None = None, commit: bool = True, analyst=None) -> Cycle:
    """``analyst`` is an optional backend from ``analyst.make_backend``."""
    memory = memory or Memory()
    prev = load_snapshot(prev_dir, window_hours)
    curr = load_snapshot(curr_dir, window_hours)
    # Reconstruct the catalog as it stood at each export.
    kev_prev = load_kev(kev_path, as_of=prev.exported_at.date())
    kev_curr = load_kev(kev_path, as_of=curr.exported_at.date())
    epss = load_epss(epss_path) if epss_path else None
    delta = compute_delta(prev, curr, kev_prev, kev_curr)
    decision = decide(delta, kev_curr, memory)
    ledger = build_ledger(delta, kev_curr, epss, decision.kind, decision.lead)
    rundown = None
    if analyst is not None and decision.kind != "SILENT":
        rundown = run_analyst(ledger, decision, delta, analyst)
        order = rundown.order
        if decision.kind == "BREAK_IN":
            # The interruption leads with what triggered it; the analyst orders the rest.
            order = [decision.lead] + [c for c in order if c != decision.lead]
        elif order and order[0] != decision.lead:
            decision.lead = order[0]
            ledger = build_ledger(delta, kev_curr, epss, decision.kind, decision.lead)
    lines = build_script(decision, ledger, order)
    gate = gate_script(lines, ledger) if lines else None
    card = build_card(delta, decision, ledger, kev_curr, edition)
    if rundown is not None:
        card["analyst"] = {"source": rundown.source, "model": rundown.trace.get("model"), "angle": rundown.angle,
                           "order": rundown.order, "lead_claims": [c.as_dict() for c in rundown.lead_claims],
                           "log": rundown.log}
    episode = Episode(decision, ledger, lines, gate, card, edition)
    if commit and (gate is None or gate.passed):
        memory.commit(decision, delta, kev_curr)
    return Cycle(delta, decision, ledger, kev_curr, epss, episode, rundown)
