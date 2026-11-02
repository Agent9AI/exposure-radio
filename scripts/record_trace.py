#!/usr/bin/env python3
"""Record a live analyst run on the demo evidence, for replay without a key.

    EXPOSURE_RADIO_ANALYST=anthropic ANTHROPIC_API_KEY=... python3 scripts/record_trace.py
    EXPOSURE_RADIO_ANALYST=command EXPOSURE_RADIO_ANALYST_CMD='claude -p --model claude-sonnet-5-5' \\
        python3 scripts/record_trace.py

The trace stores each model action and the tool result it received. Replay
recomputes every tool result from the bundled evidence and stops if any
differs, so the recording cannot be passed off against other data.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from exposure_radio.analyst import Limits, make_backend, run_analyst  # noqa: E402
from exposure_radio.pipeline import DEMO, run_cycle  # noqa: E402
from exposure_radio.policy import Memory  # noqa: E402


def main() -> int:
    backend = make_backend()
    if backend is None:
        print("set EXPOSURE_RADIO_ANALYST to anthropic or command", file=sys.stderr)
        return 2
    cycle = run_cycle(memory=Memory(), commit=False)
    limits = Limits(max_seconds=float(sys.argv[1]) if len(sys.argv) > 1 else 300.0)
    rundown = run_analyst(cycle.ledger, cycle.decision, cycle.delta, backend, limits)
    trace = dict(rundown.trace)
    trace.update(recorded_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                 backend=type(backend).__name__, source=rundown.source, angle=rundown.angle,
                 order=rundown.order, log=rundown.log,
                 token_counts="exact (API usage)" if type(backend).__name__ == "AnthropicBackend"
                 else "approximate (characters / 4)")
    out = DEMO / "analyst-trace.json"
    if rundown.source != "analyst":
        print(json.dumps(trace, indent=1))
        print("analyst did not complete; trace not saved", file=sys.stderr)
        return 1
    out.write_text(json.dumps(trace, indent=1) + "\n")
    print(f"saved {out} ({len(trace['steps'])} steps, {trace.get('seconds')} s)")
    for entry in rundown.log:
        print(entry)
    return 0


if __name__ == "__main__":
    sys.exit(main())
