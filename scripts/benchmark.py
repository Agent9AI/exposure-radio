#!/usr/bin/env python3
"""Measure complete, evidence-checked preparation; makes no human-speed claim."""
import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exposure_radio.pipeline import run_cycle
from exposure_radio.policy import Memory

p = argparse.ArgumentParser()
p.add_argument('--runs', type=int, default=5)
p.add_argument('--out')
a = p.parse_args()
if not 1 <= a.runs <= 20:
    p.error('runs must be between 1 and 20')
elapsed = []
for _ in range(a.runs):
    memory = Memory()
    started = time.perf_counter()
    c = run_cycle(memory=memory, edition='executive')
    repeated = run_cycle(memory=memory, edition='executive')
    elapsed.append(time.perf_counter() - started)
    assert c.episode.gate.passed and repeated.decision.kind == 'SILENT'
    memory.close()
result = {'measure': 'initial briefing plus unchanged rerun, seconds', 'runs': a.runs,
          'seconds': [round(s, 4) for s in elapsed], 'median_seconds': round(statistics.median(elapsed), 4),
          'threshold_seconds': 10, 'passed': max(elapsed) < 10,
          'findings_previous': len(c.delta.prev.findings), 'findings_current': len(c.delta.curr.findings),
          'facts': len(c.ledger.facts), 'spoken_sentences': len(c.episode.lines),
          'unchanged_rerun': repeated.decision.kind, 'python': platform.python_version(),
          'architecture': platform.machine()}
body = json.dumps(result, indent=2) + '\n'
if a.out:
    Path(a.out).write_text(body)
print(body, end='')
raise SystemExit(0 if result['passed'] else 1)
