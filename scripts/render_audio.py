#!/usr/bin/env python3
"""Render the bundled synthetic briefing using locally installed Kokoro."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exposure_radio.audio import render
from exposure_radio.pipeline import run_cycle

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', required=True)
p.add_argument('--model', required=True, help='Kokoro ONNX model')
p.add_argument('--voices', required=True, help='Kokoro voice data')
args = p.parse_args()
cycle = run_cycle(commit=False)
episode = cycle.episode
if episode.gate is None:
    raise SystemExit('No speech in this cycle')
print(json.dumps(render(episode.lines, episode.gate.receipt(), cycle.ledger,
                        args.output, args.model, args.voices), indent=2))
