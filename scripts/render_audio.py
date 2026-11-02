#!/usr/bin/env python3
"""Render the bundled synthetic briefing using locally installed Kokoro."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from exposure_radio.audio import render
from exposure_radio.pipeline import DEMO_CURR, DEMO_EPSS, DEMO_PREV, run_cycle
from exposure_radio.feeds import DEFAULT_KEV

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--output', required=True)
p.add_argument('--prev', type=Path, help='Previous Tenable export directory')
p.add_argument('--curr', type=Path, help='Current Tenable export directory')
p.add_argument('--kev', type=Path, help='Current local KEV catalog (required for custom exports)')
p.add_argument('--prev-kev', type=Path, help='Actual previous KEV catalog')
p.add_argument('--epss', type=Path, help='Local EPSS snapshot')
p.add_argument('--model', required=True, help='Kokoro ONNX model')
p.add_argument('--voices', required=True, help='Kokoro voice data')
args = p.parse_args()
if bool(args.prev) != bool(args.curr):
    p.error('--prev and --curr must be supplied together')
if args.prev and not args.kev:
    p.error('custom exports require --kev to identify the current supplied catalog')
cycle = run_cycle(args.prev or DEMO_PREV, args.curr or DEMO_CURR,
                  args.kev or DEFAULT_KEV, args.epss or (None if args.prev else DEMO_EPSS),
                  edition='executive', commit=False, prev_kev_path=args.prev_kev)
episode = cycle.episode
if episode.gate is None:
    raise SystemExit('No speech in this cycle')
print(json.dumps(render(episode.lines, episode.gate.receipt(), cycle.ledger,
                        args.output, args.model, args.voices), indent=2))
