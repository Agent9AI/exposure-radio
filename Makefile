PY ?= python3

.PHONY: check test gate-demo audit agent-replay demo bench fixtures site audio lint

## check: everything a reviewer needs, stdlib only
check: test gate-demo audit agent-replay

test:
	$(PY) -m unittest discover -s tests -t . -q

## gate-demo: false claims must be blocked before audio
gate-demo:
	$(PY) -m exposure_radio gate-demo

## audit: no tenant hostnames, IPs or asset IDs in executive outputs
audit:
	$(PY) -m exposure_radio audit

## agent-replay: the recorded analyst run, gate executed live, no API key
agent-replay:
	$(PY) -m exposure_radio agent --replay data/replay/analyst_trace.json --out out/agent-replay

demo:
	$(PY) -m exposure_radio demo

## bench: prep-time measurement on the 500-finding fixture
bench:
	$(PY) -m exposure_radio bench --json out/bench.json

## fixtures: regenerate the synthetic tenant (deterministic)
fixtures:
	$(PY) scripts/make_fixtures.py

## site: rebuild the static listen page from the demo outputs
site:
	$(PY) scripts/build_site.py

## audio: synthesise the episode (needs the optional Kokoro stack and ffmpeg)
audio:
	$(PY) -m exposure_radio audio --out out/audio

lint:
	ruff check src tests scripts
