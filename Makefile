PY ?= python3
export PYTHONPATH := src

.PHONY: check test gate-demo audit demo fixtures

## check: everything a reviewer needs, stdlib only
check: test gate-demo audit

test:
	$(PY) -m unittest discover -s tests -t . -q

## gate-demo: false claims must be blocked before audio
gate-demo:
	$(PY) -m exposure_radio gate-demo

## audit: no tenant hostnames, IPs or asset IDs in executive outputs
audit:
	$(PY) -m exposure_radio audit

demo:
	$(PY) -m exposure_radio demo

## fixtures: regenerate the synthetic tenant (deterministic)
fixtures:
	$(PY) scripts/make_fixtures.py
