"""Shared helpers: one cached demo episode for the slower integration tests."""

import os

from exposure_radio.pipeline import run_episode

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIX = os.path.join(ROOT, "data", "fixtures")
CURRENT = os.path.join(FIX, "current.json")
PREVIOUS = os.path.join(FIX, "previous.json")
PARTIAL = os.path.join(FIX, "current_partial.json")

_CACHE = {}


def demo_episode():
    if "demo" not in _CACHE:
        _CACHE["demo"] = run_episode(CURRENT, PREVIOUS)
    return _CACHE["demo"]


def held_episode():
    if "held" not in _CACHE:
        _CACHE["held"] = run_episode(PARTIAL, PREVIOUS)
    return _CACHE["held"]


def first_episode():
    if "first" not in _CACHE:
        _CACHE["first"] = run_episode(CURRENT, None)
    return _CACHE["first"]
