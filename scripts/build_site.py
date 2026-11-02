#!/usr/bin/env python3
"""Build the data for the public listener page (web/data/*.json). Standard library only.

    python3 scripts/build_site.py

Runs the bundled demo cycle in the EXECUTIVE edition, the adversarial gate suite,
and writes four JSON files for ``web/index.html``:

    episode.json    decision, lead, policy log, push payload, script lines, gate receipt
    card.json       the executive action card (never the analyst edition)
    facts.json      the ledger's public_view() for the subjects the page references
    gate-demo.json  every adversarial case, the summary and the script tamper test

Fail-closed rules, checked before anything is written:

* the clean script passed the gate, and the adversarial suite is fully green;
* the push payload carries no CVE ID and no digits outside its opaque reference;
* every citation on a spoken line resolves to a fact in facts.json;
* if ``web/assets/cues.json`` exists, its lines match the gated script exactly;
* no output contains a tenant identifier (hostname, FQDN, IP or asset ID), as
  judged by ``exposure_radio.rundown.find_leaks``. One adversarial case plants a
  tenant hostname on purpose; its text is redacted before publication.

Output is deterministic: the same evidence produces byte-identical files.
Re-run this script after adding ``web/assets/briefing.mp3`` (and ``cues.json``) so
the page knows the audio exists; without it the page offers the transcript only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from exposure_radio import __version__  # noqa: E402
from exposure_radio.adversarial import run_all  # noqa: E402
from exposure_radio.gate import BLOCKED, SUPPORTED  # noqa: E402
from exposure_radio.pipeline import run_cycle  # noqa: E402
from exposure_radio.policy import Memory  # noqa: E402
from exposure_radio.rundown import find_leaks  # noqa: E402

REPO_URL = "https://github.com/Agent9AI/exposure-radio"
REDACTED_HOST = "[tenant host]"
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.I)
FACT_RE = re.compile(r"\bF\d{3}\b")


class BuildError(RuntimeError):
    """The public data would be wrong or would expose the tenant."""


def _redact(text: str, ledger) -> tuple[str, bool]:
    leaks = find_leaks(text, ledger)
    for term in sorted(leaks, key=len, reverse=True):
        text = re.sub(rf"(?<![\w.-]){re.escape(term)}(?![\w-])", REDACTED_HOST, text, flags=re.I)
    return text, bool(leaks)


def _load_cues(path: Path, lines: list[dict]) -> list[dict] | None:
    """Cues must describe exactly the gated script, or the page would narrate other text."""
    if not path.is_file():
        return None
    raw = json.loads(path.read_text())
    cues = raw.get("cues", raw.get("lines")) if isinstance(raw, dict) else raw
    if not isinstance(cues, list) or len(cues) != len(lines):
        raise BuildError(f"{path}: expected {len(lines)} cues, found "
                         f"{len(cues) if isinstance(cues, list) else 'no list'}")
    for i, (cue, line) in enumerate(zip(cues, lines)):
        if cue.get("text") != line["text"]:
            raise BuildError(f"{path}: cue {i} text does not match the gated script line")
        start, end = cue.get("start"), cue.get("end")
        if not (isinstance(start, (int, float)) and isinstance(end, (int, float)) and 0 <= start <= end):
            raise BuildError(f"{path}: cue {i} needs numeric start <= end seconds")
    return cues


def build(web: Path) -> dict[str, object]:
    memory = Memory()
    cycle = run_cycle(memory=memory, edition="executive")
    ep, ledger, decision = cycle.episode, cycle.ledger, cycle.decision
    card = ep.card
    if ep.edition != "executive" or card.get("edition") != "executive":
        raise BuildError("public card must be the executive edition")
    if any("assets" in item for item in card["items"]):
        raise BuildError("executive card unexpectedly lists assets")
    if ep.gate is None or not ep.gate.passed:
        raise BuildError("the demo script did not pass the claim gate; nothing is published without a receipt")
    rerun = run_cycle(memory=memory, edition="executive")

    # --- adversarial suite ----------------------------------------------------------------------
    results, scripts = run_all(ledger, ep.lines)
    false_cases = [r for r in results if r.case.expect == BLOCKED]
    controls = [r for r in results if r.case.expect == SUPPORTED]
    suite_ok = (all(r.passed for r in results) and scripts["clean_script_passed"]
                and not scripts["tampered_script_passed"])
    if not suite_ok:
        raise BuildError("gate-demo is not green; fix the gate before publishing")

    cases, redactions = [], 0
    for r in results:
        entry: dict[str, object] = {"name": r.case.name, "expected": r.case.expect, "status": r.status,
                                    "passed": r.passed}
        if r.case.text is not None:
            text, hit = _redact(r.case.text, ledger)
            entry["text"] = text
        else:
            claim = r.case.claim.as_dict()
            text, hit = _redact(json.dumps(claim), ledger)
            entry["claim"] = json.loads(text)
        reason, hit2 = _redact(r.reasons[0] if r.reasons else "", ledger)
        entry["reason"] = reason
        if hit or hit2:
            entry["redacted"] = True
            redactions += 1
        cases.append(entry)
    tampered = [_redact(t, ledger)[0] for t in scripts["tampered_blocked"]]
    gate_demo = {
        "summary": {"false_blocked": sum(r.passed for r in false_cases), "false_total": len(false_cases),
                    "controls_supported": sum(r.passed for r in controls), "controls_total": len(controls),
                    "all_passed": suite_ok},
        "scripts": {"clean_passed": scripts["clean_script_passed"],
                    "clean_sentences": scripts["clean_receipt"]["sentences_checked"],
                    "clean_receipt": scripts["clean_receipt"],
                    "tampered_passed": scripts["tampered_script_passed"],
                    "tampered_blocked": tampered},
        "redaction_note": f"Tenant hostnames in case text are shown as {REDACTED_HOST}." if redactions else None,
        "cases": cases,
    }

    # --- push payload ---------------------------------------------------------------------------
    push = decision.push_payload()
    if push:
        visible = f"{push['title']} {push['body']}"
        if CVE_RE.search(visible) or re.search(r"\d", visible):
            raise BuildError("push payload text carries a CVE ID or a number")

    # --- facts: public view only, for the subjects this page can reference ----------------------
    public = ledger.public_view()
    by_id = {f["id"]: f for f in public}
    wanted = {"tenant", "bulletin"} | {item["cve"] for item in card["items"]}
    wanted |= {by_id[c]["subject"] for line in ep.lines for c in line["cites"] if c in by_id}
    wanted |= {m.upper() for m in CVE_RE.findall(json.dumps(cases))}
    wanted |= {by_id[m]["subject"] for m in FACT_RE.findall(json.dumps(cases)) if m in by_id}
    facts = ledger.public_view(subjects=wanted)
    fact_ids = {f["id"] for f in facts}
    dangling = sorted({c for line in ep.lines for c in line["cites"]} - fact_ids)
    if dangling:
        raise BuildError(f"spoken lines cite facts missing from the public view: {dangling}")

    # --- media manifest -------------------------------------------------------------------------
    audio = web / "assets" / "briefing.mp3"
    cues = _load_cues(web / "assets" / "cues.json", ep.lines)
    media = {"audio": "assets/briefing.mp3" if audio.is_file() and audio.stat().st_size > 0 else None,
             "cues": "assets/cues.json" if cues is not None else None}

    # --- episode --------------------------------------------------------------------------------
    lead_name = next((f["value"] for f in facts if f["subject"] == decision.lead and f["predicate"] == "cve.name"),
                     None)
    lines = []
    for i, (line, verdicts) in enumerate(zip(ep.lines, ep.gate.lines)):
        lines.append({"index": i, "voice": line["voice"], "text": line["text"], "cites": line["cites"],
                      "template": line["template"],
                      "verdict": SUPPORTED if all(v.ok for v in verdicts) else BLOCKED})
    episode = {
        "product": "Exposure Radio", "version": __version__, "edition": "executive", "repo": REPO_URL,
        "episode": decision.episode, "as_of": card["as_of"], "decision": decision.kind, "lead": decision.lead,
        "lead_name": lead_name, "policy_log": decision.log, "health": decision.health, "push": push,
        "rerun": {"decision": rerun.decision.kind, "policy_log": rerun.decision.log},
        "lines": lines, "gate": ep.gate.receipt(), "sources": ledger.sources,
        "tenant": {"synthetic": True, "assets_total": ledger.value("tenant", "tenant.assets_total"),
                   "findings_prev": len(cycle.delta.prev.findings),
                   "findings_curr": len(cycle.delta.curr.findings),
                   "export_prev": cycle.delta.prev.label, "export_curr": cycle.delta.curr.label},
        "media": media,
    }

    outputs = {"episode.json": episode, "card.json": card, "facts.json": facts, "gate-demo.json": gate_demo}

    # --- leak check: the last gate before disk --------------------------------------------------
    failures = []
    for name, obj in outputs.items():
        leaks = find_leaks(json.dumps(obj, ensure_ascii=False), ledger)
        if leaks:
            failures.append(f"{name}: {len(leaks)} tenant identifier(s), e.g. {leaks[:3]}")
    if failures:
        raise BuildError("tenant identifiers would be published:\n  " + "\n  ".join(failures))
    return outputs


def write(outputs: dict[str, object], out_dir: Path) -> list[tuple[str, int]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for name, obj in outputs.items():
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n"
        target = out_dir / name
        tmp = target.with_suffix(".json.tmp")
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, target)
        written.append((name, len(body.encode())))
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Build web/data/*.json for the public listener page.")
    p.add_argument("--web", default=str(ROOT / "web"), help="site directory (default: web/)")
    args = p.parse_args(argv)
    web = Path(args.web)
    try:
        outputs = build(web)
    except BuildError as exc:
        print(f"build_site: FAILED: {exc}", file=sys.stderr)
        return 1
    for name, size in write(outputs, web / "data"):
        print(f"wrote {web / 'data' / name} ({size:,} bytes)")
    ep, gd = outputs["episode.json"], outputs["gate-demo.json"]["summary"]
    print(f"decision {ep['decision']}, lead {ep['lead']}, gate passed, "
          f"{gd['false_blocked']}/{gd['false_total']} false statements blocked, "
          f"{gd['controls_supported']}/{gd['controls_total']} controls supported; "
          f"audio {'present' if ep['media']['audio'] else 'absent'}, "
          f"cues {'present' if ep['media']['cues'] else 'absent'}; leak check: 0 tenant identifiers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
