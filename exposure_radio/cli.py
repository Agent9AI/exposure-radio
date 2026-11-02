"""Command line: ``python3 -m exposure_radio <command>``."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from . import __version__
from .adversarial import run_all
from .analyst import make_backend
from .claims import Claim, validate_claim
from .feeds import DEFAULT_KEV
from .gate import audit_text
from .pipeline import DEMO, DEMO_CURR, DEMO_EPSS, DEMO_PREV, Cycle, run_cycle
from .policy import Memory
from .rundown import build_card, card_markdown, find_leaks

BOLD, DIM, RED, GREEN, RESET = "\033[1m", "\033[2m", "\033[31m", "\033[32m", "\033[0m"


def _color(enabled: bool):
    def paint(code: str, text: str) -> str:
        return f"{code}{text}{RESET}" if enabled else text
    return paint


def _analyst(name: str | None):
    if name == "replay":
        name = f"replay:{DEMO / 'analyst-trace.json'}"
    return make_backend(name)


def _print_analyst(cycle: Cycle, paint) -> None:
    r = cycle.rundown
    if r is None:
        return
    t = r.trace
    print(paint(BOLD, "Analyst: ") + f"{r.source} ({t.get('model', 'n/a')}), angle {r.angle}, "
          f"order {', '.join(r.order[:3])}")
    for step in t.get("steps", []):
        args = json.dumps(step.get("args", {}))
        print(paint(DIM, f"  -> {step['tool']} {args[:110]}"))
    for c in r.lead_claims:
        print(paint(DIM, f"  claim {c.subject} {c.predicate} = {c.value} [{c.cite}] validated"))
    for entry in r.log:
        print(paint(DIM, f"  {entry}"))
    if t.get("calls") is not None:
        print(paint(DIM, f"  budget used: {t.get('calls')} model calls, {t.get('tool_calls')} tool calls, "
                         f"~{t.get('tokens')} tokens"))
    print()


def _write_outputs(cycle: Cycle, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    ep = cycle.episode
    (out / "card.md").write_text(card_markdown(ep.card))
    (out / "card.json").write_text(json.dumps(ep.card, indent=2) + "\n")
    (out / "episode.json").write_text(json.dumps({
        "decision": ep.decision.kind, "lead": ep.decision.lead, "episode": ep.decision.episode,
        "policy_log": ep.decision.log, "push": ep.decision.push_payload(),
        "lines": ep.lines, "gate": ep.gate.receipt() if ep.gate else None,
        "ledger": cycle.ledger.public_view(),
    }, indent=2) + "\n")


def _print_cycle(cycle: Cycle, paint, show_card: bool = True) -> None:
    ep, dec = cycle.episode, cycle.decision
    head = {"BREAK_IN": RED, "HEALTH": RED, "SCHEDULED": GREEN, "SILENT": DIM}[dec.kind]
    print(paint(BOLD, f"Decision: ") + paint(head, dec.kind) + (f"  lead {dec.lead}" if dec.lead else ""))
    for entry in dec.log:
        print(paint(DIM, f"  policy: {entry}"))
    for entry in dec.health:
        print(paint(DIM, f"  health: {entry}"))
    if not ep.lines:
        return
    print()
    for line, verdicts in zip(ep.lines, ep.gate.lines):
        ok = all(v.ok for v in verdicts)
        mark = paint(GREEN, "✓") if ok else paint(RED, "✗")
        cites = paint(DIM, f"  [{', '.join(line['cites'])}]") if line["cites"] else ""
        print(f" {mark} {line['voice']:<7} {line['text']}{cites}")
    r = ep.gate.receipt()
    print()
    print(f"Gate: {paint(GREEN, 'PASSED') if r['passed'] else paint(RED, 'BLOCKED')}  "
          f"{r['sentences_checked']} sentences checked, {r['sentences_blocked']} blocked, "
          f"ledger {r['ledger']}, script {r['script_sha256'][:12]}")
    push = dec.push_payload()
    if push:
        print(f"Push payload: {json.dumps(push)}")
    if show_card and ep.card["items"]:
        item = ep.card["items"][0]
        print()
        print(paint(BOLD, f"Action card, item 1 ({ep.edition} edition): {item['cve']}"))
        for step in item["next_steps"]:
            print(f"  [ ] {step}")
        print(f"  owners: {', '.join(item['owners']) or 'unassigned'}; internal deadline "
              f"{item['internal_deadline']}; evidence {len(item['evidence'])} facts")
        for row in item.get("assets", [])[:5]:
            print(paint(DIM, f"  {row['asset']:<12} {row['owner']:<14} {row['status']}"))


def cmd_demo(args) -> int:
    paint = _color(sys.stdout.isatty() and not args.json)
    start = time.perf_counter()
    memory = Memory(args.state) if args.state else Memory()
    first = run_cycle(memory=memory, edition=args.edition, analyst=_analyst(args.analyst))
    t1 = time.perf_counter() - start
    second = run_cycle(memory=memory, edition=args.edition)
    t2 = time.perf_counter() - start - t1
    if args.out:
        _write_outputs(first, Path(args.out))
    if args.json:
        print(json.dumps({"first": first.episode.card, "first_lines": first.episode.lines,
                          "first_gate": first.episode.gate.receipt(),
                          "rerun_decision": second.decision.kind, "rerun_log": second.decision.log}, indent=2))
        return 0 if first.episode.gate.passed else 1
    d = first.delta
    print(paint(BOLD, f"Exposure Radio {__version__} demo") + paint(DIM, "  synthetic tenant, offline feeds"))
    print(paint(DIM, f"Evidence: Tenable VM exports {d.prev.label} ({len(d.prev.findings)} findings) -> "
                     f"{d.curr.label} ({len(d.curr.findings)} findings); {first.ledger.sources['kev']}; "
                     f"{first.ledger.sources.get('epss', 'no EPSS')}"))
    print()
    _print_analyst(first, paint)
    _print_cycle(first, paint)
    print()
    print(paint(BOLD, "Same evidence again:"))
    _print_cycle(second, paint, show_card=False)
    print()
    print(paint(DIM, f"Timing: first cycle {t1 * 1000:.0f} ms, rerun {t2 * 1000:.0f} ms. "
                     f"Facts in ledger: {len(first.ledger.facts)}."))
    if args.out:
        print(paint(DIM, f"Wrote card.md, card.json, episode.json to {args.out}"))
    return 0 if first.episode.gate.passed and second.decision.kind == "SILENT" else 1


def cmd_brief(args) -> int:
    paint = _color(sys.stdout.isatty() and not args.json)
    memory = Memory(args.state) if args.state else Memory()
    cycle = run_cycle(args.prev, args.curr, args.kev, args.epss, memory, args.edition, args.window_hours,
                      analyst=_analyst(args.analyst), prev_kev_path=args.prev_kev)
    if args.out:
        _write_outputs(cycle, Path(args.out))
    if args.json:
        print(json.dumps({"card": cycle.episode.card, "lines": cycle.episode.lines,
                          "gate": cycle.episode.gate.receipt() if cycle.episode.gate else None}, indent=2))
    else:
        _print_analyst(cycle, paint)
        _print_cycle(cycle, paint)
    return 0 if cycle.episode.gate is None or cycle.episode.gate.passed else 1


def cmd_check(args) -> int:
    cycle = run_cycle(args.prev, args.curr, args.kev, args.epss, Memory(), commit=False)
    results = []
    if args.claims:
        raw = json.loads(Path(args.claims).read_text())
        for item in raw if isinstance(raw, list) else [raw]:
            v = validate_claim(Claim.from_dict(item), cycle.ledger)
            results.append(v.as_dict())
    if args.text:
        results += [v.as_dict() for v in audit_text(args.text, cycle.ledger, strict=args.strict)]
    print(json.dumps({"ledger": cycle.ledger.id, "results": results}, indent=2))
    return 0 if all(r.get("ok", r.get("status") == "supported") for r in results) else 1


def cmd_gate_demo(args) -> int:
    paint = _color(sys.stdout.isatty())
    cycle = run_cycle(memory=Memory(), commit=False)
    results, scripts = run_all(cycle.ledger, cycle.episode.lines)
    print(paint(BOLD, "Claim gate: adversarial cases against the demo evidence ledger"))
    print()
    for r in results:
        mark = paint(GREEN, "PASS") if r.passed else paint(RED, "FAIL")
        shown = r.case.text or json.dumps(r.case.claim.as_dict())
        print(f" {mark}  {r.status:<9} {r.case.name}")
        print(paint(DIM, f"        {shown}"))
        print(paint(DIM, f"        -> {r.reasons[0]}"))
    false_cases = [r for r in results if r.case.expect == "blocked"]
    controls = [r for r in results if r.case.expect == "supported"]
    ok = all(r.passed for r in results) and scripts["clean_script_passed"] and not scripts["tampered_script_passed"]
    print()
    print(f"False statements blocked: {sum(r.passed for r in false_cases)} of {len(false_cases)}")
    print(f"Controls supported:       {sum(r.passed for r in controls)} of {len(controls)}")
    print(f"Clean script gate:        {'passed' if scripts['clean_script_passed'] else 'FAILED'} "
          f"({scripts['clean_receipt']['sentences_checked']} sentences)")
    print(f"Tampered script gate:     {'blocked' if not scripts['tampered_script_passed'] else 'NOT BLOCKED'} "
          f"(inserted: {scripts['tampered_blocked'][:1]})")
    print(paint(GREEN if ok else RED, "gate-demo: OK" if ok else "gate-demo: FAILED"))
    return 0 if ok else 1


def cmd_audit(args) -> int:
    """Executive outputs, the script and push payloads must not name tenant systems."""
    cycle = run_cycle(memory=Memory(), commit=False, edition="executive")
    ledger = cycle.ledger
    checks = {
        "executive card": json.dumps(cycle.episode.card),
        "executive card (markdown)": card_markdown(cycle.episode.card),
        "spoken script": json.dumps(cycle.episode.lines),
        "push payload": json.dumps(cycle.decision.push_payload()),
        "model view of facts": json.dumps(ledger.public_view()),
    }
    analyst = build_card(cycle.delta, cycle.decision, ledger, cycle.kev, "analyst")
    failed = 0
    for name, text in checks.items():
        leaks = find_leaks(text, ledger)
        failed += bool(leaks)
        print(f" {'FAIL' if leaks else 'PASS'}  {name}: {len(leaks)} identifiers")
    control = find_leaks(json.dumps(analyst), ledger)
    print(f" {'PASS' if control else 'FAIL'}  control, analyst card lists assets: {len(control)} identifiers")
    print(f"Checked against {len(ledger.sensitive_terms)} tenant identifiers (hostnames, FQDNs, IPs, asset IDs).")
    ok = not failed and bool(control)
    print("audit: OK" if ok else "audit: FAILED")
    return 0 if ok else 1


def cmd_mcp(args) -> int:
    from .mcp_server import serve
    serve()
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="exposure_radio", description="Verified, spoken priority briefings from "
                                                                   "Tenable exports.")
    p.add_argument("--version", action="version", version=f"exposure-radio {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def evidence(sp, required=False):
        sp.add_argument("--prev", default=None if required else str(DEMO_PREV), required=required,
                        help="previous Tenable VM export directory")
        sp.add_argument("--curr", default=None if required else str(DEMO_CURR), required=required,
                        help="current Tenable VM export directory")
        sp.add_argument("--prev-kev", help="actual previous KEV catalog, for feed membership changes")
        sp.add_argument("--kev", default=str(DEFAULT_KEV), help="CISA KEV catalog JSON")
        sp.add_argument("--epss", default=str(DEMO_EPSS) if not required else None,
                        help="EPSS scores (bundled JSON, FIRST API JSON or FIRST CSV)")

    d = sub.add_parser("demo", help="run the bundled synthetic scenario")
    d.add_argument("--edition", choices=("analyst", "executive"), default="analyst")
    d.add_argument("--state", help="SQLite memory file (default: in-memory)")
    d.add_argument("--out", help="write card.md, card.json and episode.json here")
    d.add_argument("--json", action="store_true")
    d.add_argument("--analyst", default=None, help="analyst model: none (template order), anthropic (ANTHROPIC_API_KEY), command (EXPOSURE_RADIO_ANALYST_CMD), replay (bundled recorded run) or replay:PATH")
    d.set_defaults(fn=cmd_demo)

    b = sub.add_parser("brief", help="brief on two of your own exports")
    evidence(b, required=True)
    b.add_argument("--edition", choices=("analyst", "executive"), default="analyst")
    b.add_argument("--state", default="exposure-radio.sqlite3", help="SQLite memory file")
    b.add_argument("--window-hours", type=float, default=24.0, help="scan cycle length")
    b.add_argument("--out")
    b.add_argument("--json", action="store_true")
    b.add_argument("--analyst", default=None, help="analyst model: none (template order), anthropic (ANTHROPIC_API_KEY), command (EXPOSURE_RADIO_ANALYST_CMD), replay (bundled recorded run) or replay:PATH")
    b.set_defaults(fn=cmd_brief)

    c = sub.add_parser("check", help="check text or structured claims against the evidence")
    evidence(c)
    c.add_argument("--text")
    c.add_argument("--claims", help="JSON file: one claim or a list of claims")
    c.add_argument("--strict", action="store_true", help="speech mode: only template sentences pass")
    c.set_defaults(fn=cmd_check)

    g = sub.add_parser("gate-demo", help="adversarial cases: false statements must be blocked")
    g.set_defaults(fn=cmd_gate_demo)

    a = sub.add_parser("audit", help="no tenant identifiers in executive outputs")
    a.set_defaults(fn=cmd_audit)

    m = sub.add_parser("mcp", help="run the read-only MCP server on stdio")
    m.set_defaults(fn=cmd_mcp)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
