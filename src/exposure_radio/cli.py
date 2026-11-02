"""Command line interface: ``python3 -m exposure_radio <command>``.

Standard library only. Optional extras (audio synthesis, the analyst
model) are imported inside their commands so that the core never needs
them.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List, Optional, Sequence

from . import __version__
from .model import ExportError
from .pipeline import DEFAULT_DATA_DIR, Episode, run_episode, write_outputs

FIXTURES = os.path.join(DEFAULT_DATA_DIR, "fixtures")
DEFAULT_PREVIOUS = os.path.join(FIXTURES, "previous.json")
DEFAULT_CURRENT = os.path.join(FIXTURES, "current.json")


def _episode_from_args(args: argparse.Namespace) -> Episode:
    previous = None if getattr(args, "no_previous", False) else args.previous
    return run_episode(
        args.current,
        previous,
        data_dir=args.data_dir,
        synthetic_note=not getattr(args, "no_synthetic_note", False),
        episode_date=getattr(args, "episode_date", None),
    )


def _add_export_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--current", default=DEFAULT_CURRENT, help="current Tenable export (JSON, .nessus or CSV)")
    parser.add_argument("--previous", default=DEFAULT_PREVIOUS, help="previous export; use --no-previous for a first episode")
    parser.add_argument("--no-previous", action="store_true", help="brief a single export with no delta")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="directory with feeds/, sla.json and owners.json")
    parser.add_argument("--episode-date", default=None, help="override the episode date (YYYY-MM-DD)")
    parser.add_argument("--no-synthetic-note", action="store_true", help="omit the 'synthetic estate' intro sentence")


def _print_receipt(episode: Episode) -> None:
    receipt = episode.gate.receipt
    print(
        f"Gate receipt: {'PASS' if receipt.passed else 'FAIL'} | claims {receipt.claims_accepted}/{receipt.claims_total}"
        f" | sentences {receipt.sentence_count} | sha256 {receipt.script_sha256[:16]}..."
    )
    for name, ok in receipt.checks.items():
        print(f"  [{'x' if ok else ' '}] {name}")
    if receipt.rejections:
        print(f"  rejections: {len(receipt.rejections)}")
    if receipt.issues:
        print(f"  issues: {[i['code'] for i in receipt.issues]}")


def cmd_demo(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    episode = _episode_from_args(args)
    paths = write_outputs(episode, args.out)
    elapsed = time.perf_counter() - started
    print("=" * 72)
    print("EXPOSURE RADIO  |  verified priority briefing")
    print("=" * 72)
    if episode.held:
        print("HELD: " + "; ".join(episode.hold_reasons))
    print()
    for sentence in episode.sentences:
        print(sentence)
    print()
    print("-" * 72)
    summary = episode.delta.summary()
    print(
        f"Delta: closed {summary.get('closed', 0)} (critical {summary.get('critical_closed', 0)}) | "
        f"new exposure {summary.get('new_exposure', 0)} | new visibility {summary.get('new_visibility', 0)} | "
        f"unverified absence {summary.get('unverified_absence', 0)} | assets rescanned {summary.get('assets_rescanned', 0)}, "
        f"absent {summary.get('assets_not_rescanned', 0)}, new in scope {summary.get('assets_newly_in_scope', 0)}"
    )
    print("-" * 72)
    _print_receipt(episode)
    print("-" * 72)
    print(f"Alert preview (zero PII): {episode.alert['body']}  [ref {episode.alert['reference']}]")
    pii = {k: [i.code for i in v] for k, v in episode.pii_issues.items()}
    print(f"Identifier audit: {'clean' if not any(pii.values()) else pii}")
    print("-" * 72)
    items = episode.packet_full.get("items", [])
    if items:
        print("ACTION CARD (lead item, full edition):")
        print()
        print(items[0]["ticket_markdown"])
    print("-" * 72)
    print(f"Outputs in {args.out}/: " + ", ".join(sorted(os.path.basename(p) for p in paths.values())))
    print(f"Done in {elapsed:.2f}s (parse, dedupe, delta, facts, gate, card, alert).")
    return 0 if episode.gate.passed else 1


def cmd_briefing(args: argparse.Namespace) -> int:
    episode = _episode_from_args(args)
    if args.json:
        print(
            json.dumps(
                {
                    "passed": episode.gate.passed,
                    "held": episode.held,
                    "sentences": episode.transcript(),
                    "receipt": episode.gate.receipt.to_dict(),
                    "alert": episode.alert,
                    "sources": episode.sources,
                },
                indent=2,
            )
        )
    else:
        for sentence in episode.sentences:
            print(sentence)
        print()
        _print_receipt(episode)
    return 0 if episode.gate.passed else 1


def cmd_packet(args: argparse.Namespace) -> int:
    episode = _episode_from_args(args)
    packet = episode.packet_full if args.edition == "full" else episode.packet_ciso
    items = packet.get("items", [])
    if args.cve:
        items = [i for i in items if i["cve"].upper() == args.cve.upper()]
        if not items:
            print(f"{args.cve} is not a priority item in this episode", file=sys.stderr)
            return 2
    if args.json:
        print(json.dumps(dict(packet, items=items), indent=2))
    else:
        print("\n\n---\n\n".join(i["ticket_markdown"] for i in items) or "(no items)")
    return 0


def cmd_gate_demo(args: argparse.Namespace) -> int:
    from .gate_demo import render_table, run

    episode = _episode_from_args(args)
    ok, cases = run(episode)
    print(render_table(episode, cases))
    if args.json:
        print(json.dumps([c.to_dict() for c in cases], indent=2))
    return 0 if ok else 1


def cmd_audit(args: argparse.Namespace) -> int:
    """Zero-PII audit over the CISO edition, the alert and anonymised outputs."""
    episode = _episode_from_args(args)
    failures = 0
    for name, issues in episode.pii_issues.items():
        if name == "narration":
            continue
        status = "clean" if not issues else "LEAK"
        print(f"{name:16} {status}" + (f"  {[i.to_dict() for i in issues]}" if issues else ""))
        failures += 1 if issues else 0
    narration_issues = episode.gate.receipt.issues
    print(f"{'narration':16} {'clean' if not narration_issues else 'LEAK'}")
    failures += 1 if narration_issues else 0
    hostnames = len(episode.forbidden.identifiers)
    print(f"checked against {hostnames} tenant identifiers and {len(episode.forbidden.plugin_names)} plugin names")
    return 0 if failures == 0 else 1


def cmd_check_claims(args: argparse.Namespace) -> int:
    from .claims import Claim, validate

    episode = _episode_from_args(args)
    with open(args.claims, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    if isinstance(raw, dict):
        raw = raw.get("claims", [])
    claims = [Claim.from_dict(c) for c in raw]
    accepted, rejected = validate(claims, episode.facts)
    print(json.dumps({"accepted": [c.to_dict() for c in accepted], "rejected": [r.to_dict() for r in rejected]}, indent=2))
    return 0 if not rejected else 1


def cmd_facts(args: argparse.Namespace) -> int:
    episode = _episode_from_args(args)
    print(episode.facts.to_json(redact=args.redact))
    return 0


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import serve_stdio

    return serve_stdio(data_dir=args.data_dir, default_current=args.current, default_previous=args.previous)


def cmd_bench(args: argparse.Namespace) -> int:
    from .bench import run_benchmark, render_report

    report = run_benchmark(args.current, args.previous, data_dir=args.data_dir, runs=args.runs)
    print(render_report(report))
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2)
            handle.write("\n")
        print(f"written {args.json}")
    return 0


def cmd_feeds(args: argparse.Namespace) -> int:
    from .feeds import load_feeds, refresh

    feeds_dir = os.path.join(args.data_dir, "feeds")
    if args.action == "refresh":
        print("Downloading CISA KEV and FIRST EPSS (explicit opt-in network access)...")
        summary = refresh(feeds_dir)
        for name, line in summary.items():
            print(f"  {name}: {line}")
        return 0
    feeds = load_feeds(feeds_dir)
    print(f"KEV: {len(feeds.kev.entries)} entries, version {feeds.kev.catalog_version or 'none'}")
    print(f"EPSS: {len(feeds.epss.scores)} scores, score date {feeds.epss.score_date or 'none'}")
    print(f"Tenable Research: {len(feeds.research.items)} publications")
    for source in feeds.ledger.to_list():
        print(f"  {source['id']}: {source['coverage'] or 'coverage unspecified'} | sha256 {source['sha256'][:12]}")
    return 0


def cmd_agent(args: argparse.Namespace) -> int:
    from .agent import run_agent_cli

    return run_agent_cli(args)


def cmd_audio(args: argparse.Namespace) -> int:
    from .audio.produce import produce_cli

    return produce_cli(args)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="exposure_radio", description="Verified spoken exposure briefings from Tenable exports.")
    parser.add_argument("--version", action="version", version=f"exposure-radio {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="run the full pipeline on the bundled synthetic estate")
    _add_export_args(p)
    p.add_argument("--out", default="out/demo", help="directory for the written artefacts")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("briefing", help="print the verified narration for two exports")
    _add_export_args(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_briefing)

    p = sub.add_parser("packet", help="print ticket-ready action cards")
    _add_export_args(p)
    p.add_argument("--edition", choices=("full", "ciso"), default="full")
    p.add_argument("--cve", default=None)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_packet)

    p = sub.add_parser("gate-demo", help="show the gate blocking planted false claims")
    _add_export_args(p)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_gate_demo)

    p = sub.add_parser("audit", help="zero-PII audit over CISO edition, alert and anonymised outputs")
    _add_export_args(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("check-claims", help="validate a JSON file of claims against the ledger")
    _add_export_args(p)
    p.add_argument("claims")
    p.set_defaults(func=cmd_check_claims)

    p = sub.add_parser("facts", help="dump the evidence ledger as JSON")
    _add_export_args(p)
    p.add_argument("--redact", action="store_true", help="omit evidence rows (asset identifiers)")
    p.set_defaults(func=cmd_facts)

    p = sub.add_parser("mcp", help="serve the read-only MCP tools over stdio")
    _add_export_args(p)
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("bench", help="prep-time benchmark on the 500-finding fixture")
    p.add_argument("--current", default=os.path.join(FIXTURES, "bench", "current_500.json"))
    p.add_argument("--previous", default=os.path.join(FIXTURES, "bench", "previous_500.json"))
    p.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--json", default=None, help="write the report to this JSON file")
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("feeds", help="inspect or refresh the offline feed snapshots")
    p.add_argument("action", choices=("status", "refresh"))
    p.add_argument("--data-dir", default=DEFAULT_DATA_DIR)
    p.set_defaults(func=cmd_feeds)

    p = sub.add_parser("agent", help="opt-in bounded analyst agent (needs ANTHROPIC_API_KEY) or a recorded replay")
    _add_export_args(p)
    p.add_argument("--replay", default=None, help="replay a recorded trace instead of calling a model")
    p.add_argument("--record", default=None, help="write the trace of this run to a JSON file")
    p.add_argument("--model", default=None, help="model id (default: claude-sonnet-5-5)")
    p.add_argument("--scripted", action="store_true", help="use the built-in scripted model stand-in (no network)")
    p.add_argument("--out", default="out/agent", help="directory for the written artefacts")
    p.set_defaults(func=cmd_agent)

    p = sub.add_parser("audio", help="synthesise the episode (optional audio extras required)")
    _add_export_args(p)
    p.add_argument("--out", default="out/audio")
    p.add_argument("--voice", default="af_heart")
    p.add_argument("--model-path", default=None)
    p.add_argument("--voices-dir", default=None)
    p.add_argument("--mp3-bitrate", default="64k")
    p.set_defaults(func=cmd_audio)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        return int(args.func(args))
    except ExportError as exc:
        print(f"export error: {exc}", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"missing file: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
