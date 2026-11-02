"""Stdio MCP server: Exposure Radio as tools for any MCP client.

All tools are read-only. Export directories must sit under the data root
(``EXPOSURE_RADIO_DATA_ROOT``, default: the working directory) or be the
bundled demo. Responses carry typed facts and gated text, never raw export
content.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from . import __version__
from .claims import Claim, validate_claim
from .gate import audit_text
from .pipeline import DEMO, DEMO_CURR, DEMO_PREV, run_cycle
from .policy import Memory, ranked
from .rundown import build_card, card_markdown

PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")

_EVIDENCE = {
    "prev": {"type": "string", "description": "Previous Tenable VM export directory (default: bundled demo)"},
    "curr": {"type": "string", "description": "Current Tenable VM export directory (default: bundled demo)"},
}
_CLAIM = {"type": "object", "properties": {"subject": {"type": "string"}, "predicate": {"type": "string"},
                                           "value": {}, "cite": {"type": "string"}},
          "required": ["subject", "predicate", "value", "cite"], "additionalProperties": False}

TOOLS = [
    {"name": "exposure_briefing",
     "description": "Compare two Tenable exports and return the policy decision, the gated two-voice script "
                    "with fact citations and gate receipt, and the action card.",
     "inputSchema": {"type": "object", "properties": {
         **_EVIDENCE, "edition": {"type": "string", "enum": ["executive", "analyst"], "default": "executive"}}},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "check_claims",
     "description": "Check text or structured claims against the evidence ledger. Returns supported, blocked "
                    "or unverifiable per sentence, with the evidence behind each verdict.",
     "inputSchema": {"type": "object", "properties": {
         **_EVIDENCE, "text": {"type": "string"}, "claims": {"type": "array", "items": _CLAIM},
         "strict": {"type": "boolean", "default": False,
                    "description": "speech mode: only controlled template sentences pass"}}},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "remediation_packet",
     "description": "Ticket-ready remediation packet for one CVE: assets (analyst edition), owners, deadline, "
                    "CISA required action, next steps and evidence IDs, as Markdown and JSON.",
     "inputSchema": {"type": "object", "properties": {
         **_EVIDENCE, "cve": {"type": "string"},
         "edition": {"type": "string", "enum": ["executive", "analyst"], "default": "analyst"}},
         "required": ["cve"]},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
    {"name": "explain_priority",
     "description": "Why a CVE ranks where it does: rank, the policy reasons, and the typed facts behind it.",
     "inputSchema": {"type": "object", "properties": {**_EVIDENCE, "cve": {"type": "string"}},
                     "required": ["cve"]},
     "annotations": {"readOnlyHint": True, "openWorldHint": False}},
]


class ToolError(Exception):
    pass


def _dir(value: str | None, default: Path) -> Path:
    if not value:
        return default
    root = Path(os.environ.get("EXPOSURE_RADIO_DATA_ROOT", os.getcwd())).resolve()
    path = Path(value).expanduser().resolve()
    for base in (root, DEMO.resolve()):
        if path == base or base in path.parents:
            if not (path / "export-status.json").is_file():
                raise ToolError(f"{value} is not a Tenable export directory")
            for entry in path.rglob("*"):
                if entry.is_symlink():
                    raise ToolError("export directories must not contain symbolic links")
            return path
    raise ToolError("export directories must be inside EXPOSURE_RADIO_DATA_ROOT")


def _cycle(args: dict, edition: str = "analyst"):
    return run_cycle(_dir(args.get("prev"), DEMO_PREV), _dir(args.get("curr"), DEMO_CURR),
                     memory=Memory(), edition=edition, commit=False)


def call_tool(name: str, args: dict) -> dict:
    if name == "exposure_briefing":
        edition = args.get("edition", "executive")
        if edition not in ("executive", "analyst"):
            raise ToolError("edition must be executive or analyst")
        c = _cycle(args, edition)
        ep = c.episode
        return {"decision": ep.decision.kind, "lead": ep.decision.lead, "policy_log": ep.decision.log,
                "health": ep.decision.health, "push_payload": ep.decision.push_payload(),
                "script": [{"voice": l["voice"], "text": l["text"], "cites": l["cites"]} for l in ep.lines],
                "gate": ep.gate.receipt() if ep.gate else None, "card": ep.card}
    if name == "check_claims":
        if not isinstance(args.get("claims", []), list) or len(args.get("claims", [])) > 32:
            raise ToolError("claims must be an array of at most 32 items")
        if len(str(args.get("text", ""))) > 4000:
            raise ToolError("text must be at most 4000 characters")
        c = _cycle(args)
        out = []
        for raw in args.get("claims") or []:
            if not isinstance(raw, dict) or not raw.get("cite"):
                raise ToolError("every structured claim requires an evidence citation")
            out.append(validate_claim(Claim.from_dict(raw), c.ledger).as_dict())
        if args.get("text"):
            out += [v.as_dict() for v in audit_text(str(args["text"])[:4000], c.ledger,
                                                    strict=bool(args.get("strict")))]
        if not out:
            raise ToolError("provide text or claims")
        return {"ledger": c.ledger.id, "results": out}
    if name == "remediation_packet":
        cve = str(args.get("cve", "")).upper()
        edition = args.get("edition", "analyst")
        if edition not in ("executive", "analyst"):
            raise ToolError("edition must be executive or analyst")
        c = _cycle(args, edition)
        card = build_card(c.delta, c.decision, c.ledger, c.kev, edition, limit=50)
        items = [i for i in card["items"] if i["cve"] == cve]
        if not items:
            raise ToolError(f"{cve} has no open finding in this evidence")
        single = dict(card, items=items)
        return {"packet": items[0], "markdown": card_markdown(single)}
    if name == "explain_priority":
        cve = str(args.get("cve", "")).upper()
        c = _cycle(args)
        order = [r.cve for r in ranked(c.delta)]
        if cve not in order:
            raise ToolError(f"{cve} has no open finding in this evidence")
        reasons = [a.reasons for a in c.decision.alerts if a.cve == cve]
        return {"cve": cve, "rank": order.index(cve) + 1, "of": len(order),
                "policy_reasons": reasons[0] if reasons else [],
                "is_lead": cve == c.decision.lead, "decision": c.decision.kind,
                "facts": c.ledger.public_view({cve}),
                "ranking_rule": "exploited and newly listed or newly present > newly listed > exploited > "
                                "new exposure > new visibility > severity > affected assets"}
    raise ToolError(f"unknown tool {name}")


def handle(msg: dict) -> dict | None:
    method, mid = msg.get("method"), msg.get("id")
    if msg.get("jsonrpc") != "2.0" or not isinstance(method, str) or (
            mid is not None and (isinstance(mid, bool) or not isinstance(mid, (int, str)))):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
    if not isinstance(msg.get("params", {}), dict):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "params must be an object"}}
    if mid is None:
        return None                      # notification
    try:
        if method == "initialize":
            asked = (msg.get("params") or {}).get("protocolVersion")
            result = {"protocolVersion": asked if asked in PROTOCOLS else PROTOCOLS[0],
                      "capabilities": {"tools": {"listChanged": False}},
                      "serverInfo": {"name": "exposure-radio", "version": __version__},
                      "instructions": "Read-only. Factual narration is gated against the evidence ledger. "
                                      "Use check_claims before repeating any figure."}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = msg.get("params") or {}
            try:
                arguments = params.get("arguments") or {}
                if not isinstance(arguments, dict):
                    raise ToolError("arguments must be an object")
                payload = call_tool(params.get("name", ""), arguments)
                result = {"content": [{"type": "text", "text": json.dumps(payload, indent=1)}],
                          "structuredContent": payload, "isError": False}
            except ToolError as e:
                result = {"content": [{"type": "text", "text": str(e)}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"unknown method {method}"}}
        return {"jsonrpc": "2.0", "id": mid, "result": result}
    except Exception as e:  # noqa: BLE001
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32603, "message": type(e).__name__}}


def serve(stdin=sys.stdin, stdout=sys.stdout) -> None:
    while True:
        line = stdin.readline(131_074)
        if not line:
            break
        if len(line.encode("utf-8")) > 131_072:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                         "error": {"code": -32600, "message": "request exceeds byte budget"}}) + "\n")
            stdout.flush()
            return
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            stdout.write(json.dumps({"jsonrpc": "2.0", "id": None,
                                     "error": {"code": -32700, "message": "parse error"}}) + "\n")
            stdout.flush()
            continue
        reply = handle(msg) if isinstance(msg, dict) else {"jsonrpc": "2.0", "id": None,
                 "error": {"code": -32600, "message": "invalid request"}}
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
