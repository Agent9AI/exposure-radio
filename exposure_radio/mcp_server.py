"""Read-only MCP server over stdio.

Implements the Model Context Protocol JSON-RPC surface a client needs for
tools: ``initialize``, ``notifications/initialized``, ``ping``,
``tools/list`` and ``tools/call``. Three tools are exposed:

* ``exposure_briefing``: the verified narration, receipt and alert;
* ``check_claims``: validate claims against the episode's ledger;
* ``remediation_packet``: the ticket-ready action cards.

The server never writes: the episode memory is in-process, export paths
are restricted to the working directory and the data directory, and all
output is JSON on stdout. Diagnostics go to stderr.
"""

from __future__ import annotations

import json
import os
import sys
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .claims import Claim, validate
from .model import ExportError
from .pipeline import DEFAULT_DATA_DIR, Episode, run_episode

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_LINE = 1024 * 1024
MAX_CLAIMS = 200

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "exposure_briefing",
        "title": "Exposure briefing",
        "description": (
            "Turn two Tenable exports (previous and current) into a verified priority briefing. Returns the gate-approved "
            "sentences with their cited facts, the gate receipt, the coverage-aware delta and a zero-PII alert preview. "
            "Read-only; exports default to the bundled synthetic estate."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "current": {"type": "string", "description": "path to the current export (JSON, .nessus or CSV)"},
                "previous": {"type": "string", "description": "path to the previous export; omit for a single-export episode"},
                "edition": {"type": "string", "enum": ["full", "ciso"], "description": "ciso hides tenant identifiers"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "check_claims",
        "title": "Check claims",
        "description": (
            "Validate structured claims (subject, predicate, value, cite) against the episode's evidence ledger. "
            "A claim is accepted only when the cited fact exists and has the same subject, predicate and value."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "claims": {
                    "type": "array",
                    "maxItems": MAX_CLAIMS,
                    "items": {
                        "type": "object",
                        "properties": {
                            "subject": {"type": "string"},
                            "predicate": {"type": "string"},
                            "value": {},
                            "cite": {"type": "string"},
                        },
                        "required": ["subject", "predicate", "value", "cite"],
                    },
                },
                "current": {"type": "string"},
                "previous": {"type": "string"},
            },
            "required": ["claims"],
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
    {
        "name": "remediation_packet",
        "title": "Remediation packet",
        "description": (
            "Ticket-ready action cards for the priority items: owner, internal SLA deadline, KEV catalogue dates, "
            "cited evidence and copyable Markdown. The ciso edition withholds asset identifiers."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "cve": {"type": "string", "description": "limit to one CVE id"},
                "edition": {"type": "string", "enum": ["full", "ciso"]},
                "current": {"type": "string"},
                "previous": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "annotations": {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False},
    },
]


class ToolError(ValueError):
    pass


class Server:
    def __init__(self, data_dir: str = DEFAULT_DATA_DIR, default_current: Optional[str] = None, default_previous: Optional[str] = None) -> None:
        self.data_dir = os.path.abspath(data_dir)
        self.default_current = default_current or os.path.join(self.data_dir, "fixtures", "current.json")
        self.default_previous = default_previous or os.path.join(self.data_dir, "fixtures", "previous.json")
        self.roots = (os.path.realpath(os.getcwd()), os.path.realpath(self.data_dir))
        self._cache: OrderedDict[Tuple[str, Optional[str]], Episode] = OrderedDict()
        self.initialized = False

    # --- helpers ---------------------------------------------------------
    def _resolve(self, path: Optional[str], default: Optional[str]) -> Optional[str]:
        if path is None or path == "":
            return default
        if not isinstance(path, str) or len(path) > 1024 or "\x00" in path:
            raise ToolError("path must be a short string")
        candidate = os.path.realpath(path)  # symlinks resolved before the root check
        if not any(candidate == root or candidate.startswith(root + os.sep) for root in self.roots):
            raise ToolError("export paths must be inside the working directory or the data directory")
        if not os.path.isfile(candidate):
            raise ToolError("export file does not exist")
        return candidate

    def episode(self, current: Optional[str], previous: Optional[str], use_default_previous: bool = True) -> Episode:
        cur = self._resolve(current, self.default_current)
        prev = self._resolve(previous, self.default_previous if use_default_previous else None)
        key = (cur or "", prev)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        episode = run_episode(cur or self.default_current, prev, data_dir=self.data_dir)  # in-process memory, closed by the pipeline
        self._cache[key] = episode
        while len(self._cache) > 4:
            self._cache.popitem(last=False)
        return episode

    # --- tools -----------------------------------------------------------
    def tool_exposure_briefing(self, args: Dict[str, Any]) -> Dict[str, Any]:
        edition = args.get("edition", "full")
        if edition not in ("full", "ciso"):
            raise ToolError("edition must be full or ciso")
        episode = self.episode(args.get("current"), args.get("previous"), use_default_previous="previous" not in args)
        transcript = episode.transcript()
        if edition == "ciso":
            for row in transcript:
                for cite in row["cites"]:
                    cite.pop("evidence", None)
        return {
            "edition": edition,
            "passed": episode.gate.passed,
            "held": episode.held,
            "hold_reasons": episode.hold_reasons,
            "sentences": transcript,
            "receipt": episode.gate.receipt.to_dict(),
            "delta": episode.delta.summary(),
            "alert": episode.alert,
            "sources": episode.sources,
            "memory_trend": episode.memory_trend,
        }

    def tool_check_claims(self, args: Dict[str, Any]) -> Dict[str, Any]:
        raw = args.get("claims")
        if not isinstance(raw, list) or len(raw) > MAX_CLAIMS:
            raise ToolError(f"claims must be a list of at most {MAX_CLAIMS} objects")
        try:
            claims = [Claim.from_dict(c) for c in raw]
        except ValueError as exc:
            raise ToolError(str(exc)) from None
        episode = self.episode(args.get("current"), args.get("previous"), use_default_previous="previous" not in args)
        accepted, rejected = validate(claims, episode.facts)
        return {
            "accepted": [c.to_dict() for c in accepted],
            "rejected": [r.to_dict() for r in rejected],
            "ledger_size": len(episode.facts),
        }

    def tool_remediation_packet(self, args: Dict[str, Any]) -> Dict[str, Any]:
        edition = args.get("edition", "full")
        if edition not in ("full", "ciso"):
            raise ToolError("edition must be full or ciso")
        episode = self.episode(args.get("current"), args.get("previous"), use_default_previous="previous" not in args)
        packet = episode.packet_full if edition == "full" else episode.packet_ciso
        items = list(packet.get("items", []))
        cve = args.get("cve")
        if cve:
            if not isinstance(cve, str) or len(cve) > 32:
                raise ToolError("cve must be a short string")
            items = [i for i in items if i["cve"].upper() == cve.upper()]
        return dict(packet, items=items)

    # --- JSON-RPC --------------------------------------------------------
    def handle(self, message: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "invalid request")
        method = message.get("method")
        msg_id = message.get("id")
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return self._error(msg_id, -32602, "params must be an object")
        if method == "initialize":
            requested = str(params.get("protocolVersion", PROTOCOL_VERSIONS[0]))
            version = requested if requested in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0]
            self.initialized = True
            return self._result(
                msg_id,
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "exposure-radio", "version": __version__},
                    "instructions": (
                        "Read-only tools over Tenable exports. Facts are cited by id; use check_claims before stating "
                        "anything the briefing did not say."
                    ),
                },
            )
        if method == "notifications/initialized" or (isinstance(method, str) and method.startswith("notifications/")):
            return None
        if method == "ping":
            return self._result(msg_id, {})
        if method == "tools/list":
            return self._result(msg_id, {"tools": TOOLS})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                return self._error(msg_id, -32602, "arguments must be an object")
            handler = {
                "exposure_briefing": self.tool_exposure_briefing,
                "check_claims": self.tool_check_claims,
                "remediation_packet": self.tool_remediation_packet,
            }.get(str(name))
            if handler is None:
                return self._error(msg_id, -32602, f"unknown tool {name!r}")
            try:
                payload = handler(args)
            except (ToolError, ExportError) as exc:
                return self._result(msg_id, {"content": [{"type": "text", "text": str(exc)}], "isError": True})
            return self._result(
                msg_id,
                {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    "structuredContent": payload,
                    "isError": False,
                },
            )
        if msg_id is None:
            return None
        return self._error(msg_id, -32601, f"method not found: {method}")

    @staticmethod
    def _result(msg_id: Any, result: Dict[str, Any]) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def serve_stdio(data_dir: str = DEFAULT_DATA_DIR, default_current: Optional[str] = None, default_previous: Optional[str] = None) -> int:
    server = Server(data_dir, default_current, default_previous)
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    print(f"exposure-radio MCP server {__version__} on stdio (read-only)", file=sys.stderr, flush=True)
    while True:
        line = stdin.readline(MAX_LINE + 1)
        if not line:
            return 0
        if len(line) > MAX_LINE:
            response: Optional[Dict[str, Any]] = Server._error(None, -32600, "message too large")
        else:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                message = json.loads(stripped.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                response = Server._error(None, -32700, "parse error")
            else:
                response = server.handle(message)
        if response is not None:
            stdout.write((json.dumps(response) + "\n").encode("utf-8"))
            stdout.flush()
