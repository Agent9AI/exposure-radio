"""Bounded analyst agent (opt-in).

One model call loop that proposes the lead item, an angle and a break-in
decision for the episode. The model sees redacted evidence only (facts
without asset rows, the CISO edition of the packet), through the same three
read-only tools the MCP server exposes. Its proposal is a set of structured
claims; those go through the gate exactly like the deterministic producer's.
A rejection is sent back as the tool result and forces a rewrite, at most
twice. If the loop runs out of retries, calls, tokens or wall-clock time, the
template edition airs. Template mode is the default; nothing here runs unless
asked for.

Three transports share the loop:

* ``AnthropicTransport``: the Claude API through the ``anthropic`` SDK
  (optional dependency, user's own key, ``claude-opus-5-5`` by default);
* ``ScriptedTransport``: a deterministic stand-in that behaves like an
  analyst who misquotes a number once and corrects it. It needs no network
  and is what produced the committed replay trace;
* ``ReplayTransport``: plays the model responses recorded in a trace file
  back into the loop; tools and the gate run live.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .briefing import build_segments
from .claims import Claim
from .gate import GateResult, run_gate
from .pipeline import Episode, run_episode, write_outputs
from .templates import FIXED, TEMPLATES, Segment, TemplateError
from .textaudit import audit_free_text

DEFAULT_MODEL = "claude-opus-5-5"
MAX_CALLS = 6
MAX_TOKENS_TOTAL = 60_000
MAX_WALL_SECONDS = 90.0
MAX_RETRIES = 2
MAX_OUTPUT_TOKENS = 4_000

ANGLES = ("new_kev_entry", "longest_open", "largest_reach", "closure_progress", "default")

SYSTEM_PROMPT = """You are the analyst for Exposure Radio, a spoken vulnerability briefing built from two Tenable exports.
Your job is editorial: choose the lead item, the angle and whether this episode is urgent enough to break in,
then submit a plan with propose_edition.

Rules you cannot work around:
- Every number, date or status you use must come from the facts returned by exposure_briefing, cited by fact id.
  Claims are checked in code; a claim whose cited fact has a different subject, predicate or value is rejected
  and you must rewrite it.
- Narration is rendered from fixed templates. You pick template ids and supply the claims they take; you never
  write free sentences. Hostnames, IP addresses and scanner text are not available to you and must not be requested.
- Use the tools, then call propose_edition exactly once per attempt. If the gate rejects your proposal you get the
  rejection reasons as the tool result; fix the claims and call propose_edition again.
- Prefer the week's genuine news: a KEV catalogue addition touching the estate, a reopened critical, a large
  closure. Break in only when a KEV-listed critical is newly exposed or a public exploit appeared since the previous export.
"""

TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "exposure_briefing",
        "description": "Return the redacted evidence ledger for this episode (facts with ids, no asset identifiers), the template edition's sentences, the delta summary and the template catalogue.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
        "strict": True,
    },
    {
        "name": "check_claims",
        "description": "Validate claims (subject, predicate, value, cite) against the ledger before proposing them.",
        "input_schema": {
            "type": "object",
            "properties": {
                "claims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "subject": {"type": "string"},
                            "predicate": {"type": "string"},
                            "value": {"type": ["string", "number", "boolean", "array"]},
                            "cite": {"type": "string"},
                        },
                        "required": ["subject", "predicate", "value", "cite"],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["claims"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "remediation_packet",
        "description": "Return the CISO edition of the action card for one CVE (counts and groups, no identifiers).",
        "input_schema": {
            "type": "object",
            "properties": {"cve": {"type": "string"}},
            "required": ["cve"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "name": "propose_edition",
        "description": (
            "Submit the editorial plan. items is the ordered list of CVE ids to cover (first is the lead). "
            "angle_template and angle_claims add one extra templated sentence right after the lead item; use a cve.* "
            "template about the lead CVE, or leave both empty. break_in marks the episode as urgent."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 3},
                "angle": {"type": "string", "enum": list(ANGLES)},
                "angle_template": {"type": "string"},
                "angle_claims": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "subject": {"type": "string"},
                            "predicate": {"type": "string"},
                            "value": {"type": ["string", "number", "boolean", "array"]},
                            "cite": {"type": "string"},
                        },
                        "required": ["subject", "predicate", "value", "cite"],
                        "additionalProperties": False,
                    },
                },
                "break_in": {"type": "boolean"},
                "rationale": {"type": "string"},
            },
            "required": ["items", "angle", "angle_template", "angle_claims", "break_in", "rationale"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]


# --------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------


class TransportError(RuntimeError):
    pass


class Transport:
    name = "base"

    def complete(self, system: str, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        raise NotImplementedError


class AnthropicTransport(Transport):
    """Claude API through the official SDK. Imported lazily: optional extra."""

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, client: Any = None) -> None:
        self.model = model
        if client is None:
            try:
                import anthropic  # type: ignore
            except ImportError as exc:  # pragma: no cover - depends on the environment
                raise TransportError("the analyst agent needs the optional 'anthropic' package: pip install anthropic") from exc
            if not os.environ.get("ANTHROPIC_API_KEY") and not os.environ.get("ANTHROPIC_AUTH_TOKEN"):
                raise TransportError("set ANTHROPIC_API_KEY (your own key) to run the analyst agent, or use --replay / --scripted")
            client = anthropic.Anthropic()
        self.client = client

    def complete(self, system: str, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        try:
            response = self.client.beta.messages.create(
                model=self.model,
                max_tokens=MAX_OUTPUT_TOKENS,
                system=system,
                messages=messages,
                tools=tools,
                output_config={"effort": "medium"},
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
            )
        except Exception as exc:  # the SDK's typed errors all derive from Exception; the loop aborts to template mode
            raise TransportError(f"model call failed: {type(exc).__name__}: {exc}") from exc
        data = response.to_dict() if hasattr(response, "to_dict") else response
        if not isinstance(data, dict):
            raise TransportError("unexpected response shape from the SDK")
        return data


class ReplayTransport(Transport):
    """Plays recorded model responses back; the loop still runs tools and the gate."""

    name = "replay"

    def __init__(self, trace: Dict[str, Any]) -> None:
        self.responses = [e["response"] for e in trace.get("events", []) if e.get("type") == "response"]
        self.cursor = 0
        self.recorded_transport = trace.get("transport", "unknown")

    def complete(self, system: str, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        if self.cursor >= len(self.responses):
            raise TransportError("replay trace has no more recorded responses")
        response = self.responses[self.cursor]
        self.cursor += 1
        return response


class ScriptedTransport(Transport):
    """Deterministic analyst stand-in.

    Turn 1: asks for the evidence. Turn 2: proposes the lead with an angle
    sentence whose claim misquotes the asset count by one (the classic
    off-by-one an LLM makes when it reasons from the previous episode).
    Turn 3: reads the rejection, re-cites the correct fact and resubmits.
    """

    name = "scripted"

    def __init__(self) -> None:
        self.turn = 0
        self.facts: List[Dict[str, Any]] = []
        self.counter = 0

    def _id(self) -> str:
        self.counter += 1
        return f"toolu_scripted_{self.counter:03d}"

    def _fact(self, subject: str, predicate: str) -> Optional[Dict[str, Any]]:
        for fact in self.facts:
            if fact["subject"] == subject and fact["predicate"] == predicate:
                return fact
        return None

    def complete(self, system: str, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        self.turn += 1
        last = messages[-1]
        if isinstance(last.get("content"), list):
            for block in last["content"]:
                if block.get("type") == "tool_result":
                    try:
                        payload = json.loads(block["content"]) if isinstance(block["content"], str) else block["content"]
                    except (ValueError, TypeError):
                        payload = {}
                    if isinstance(payload, dict) and "facts" in payload:
                        self.facts = payload["facts"]
        usage = {"input_tokens": 1200 + 400 * self.turn, "output_tokens": 180}
        if self.turn == 1:
            return {
                "stop_reason": "tool_use",
                "content": [
                    {"type": "text", "text": "Pulling the evidence ledger before choosing a lead."},
                    {"type": "tool_use", "id": self._id(), "name": "exposure_briefing", "input": {}},
                ],
                "usage": usage,
            }
        lead = None
        new_entries = self._fact("delta", "kev_new_entries")
        if new_entries and new_entries.get("value"):
            lead = new_entries["value"][0]
            angle = "new_kev_entry"
        else:
            items_fact = self._fact("priority", "items")
            lead = (items_fact or {}).get("value", [None])[0]
            angle = "default"
        items_fact = self._fact("priority", "items")
        items = list((items_fact or {}).get("value", []))
        if lead and lead in items:
            items.remove(lead)
        items = ([lead] if lead else []) + items
        subject = f"cve:{lead}"
        open_fact = self._fact(subject, "open_asset_count")
        rank_fact = self._fact(subject, "priority_rank")
        sev_fact = self._fact(subject, "severity")
        first_seen = self._fact(subject, "first_seen")
        if self.turn == 2:
            # The slip: the count is quoted one too high, and the rank is asserted rather than read.
            claims = [
                {"subject": subject, "predicate": "priority_rank", "value": 1, "cite": rank_fact["id"] if rank_fact else "f0000"},
                {"subject": subject, "predicate": "severity", "value": sev_fact["value"] if sev_fact else "critical", "cite": sev_fact["id"] if sev_fact else "f0000"},
                {"subject": subject, "predicate": "open_asset_count", "value": (open_fact["value"] + 1) if open_fact else 2, "cite": open_fact["id"] if open_fact else "f0000"},
            ]
            return {
                "stop_reason": "tool_use",
                "content": [
                    {"type": "text", "text": f"Leading with {lead}: it is the KEV addition of the week and it is open in the estate."},
                    {
                        "type": "tool_use",
                        "id": self._id(),
                        "name": "propose_edition",
                        "input": {
                            "items": items[:3],
                            "angle": angle,
                            "angle_template": "cve.lead",
                            "angle_claims": claims,
                            "break_in": True,
                            "rationale": "A KEV-listed critical is newly exposed on the estate this week.",
                        },
                    },
                ],
                "usage": usage,
            }
        # Turn 3+: corrected proposal built strictly from the cited facts.
        if first_seen:
            angle_template = "cve.first_seen"
            claims = [{"subject": subject, "predicate": "first_seen", "value": first_seen["value"], "cite": first_seen["id"]}]
        else:
            angle_template = ""
            claims = []
        return {
            "stop_reason": "tool_use",
            "content": [
                {"type": "text", "text": "The gate rejected the asset count; re-reading the ledger and citing the recorded value."},
                {
                    "type": "tool_use",
                    "id": self._id(),
                    "name": "propose_edition",
                    "input": {
                        "items": items[:3],
                        "angle": angle,
                        "angle_template": angle_template,
                        "angle_claims": claims,
                        "break_in": True,
                        "rationale": "A KEV-listed critical is newly exposed on the estate this week; the count now matches the ledger.",
                    },
                },
            ],
            "usage": usage,
        }


# --------------------------------------------------------------------------
# Tools the model may call (redacted views only)
# --------------------------------------------------------------------------


class RedactedTools:
    def __init__(self, episode: Episode) -> None:
        self.episode = episode

    def _guard(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        issues = audit_free_text(json.dumps(payload, sort_keys=True), self.episode.forbidden)
        if issues:
            return {"error": "tool output withheld: identifier audit failed", "issues": [i.to_dict() for i in issues]}
        return payload

    def exposure_briefing(self, _args: Dict[str, Any]) -> Dict[str, Any]:
        return self._guard(
            {
                "facts": self.episode.facts.to_list(redact=True),
                "template_edition": list(self.episode.gate.sentences),
                "delta": self.episode.delta.summary(),
                "templates": {tid: list(t.slots) for tid, t in TEMPLATES.items()},
                "fixed_sentences": sorted(FIXED),
            }
        )

    def check_claims(self, args: Dict[str, Any]) -> Dict[str, Any]:
        from .claims import validate

        raw = args.get("claims")
        if not isinstance(raw, list) or len(raw) > 50:
            return {"error": "claims must be a list of at most 50 objects"}
        try:
            claims = [Claim.from_dict(c) for c in raw]
        except ValueError as exc:
            return {"error": str(exc)}
        accepted, rejected = validate(claims, self.episode.facts)
        return {"accepted": [c.to_dict() for c in accepted], "rejected": [r.to_dict() for r in rejected]}

    def remediation_packet(self, args: Dict[str, Any]) -> Dict[str, Any]:
        cve = str(args.get("cve", "")).upper()
        items = [i for i in self.episode.packet_ciso.get("items", []) if i.get("cve") == cve]
        return self._guard({"items": items})


# --------------------------------------------------------------------------
# The loop
# --------------------------------------------------------------------------


@dataclass
class AgentOutcome:
    mode: str  # "analyst" or "template"
    reason: str
    gate: GateResult
    segments: List[Segment]
    items: List[str]
    angle: str
    break_in: bool
    calls: int
    tokens: int
    elapsed: float
    retries: int
    trace: Dict[str, Any] = field(default_factory=dict)

    @property
    def sentences(self) -> List[str]:
        return list(self.gate.sentences)


def _proposal_segments(episode: Episode, proposal: Dict[str, Any]) -> List[Segment]:
    items = proposal.get("items")
    if not isinstance(items, list) or not items or len(items) > 3:
        raise TemplateError("items must list 1 to 3 CVE ids")
    known = set(episode.facts.cves())
    clean_items: List[str] = []
    for item in items:
        if not isinstance(item, str) or item.upper() not in known:
            raise TemplateError(f"{item!r} is not a CVE in this episode's ledger")
        if int(episode.facts.value(f"cve:{item.upper()}", "open_asset_count", 0) or 0) <= 0:
            raise TemplateError(f"{item} has no open findings and cannot be an item")
        clean_items.append(item.upper())
    segments = build_segments(episode.facts, synthetic_note="intro.synthetic" in {s.template_id for s in episode.segments}, items=clean_items)
    template_id = str(proposal.get("angle_template") or "")
    raw_claims = proposal.get("angle_claims") or []
    if template_id:
        if template_id not in TEMPLATES or not template_id.startswith("cve."):
            raise TemplateError(f"angle_template must be a cve.* template, got {template_id!r}")
        if not isinstance(raw_claims, list) or len(raw_claims) > 8:
            raise TemplateError("angle_claims must be a short list")
        angle = Segment(template_id, tuple(Claim.from_dict(c) for c in raw_claims))
        # Insert right after the lead item's headline sentence.
        insert_at = len(segments) - 2
        for index, segment in enumerate(segments):
            if segment.template_id in ("cve.lead", "cve.item"):
                insert_at = index + 1
                break
        segments.insert(insert_at, angle)
    return segments


def run_agent(
    episode: Episode,
    transport: Transport,
    max_calls: int = MAX_CALLS,
    max_tokens: int = MAX_TOKENS_TOTAL,
    max_seconds: float = MAX_WALL_SECONDS,
    max_retries: int = MAX_RETRIES,
) -> AgentOutcome:
    started = time.monotonic()
    tools = RedactedTools(episode)
    messages: List[Dict[str, Any]] = [
        {
            "role": "user",
            "content": (
                f"Plan the episode for export date {episode.facts.value('episode', 'export_date')}. "
                "Call exposure_briefing first, then propose_edition."
            ),
        }
    ]
    trace: Dict[str, Any] = {
        "transport": transport.name,
        "model": getattr(transport, "model", None),
        "caps": {"max_calls": max_calls, "max_tokens": max_tokens, "max_seconds": max_seconds, "max_retries": max_retries},
        "events": [],
    }
    calls = tokens = retries = 0
    nudged = False

    def event(kind: str, **data: Any) -> None:
        entry = {"type": kind, "t": round(time.monotonic() - started, 3)}
        entry.update(data)
        trace["events"].append(entry)

    def template_fallback(reason: str) -> AgentOutcome:
        event("abort", reason=reason)
        event("final", mode="template", reason=reason)
        return AgentOutcome("template", reason, episode.gate, list(episode.segments), list(episode.facts.value("priority", "items", ()) or ()), "default", False, calls, tokens, time.monotonic() - started, retries, trace)

    while True:
        if calls >= max_calls:
            return template_fallback(f"call cap reached ({max_calls})")
        if tokens >= max_tokens:
            return template_fallback(f"token cap reached ({tokens} >= {max_tokens})")
        if time.monotonic() - started >= max_seconds:
            return template_fallback(f"wall-clock cap reached ({max_seconds}s)")
        calls += 1
        event("request", call=calls, message_count=len(messages))
        try:
            response = transport.complete(SYSTEM_PROMPT, messages, TOOL_DEFINITIONS)
        except TransportError as exc:
            return template_fallback(str(exc))
        usage = response.get("usage") or {}
        tokens += int(usage.get("input_tokens", 0) or 0) + int(usage.get("output_tokens", 0) or 0)
        event("response", call=calls, response=response, tokens_so_far=tokens)
        stop = response.get("stop_reason")
        content = response.get("content") or []
        if stop == "refusal":
            return template_fallback("model declined the request")
        if stop == "max_tokens":
            return template_fallback("model output hit max_tokens")
        tool_uses = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_use"]
        messages.append({"role": "assistant", "content": content})
        if not tool_uses:
            if nudged:
                return template_fallback("model ended without calling propose_edition")
            nudged = True
            messages.append({"role": "user", "content": "Submit the plan by calling propose_edition."})
            continue
        results: List[Dict[str, Any]] = []
        for block in tool_uses:
            name = block.get("name")
            args = block.get("input") if isinstance(block.get("input"), dict) else {}
            if name == "propose_edition":
                try:
                    segments = _proposal_segments(episode, args)
                except (TemplateError, ValueError) as exc:
                    gate_result = None
                    verdict = {"accepted": False, "reasons": [{"code": "PROPOSAL", "detail": str(exc)}]}
                else:
                    gate_result = run_gate(segments, episode.facts, episode.forbidden, edition="full")
                    verdict = {
                        "accepted": gate_result.passed,
                        "reasons": [r for rej in gate_result.receipt.rejections for r in rej["reasons"]] + gate_result.receipt.issues,
                    }
                event("gate", call=calls, accepted=verdict["accepted"], reasons=verdict["reasons"])
                if verdict["accepted"] and gate_result is not None:
                    event("final", mode="analyst", items=args.get("items"), angle=args.get("angle"), break_in=bool(args.get("break_in")))
                    return AgentOutcome(
                        "analyst",
                        "proposal passed the gate",
                        gate_result,
                        segments,
                        [str(i).upper() for i in args.get("items", [])],
                        str(args.get("angle", "default")),
                        bool(args.get("break_in", False)),
                        calls,
                        tokens,
                        time.monotonic() - started,
                        retries,
                        trace,
                    )
                retries += 1
                if retries > max_retries:
                    return template_fallback(f"proposal rejected {retries} times; template edition airs")
                results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": block.get("id"),
                        "content": json.dumps({"gate": "rejected", "attempt": retries, "reasons": verdict["reasons"], "instruction": "Fix the claims so each cites a fact with the same subject, predicate and value, then call propose_edition again."}),
                        "is_error": True,
                    }
                )
                continue
            handler = {"exposure_briefing": tools.exposure_briefing, "check_claims": tools.check_claims, "remediation_packet": tools.remediation_packet}.get(str(name))
            if handler is None:
                payload: Dict[str, Any] = {"error": f"unknown tool {name!r}"}
            else:
                payload = handler(args)
            event("tool_call", call=calls, tool=name, error=bool(payload.get("error")))
            results.append({"type": "tool_result", "tool_use_id": block.get("id"), "content": json.dumps(payload), "is_error": bool(payload.get("error"))})
        messages.append({"role": "user", "content": results})


# --------------------------------------------------------------------------
# CLI glue
# --------------------------------------------------------------------------


def load_trace(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("events"), list):
        raise ValueError("trace file must be an object with an events list")
    return data


def render_trace(outcome: AgentOutcome) -> str:
    lines = [f"Analyst agent ({outcome.trace.get('transport')}, model {outcome.trace.get('model') or 'n/a'}): mode={outcome.mode}, {outcome.reason}"]
    lines.append(f"caps: {outcome.trace.get('caps')}")
    for ev in outcome.trace.get("events", []):
        kind = ev["type"]
        if kind == "response":
            texts = [b.get("text") for b in ev["response"].get("content", []) if b.get("type") == "text"]
            calls = [b.get("name") for b in ev["response"].get("content", []) if b.get("type") == "tool_use"]
            lines.append(f"  [{ev['t']:6.2f}s] call {ev['call']}: model said {texts[0][:90] + '...' if texts and len(texts[0]) > 90 else (texts[0] if texts else '(no text)')!r}; tools {calls}; tokens so far {ev['tokens_so_far']}")
        elif kind == "gate":
            verdict = "ACCEPTED" if ev["accepted"] else "REJECTED"
            lines.append(f"  [{ev['t']:6.2f}s] gate: {verdict}" + ("" if ev["accepted"] else f" -> {[(r.get('code'), r.get('detail')) for r in ev['reasons']][:3]}"))
        elif kind == "tool_call":
            lines.append(f"  [{ev['t']:6.2f}s] tool {ev['tool']}" + (" (error)" if ev.get("error") else ""))
        elif kind == "abort":
            lines.append(f"  [{ev['t']:6.2f}s] abort: {ev['reason']}")
        elif kind == "final":
            lines.append(f"  [{ev['t']:6.2f}s] final: {ev.get('mode')}" + (f" items={ev.get('items')} angle={ev.get('angle')} break_in={ev.get('break_in')}" if ev.get("mode") == "analyst" else ""))
    lines.append(f"calls {outcome.calls}, tokens {outcome.tokens}, retries {outcome.retries}, {outcome.elapsed:.2f}s")
    return "\n".join(lines)


def run_agent_cli(args: Any) -> int:
    episode = run_episode(args.current, None if getattr(args, "no_previous", False) else args.previous, data_dir=args.data_dir, synthetic_note=not getattr(args, "no_synthetic_note", False))
    if args.replay:
        transport: Transport = ReplayTransport(load_trace(args.replay))
    elif args.scripted:
        transport = ScriptedTransport()
    else:
        try:
            transport = AnthropicTransport(model=args.model or DEFAULT_MODEL)
        except TransportError as exc:
            print(f"agent unavailable: {exc}", file=__import__("sys").stderr)
            return 2
    outcome = run_agent(episode, transport)
    print(render_trace(outcome))
    print()
    print("Edition that airs:")
    for sentence in outcome.sentences:
        print("  " + sentence)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "trace.json"), "w", encoding="utf-8") as handle:
        json.dump(outcome.trace, handle, indent=2)
        handle.write("\n")
    with open(os.path.join(args.out, "decision.json"), "w", encoding="utf-8") as handle:
        json.dump({"mode": outcome.mode, "reason": outcome.reason, "items": outcome.items, "angle": outcome.angle, "break_in": outcome.break_in, "calls": outcome.calls, "tokens": outcome.tokens, "retries": outcome.retries, "receipt": outcome.gate.receipt.to_dict()}, handle, indent=2)
        handle.write("\n")
    with open(os.path.join(args.out, "briefing.txt"), "w", encoding="utf-8") as handle:
        handle.write("\n".join(outcome.sentences) + "\n")
    if args.record:
        with open(args.record, "w", encoding="utf-8") as handle:
            json.dump(outcome.trace, handle, indent=2)
            handle.write("\n")
        print(f"trace recorded to {args.record}")
    write_outputs(episode, os.path.join(args.out, "template_edition"))
    return 0 if outcome.gate.passed else 1
