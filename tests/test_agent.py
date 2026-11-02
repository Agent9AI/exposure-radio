import json
import os
import unittest
from unittest import mock

from exposure_radio import agent as agent_mod
from exposure_radio.gate import run_gate
from tests.common import ROOT, demo_episode

TRACE = os.path.join(ROOT, "data", "replay", "analyst_trace.json")


class ScriptedAndReplayTests(unittest.TestCase):
    def test_scripted_run_is_rejected_once_then_accepted(self):
        episode = demo_episode()
        outcome = agent_mod.run_agent(episode, agent_mod.ScriptedTransport())
        self.assertEqual(outcome.mode, "analyst")
        self.assertEqual(outcome.retries, 1)
        self.assertEqual(outcome.calls, 3)
        gates = [e for e in outcome.trace["events"] if e["type"] == "gate"]
        self.assertEqual([g["accepted"] for g in gates], [False, True])
        self.assertEqual(gates[0]["reasons"][0]["code"], "VALUE_MISMATCH")
        self.assertEqual(outcome.items[0], "CVE-2026-110447")
        self.assertTrue(outcome.break_in)
        self.assertTrue(outcome.gate.passed)
        self.assertIn("CVE-2026-110447 was first seen in this estate on 27 October 2026.", outcome.sentences)
        # The airing script is re-checkable by anyone with the ledger.
        self.assertTrue(run_gate(outcome.segments, episode.facts, episode.forbidden).passed)
        self.assertGreater(outcome.tokens, 0)

    def test_committed_trace_replays_through_a_live_gate(self):
        episode = demo_episode()
        trace = agent_mod.load_trace(TRACE)
        self.assertEqual(trace["transport"], "scripted")
        outcome = agent_mod.run_agent(episode, agent_mod.ReplayTransport(trace))
        self.assertEqual(outcome.mode, "analyst")
        self.assertEqual(outcome.retries, 1)
        self.assertEqual(outcome.trace["transport"], "replay")

    def test_replay_exhaustion_falls_back_to_template(self):
        episode = demo_episode()
        trace = agent_mod.load_trace(TRACE)
        trace["events"] = [e for e in trace["events"] if e["type"] == "response"][:1]
        outcome = agent_mod.run_agent(episode, agent_mod.ReplayTransport(trace))
        self.assertEqual(outcome.mode, "template")
        self.assertIn("no more recorded responses", outcome.reason)
        self.assertEqual(outcome.sentences, episode.sentences)


class CapTests(unittest.TestCase):
    def test_call_cap(self):
        outcome = agent_mod.run_agent(demo_episode(), agent_mod.ScriptedTransport(), max_calls=2)
        self.assertEqual(outcome.mode, "template")
        self.assertIn("call cap", outcome.reason)

    def test_token_cap(self):
        outcome = agent_mod.run_agent(demo_episode(), agent_mod.ScriptedTransport(), max_tokens=2000)
        self.assertEqual(outcome.mode, "template")
        self.assertIn("token cap", outcome.reason)

    def test_retry_cap(self):
        outcome = agent_mod.run_agent(demo_episode(), agent_mod.ScriptedTransport(), max_retries=0)
        self.assertEqual(outcome.mode, "template")
        self.assertIn("rejected", outcome.reason)

    def test_wall_clock_cap(self):
        outcome = agent_mod.run_agent(demo_episode(), agent_mod.ScriptedTransport(), max_seconds=0.0)
        self.assertEqual(outcome.mode, "template")
        self.assertIn("wall-clock", outcome.reason)


class _FakeResponse:
    def __init__(self, data):
        self._data = data

    def to_dict(self):
        return self._data


class _FakeClient:
    """Stands in for anthropic.Anthropic(): records requests, plays canned responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.beta = self
        self.messages = self

    def create(self, **kwargs):
        self.requests.append(kwargs)
        if isinstance(self.responses[0], Exception):
            raise self.responses.pop(0)
        return _FakeResponse(self.responses.pop(0))


class AnthropicTransportTests(unittest.TestCase):
    def test_requests_follow_the_current_api_shape(self):
        scripted = agent_mod.ScriptedTransport()
        episode = demo_episode()
        # Drive the scripted stand-in through the SDK-shaped transport so request construction is exercised.
        canned = []
        messages = [{"role": "user", "content": "x"}]
        canned.append(scripted.complete("", messages, []))
        fake = _FakeClient(canned + [{"stop_reason": "end_turn", "content": [{"type": "text", "text": "done"}], "usage": {"input_tokens": 1, "output_tokens": 1}}] * 3)
        transport = agent_mod.AnthropicTransport(model="claude-opus-5-5", client=fake)
        outcome = agent_mod.run_agent(episode, transport)
        request = fake.requests[0]
        self.assertEqual(request["model"], "claude-opus-5-5")
        self.assertNotIn("tool_choice", request)
        self.assertNotIn("thinking", request)
        self.assertEqual(request["fallbacks"], "default")
        self.assertIn("server-side-fallback-2026-07-01", request["betas"])
        self.assertTrue(all(t.get("strict") for t in request["tools"]))
        self.assertEqual({t["name"] for t in request["tools"]}, {"exposure_briefing", "check_claims", "remediation_packet", "propose_edition"})
        self.assertEqual(outcome.mode, "template")  # the canned end_turn never proposed an edition
        self.assertIn("without calling propose_edition", outcome.reason)

    def test_refusal_and_errors_fall_back_to_template(self):
        episode = demo_episode()
        fake = _FakeClient([{"stop_reason": "refusal", "content": [], "usage": {"input_tokens": 5, "output_tokens": 0}}])
        outcome = agent_mod.run_agent(episode, agent_mod.AnthropicTransport(client=fake))
        self.assertEqual(outcome.mode, "template")
        self.assertIn("declined", outcome.reason)
        fake = _FakeClient([RuntimeError("boom")])
        outcome = agent_mod.run_agent(episode, agent_mod.AnthropicTransport(client=fake))
        self.assertEqual(outcome.mode, "template")
        self.assertIn("model call failed", outcome.reason)

    def test_missing_key_is_a_clean_transport_error(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "", "ANTHROPIC_AUTH_TOKEN": ""}):
            with self.assertRaises(agent_mod.TransportError):
                agent_mod.AnthropicTransport()


class ProposalTests(unittest.TestCase):
    def test_unknown_item_and_bad_template_are_rejected(self):
        episode = demo_episode()
        with self.assertRaises(Exception):
            agent_mod._proposal_segments(episode, {"items": ["CVE-2031-99999"], "angle_template": "", "angle_claims": []})
        with self.assertRaises(Exception):
            agent_mod._proposal_segments(episode, {"items": ["CVE-2024-3400"], "angle_template": "intro.held", "angle_claims": []})
        with self.assertRaises(Exception):
            agent_mod._proposal_segments(episode, {"items": ["CVE-2023-4966"], "angle_template": "", "angle_claims": []})  # closed/unverified, nothing open

    def test_tools_expose_redacted_evidence_only(self):
        episode = demo_episode()
        tools = agent_mod.RedactedTools(episode)
        briefing = json.dumps(tools.exposure_briefing({}))
        self.assertNotIn("northwind", briefing)
        self.assertNotIn("10.20.", briefing)
        self.assertNotIn("evidence\"", briefing)
        packet = json.dumps(tools.remediation_packet({"cve": "CVE-2024-3400"}))
        self.assertNotIn("northwind", packet)
        self.assertIn("identifiers withheld", packet)
        self.assertIn("error", tools.check_claims({"claims": "nope"}))


if __name__ == "__main__":
    unittest.main()
