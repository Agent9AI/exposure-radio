"""Boundary checks for model authority, failover and stdio access."""
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from exposure_radio.analyst import (AnthropicBackend, CommandBackend, Limits, Step, Tools, _check_submission,
                                    run_analyst)
from exposure_radio.mcp_server import ToolError, _dir, call_tool, handle, serve
from exposure_radio.pipeline import DEMO_CURR, run_cycle
from exposure_radio.policy import ranked


class Backend:
    model = "test"
    def __init__(self, steps):
        self.steps = iter(steps)
        self.results = []
    def start(self, user):
        pass
    def step(self, limits):
        return next(self.steps)
    def result(self, step, payload, is_error=False):
        self.results.append(payload)


class AnalystChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.c = run_cycle(commit=False)
        cls.candidates = [r.cve for r in ranked(cls.c.delta)][:8]
        cls.lead = cls.c.decision.lead
        cls.fact = cls.c.ledger.find(cls.lead, "cve.open_assets")

    def submission(self, **changes):
        result = {"order": [self.lead], "angle": "persisting_risk", "lead_claims": [{
            "subject": self.lead, "predicate": self.fact.predicate,
            "value": self.fact.value, "cite": self.fact.id}]}
        result.update(changes)
        return result

    def run_backend(self, backend, **limits):
        return run_analyst(self.c.ledger, self.c.decision, self.c.delta, backend, Limits(**limits))

    def test_valid_tools_then_submission(self):
        b = Backend([Step("list_candidates", {}), Step("submit_rundown", self.submission())])
        out = self.run_backend(b)
        self.assertEqual(out.source, "analyst")
        self.assertEqual(out.trace["calls"], 2)

    def test_unread_citation_rejected(self):
        b = Backend([Step("submit_rundown", self.submission())])
        self.assertEqual(self.run_backend(b, revisions=0).source, "deterministic")

    def test_missing_citation_rejected(self):
        data = self.submission()
        data["lead_claims"][0].pop("cite")
        self.assertFalse(_check_submission(data, self.c.ledger, self.candidates)["ok"])

    def test_unknown_tool_never_executes(self):
        out = self.run_backend(Backend([Step("shell", {"command": "do things"})]))
        self.assertEqual(out.source, "deterministic")
        self.assertEqual(out.trace["failed"], "ValueError")

    def test_unknown_lead_and_unjustified_angle_rejected(self):
        for data in [self.submission(order=["CVE-1900-0000"]),
                     self.submission(angle="coverage_gap"), self.submission(order="bad"),
                     self.submission(lead_claims={"bad": "shape"})]:
            self.assertFalse(_check_submission(data, self.c.ledger, self.candidates)["ok"])

    def test_failing_start_falls_back(self):
        b = Backend([])
        def broken(_):
            raise RuntimeError("unavailable")
        b.start = broken
        self.assertEqual(self.run_backend(b).source, "deterministic")

    def test_model_call_and_tool_budgets(self):
        for limits in [{"max_model_calls": 1}, {"max_tool_calls": 0}]:
            out = self.run_backend(Backend([Step("list_candidates", {})] * 6), **limits)
            self.assertEqual(out.source, "deterministic")
            self.assertIn("cap", out.trace["failed"])

    def test_late_result_discarded(self):
        b = Backend([Step("list_candidates", {})])
        ticks = iter([0, 0, 0, 0, 100, 100])
        with patch("exposure_radio.analyst.time.monotonic", side_effect=lambda: next(ticks, 100)):
            out = self.run_backend(b, max_seconds=1)
        self.assertEqual(out.source, "deterministic")
        self.assertIn("time", out.trace["failed"])

    def test_hidden_fact_is_not_disclosed_by_validation(self):
        tools = Tools(self.c.ledger, self.c.decision, self.candidates)
        fact = next(f for f in self.c.ledger.facts if f.predicate == "cve.name" and
                    f.id not in {p["id"] for p in self.c.ledger.public_view()})
        raw = {"subject": fact.subject, "predicate": fact.predicate, "value": "probe", "cite": fact.id}
        for result in [tools.check_claims([raw]), call_tool("check_claims", {"claims": [raw]}),
                       call_tool("check_claims", {"text": f"{fact.subject} is listed as probe."})]:
            self.assertNotIn(str(fact.value), json.dumps(result))

    def test_provider_exception_does_not_leak_into_card(self):
        b = Backend([])
        def broken(_):
            raise RuntimeError("vpn-gw-01 secret-provider-diagnostic")
        b.start = broken
        c = run_cycle(analyst=b, edition="executive", commit=False)
        self.assertNotIn("vpn-gw-01", json.dumps(c.episode.card))
        self.assertNotIn("secret-provider-diagnostic", json.dumps(c.rundown.trace))

    def test_command_stream_is_bounded(self):
        import sys
        backend = CommandBackend(f"{sys.executable} -c 'import sys; sys.stderr.write(chr(120)*1000000)'")
        backend.start("test")
        with self.assertRaises(RuntimeError):
            backend.step(Limits(max_output_tokens=64, max_seconds=3))

    def test_model_cannot_omit_policy_alerts(self):
        b = Backend([Step("list_candidates", {}), Step("submit_rundown", self.submission())])
        c = run_cycle(analyst=b, commit=False)
        spoken = " ".join(line["text"] for line in c.episode.lines)
        for alert in c.decision.fresh_alerts:
            self.assertIn(alert.cve, spoken)
        self.assertTrue(c.episode.gate.passed)

    def test_output_failure_leaves_alert_uncommitted(self):
        from exposure_radio.cli import main
        from exposure_radio.policy import Memory
        with tempfile.TemporaryDirectory() as d:
            state = str(Path(d) / "state.db")
            with patch("exposure_radio.cli._write_outputs", side_effect=OSError("disk unavailable")):
                with self.assertRaises(OSError):
                    main(["demo", "--state", state, "--out", str(Path(d) / "out")])
            memory = Memory(state)
            self.assertFalse(memory.seen_episode(self.c.decision.episode))
            self.assertEqual(memory.seen_assets(self.lead), set())
            memory.close()

    def test_count_before_generation(self):
        backend = AnthropicBackend(api_key="test-only")
        backend.start("test")
        with patch.object(backend, "_request", return_value={"input_tokens": 40_000}) as request:
            with self.assertRaises(RuntimeError):
                backend.step(Limits(max_total_tokens=100))
            self.assertEqual(request.call_count, 1)
            self.assertTrue(request.call_args.args[0].endswith("/count_tokens"))

    def test_generation_has_single_tool_and_reserved_budget(self):
        backend = AnthropicBackend(api_key="test-only")
        backend.start("test")
        response = {"content": [{"type": "tool_use", "name": "list_candidates", "input": {}, "id": "x"}],
                    "usage": {"input_tokens": 100, "output_tokens": 20}}
        with patch.object(backend, "_request", side_effect=[{"input_tokens": 100}, response]) as request:
            step = backend.step(Limits(max_total_tokens=400))
            body = request.call_args.args[1]
        self.assertEqual(body["max_tokens"], 44)
        self.assertTrue(body["tool_choice"]["disable_parallel_tool_use"])
        self.assertEqual(step.tool, "list_candidates")


class McpChecks(unittest.TestCase):
    def test_stdio_roundtrip(self):
        requests = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
                "name": "exposure_briefing", "arguments": {"edition": "executive"}}}]
        output = io.StringIO()
        serve(io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n"), output)
        results = [json.loads(l) for l in output.getvalue().splitlines()]
        self.assertEqual([r["id"] for r in results], [1, 2, 3])
        self.assertEqual(len(results[1]["result"]["tools"]), 4)
        self.assertTrue(results[2]["result"]["structuredContent"]["gate"]["passed"])

    def test_invalid_messages(self):
        for msg in [{"id": 1, "method": "ping"}, {"jsonrpc": "2.0", "id": True, "method": "ping"}]:
            self.assertEqual(handle(msg)["error"]["code"], -32600)
        self.assertEqual(handle({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": []})["error"]["code"], -32602)
        output = io.StringIO()
        serve(io.StringIO("[1,2]\nnot-json\n"), output)
        self.assertEqual(len(output.getvalue().splitlines()), 2)

    def test_large_message_rejected(self):
        output = io.StringIO()
        serve(io.StringIO("a" * 140000 + "\n"), output)
        self.assertIn("byte budget", output.getvalue())

    def test_external_directory_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d, patch.dict("os.environ", {"EXPOSURE_RADIO_DATA_ROOT": d}):
            with self.assertRaises(ToolError):
                _dir("/etc", DEMO_CURR)
            root = Path(d) / "test"
            root.mkdir()
            (root / "export-status.json").write_text("{}")
            (root / "chunk.json").symlink_to("/etc/passwd")
            with self.assertRaises(ToolError):
                _dir(str(root), DEMO_CURR)

    def test_no_truncation_or_missing_claim_cite(self):
        for args in [{"text": "a" * 4001}, {"claims": [{}]}, {"claims": [1] * 33}]:
            with self.assertRaises(ToolError):
                call_tool("check_claims", args)
        with self.assertRaises(ToolError):
            call_tool("remediation_packet", {"cve": "CVE-2024-3400", "edition": "bad"})


if __name__ == "__main__":
    unittest.main()
