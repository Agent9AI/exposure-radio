import io
import json
import os
import unittest
from contextlib import redirect_stderr
from unittest import mock

from exposure_radio import mcp_server
from tests.common import CURRENT, FIX, PREVIOUS


def rpc(server, method, params=None, msg_id=1):
    return server.handle({"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}})


class McpServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = mcp_server.Server(default_current=CURRENT, default_previous=PREVIOUS)

    def test_initialize_and_tools_list(self):
        response = rpc(self.server, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}})
        self.assertEqual(response["result"]["protocolVersion"], "2025-03-26")
        self.assertEqual(response["result"]["serverInfo"]["name"], "exposure-radio")
        response = rpc(self.server, "initialize", {"protocolVersion": "1999-01-01"})
        self.assertEqual(response["result"]["protocolVersion"], mcp_server.PROTOCOL_VERSIONS[0])
        self.assertIsNone(rpc(self.server, "notifications/initialized"))
        tools = rpc(self.server, "tools/list")["result"]["tools"]
        self.assertEqual([t["name"] for t in tools], ["exposure_briefing", "check_claims", "remediation_packet"])
        for tool in tools:
            self.assertTrue(tool["annotations"]["readOnlyHint"])
            self.assertFalse(tool["annotations"]["destructiveHint"])
        self.assertEqual(rpc(self.server, "ping")["result"], {})

    def test_exposure_briefing_tool(self):
        response = rpc(self.server, "tools/call", {"name": "exposure_briefing", "arguments": {"edition": "ciso"}})
        result = response["result"]
        self.assertFalse(result["isError"])
        payload = result["structuredContent"]
        self.assertTrue(payload["passed"])
        self.assertEqual(payload["edition"], "ciso")
        self.assertGreater(len(payload["sentences"]), 20)
        self.assertNotIn("northwind", json.dumps(payload))
        self.assertEqual(json.loads(result["content"][0]["text"])["receipt"]["passed"], True)

    def test_check_claims_tool(self):
        briefing = rpc(self.server, "tools/call", {"name": "exposure_briefing", "arguments": {}})["result"]["structuredContent"]
        cite = briefing["sentences"][2]["cites"][0]
        good = {"subject": cite["subject"], "predicate": cite["predicate"], "value": cite["value"], "cite": cite["fact"]}
        bad = dict(good, value="never")
        response = rpc(self.server, "tools/call", {"name": "check_claims", "arguments": {"claims": [good, bad]}})
        payload = response["result"]["structuredContent"]
        self.assertEqual(len(payload["accepted"]), 1)
        self.assertEqual(payload["rejected"][0]["code"], "VALUE_MISMATCH")

    def test_check_claims_rejects_oversized_or_malformed_input(self):
        response = rpc(self.server, "tools/call", {"name": "check_claims", "arguments": {"claims": "nope"}})
        self.assertTrue(response["result"]["isError"])
        response = rpc(self.server, "tools/call", {"name": "check_claims", "arguments": {"claims": [{"subject": 1}]}})
        self.assertTrue(response["result"]["isError"])

    def test_remediation_packet_tool(self):
        response = rpc(self.server, "tools/call", {"name": "remediation_packet", "arguments": {"cve": "cve-2024-3400", "edition": "ciso"}})
        payload = response["result"]["structuredContent"]
        self.assertEqual([i["cve"] for i in payload["items"]], ["CVE-2024-3400"])
        self.assertEqual(payload["items"][0]["assets"], [])
        self.assertIn("ticket_markdown", payload["items"][0])

    def test_path_restrictions(self):
        response = rpc(self.server, "tools/call", {"name": "exposure_briefing", "arguments": {"current": "/etc/passwd"}})
        self.assertTrue(response["result"]["isError"])
        self.assertIn("inside the working directory", response["result"]["content"][0]["text"])
        response = rpc(self.server, "tools/call", {"name": "exposure_briefing", "arguments": {"current": os.path.join(FIX, "missing.json")}})
        self.assertTrue(response["result"]["isError"])
        response = rpc(self.server, "tools/call", {"name": "exposure_briefing", "arguments": {"current": os.path.join(FIX, "current_with_dtd.nessus"), "previous": PREVIOUS}})
        self.assertTrue(response["result"]["isError"])
        self.assertIn("DOCTYPE", response["result"]["content"][0]["text"])

    def test_symlink_cannot_escape_the_roots(self):
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            link = os.path.join(tmp, "export.json")
            os.symlink(CURRENT, link)  # points at a real fixture outside this data directory
            server = mcp_server.Server(data_dir=tmp, default_current=CURRENT, default_previous=PREVIOUS)
            server.roots = (os.path.realpath(tmp),)  # only the temp data dir is allowed
            response = rpc(server, "tools/call", {"name": "exposure_briefing", "arguments": {"current": link, "previous": PREVIOUS}})
            self.assertTrue(response["result"]["isError"])
            self.assertIn("inside the working directory", response["result"]["content"][0]["text"])

    def test_protocol_errors(self):
        self.assertEqual(rpc(self.server, "tools/call", {"name": "shell", "arguments": {}})["error"]["code"], -32602)
        self.assertEqual(rpc(self.server, "resources/list")["error"]["code"], -32601)
        self.assertEqual(self.server.handle({"id": 1, "method": "ping"})["error"]["code"], -32600)
        self.assertEqual(rpc(self.server, "tools/call", "bad")["error"]["code"], -32602)

    def test_stdio_loop(self):
        lines = [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}}),
            json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            "not json",
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        ]
        stdin = io.BytesIO(("\n".join(lines) + "\n").encode())
        stdout = io.BytesIO()
        fake_in = mock.Mock(buffer=stdin)
        fake_out = mock.Mock(buffer=stdout)
        with mock.patch.object(mcp_server.sys, "stdin", fake_in), mock.patch.object(mcp_server.sys, "stdout", fake_out), redirect_stderr(io.StringIO()):
            code = mcp_server.serve_stdio(default_current=CURRENT, default_previous=PREVIOUS)
        self.assertEqual(code, 0)
        responses = [json.loads(line) for line in stdout.getvalue().decode().splitlines()]
        self.assertEqual([r.get("id") for r in responses], [1, None, 2])
        self.assertEqual(responses[1]["error"]["code"], -32700)
        self.assertEqual(len(responses[2]["result"]["tools"]), 3)


if __name__ == "__main__":
    unittest.main()
