"""Alert policy, memory, action card and redaction."""

import json
import tempfile
import unittest
from pathlib import Path

from exposure_radio.cli import main
from exposure_radio.pipeline import run_cycle
from exposure_radio.policy import Memory
from exposure_radio.rundown import RedactionError, build_card, card_markdown, find_leaks

from .helpers import DEMO_CURR, DEMO_PREV, TempCopy, demo_cycle, edit_json


class Policy(unittest.TestCase):
    def test_break_in_then_silent(self):
        memory = Memory()
        first = run_cycle(memory=memory)
        self.assertEqual(first.decision.kind, "BREAK_IN")
        self.assertEqual(first.decision.lead, "CVE-2026-118527")
        second = run_cycle(memory=memory)
        self.assertEqual(second.decision.kind, "SILENT")
        self.assertEqual(second.episode.lines, [])
        self.assertIsNone(second.decision.push_payload())

    def test_memory_survives_restart(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d, "state.sqlite3")
            run_cycle(memory=Memory(path))
            self.assertEqual(run_cycle(memory=Memory(path)).decision.kind, "SILENT")

    def test_no_duplicate_alert_on_new_episode_with_same_exposure(self):
        memory = Memory()
        run_cycle(memory=memory)
        with TempCopy() as snap:
            # A new export with the same findings: a different episode, same alert keys.
            edit_json(snap / "export-status.json", lambda s: s.update(uuid="another-export"))
            again = run_cycle(DEMO_PREV, snap, memory=memory)
            self.assertNotEqual(again.decision.kind, "BREAK_IN")
            self.assertTrue(all(a.duplicate for a in again.decision.alerts))

    def test_new_asset_on_alerted_cve_alerts_again(self):
        memory = Memory()
        run_cycle(memory=memory)
        with TempCopy() as snap:
            def spread(rows):
                extra = [r for r in rows if "CVE-2026-41709" in r["plugin"]["cve"]][0]
                twin = json.loads(json.dumps(extra))
                donor = [r for r in rows if r["asset"]["hostname"] == "esx-06"][0]["asset"]
                twin["asset"] = donor
                rows.append(twin)
            edit_json(snap / "vulns" / "chunk-1.json", spread)
            again = run_cycle(DEMO_PREV, snap, memory=memory)
            self.assertEqual(again.decision.kind, "BREAK_IN")
            self.assertEqual(again.decision.lead, "CVE-2026-41709")

    def test_failed_gate_does_not_commit_memory(self):
        memory = Memory()
        cycle = run_cycle(memory=memory, commit=False)
        self.assertFalse(memory.seen_episode(cycle.decision.episode))


class Card(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cycle = demo_cycle()

    def test_analyst_card_is_ticket_ready(self):
        card = self.cycle.episode.card
        lead = card["items"][0]
        self.assertEqual(lead["cve"], "CVE-2026-118527")
        self.assertEqual([a["asset"] for a in lead["assets"]], ["vpn-gw-01"])
        self.assertEqual(lead["owners"], ["network-team"])
        self.assertEqual(lead["internal_deadline"], "2026-11-06")
        self.assertTrue(lead["kev"]["required_action"])
        self.assertTrue(lead["next_steps"])
        md = card_markdown(card)
        self.assertIn("| vpn-gw-01 | network-team |", md)

    def test_unowned_asset_gets_an_assignment_step(self):
        items = build_card(self.cycle.delta, self.cycle.decision, self.cycle.ledger, self.cycle.kev,
                           limit=20)["items"]
        legacy = [i for i in items if i["cve"] == "CVE-2017-0144"][0]
        self.assertTrue(any("Assign an owner" in s for s in legacy["next_steps"]))

    def test_unverified_assets_are_labelled(self):
        items = build_card(self.cycle.delta, self.cycle.decision, self.cycle.ledger, self.cycle.kev,
                           limit=20)["items"]
        bluekeep = [i for i in items if i["cve"] == "CVE-2019-0708"][0]
        self.assertEqual({a["status"] for a in bluekeep["assets"]}, {"unverified (not rescanned)"})

    def test_executive_card_has_no_identifiers(self):
        c = self.cycle
        card = build_card(c.delta, c.decision, c.ledger, c.kev, "executive", limit=20)
        self.assertEqual(find_leaks(json.dumps(card), c.ledger), [])
        self.assertTrue(all("assets" not in i for i in card["items"]))

    def test_executive_card_fails_closed(self):
        with TempCopy() as snap:
            def poison(rows):
                for r in rows:
                    if "CVE-2026-53435" in r["plugin"]["cve"]:
                        r["plugin"]["name"] = "Jenkins flaw on app-07.corp.example"
            edit_json(snap / "vulns" / "chunk-1.json", poison)
            edit_json(snap / "vulns" / "chunk-2.json", poison)
            c = run_cycle(DEMO_PREV, snap, memory=Memory(), commit=False)
            card = build_card(c.delta, c.decision, c.ledger, c.kev, "executive", limit=20)
            self.assertEqual(find_leaks(json.dumps(card), c.ledger), [])

    def test_push_payload_is_generic(self):
        payload = self.cycle.decision.push_payload()
        self.assertEqual(set(payload), {"title", "body", "ref"})
        self.assertNotIn("CVE", json.dumps(payload))


class Cli(unittest.TestCase):
    def _run(self, *argv):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def test_demo(self):
        code, out = self._run("demo")
        self.assertEqual(code, 0)
        self.assertIn("Decision: BREAK_IN", out)
        self.assertIn("Decision: SILENT", out)

    def test_gate_demo_and_audit(self):
        self.assertEqual(self._run("gate-demo")[0], 0)
        self.assertEqual(self._run("audit")[0], 0)

    def test_check_text(self):
        code, out = self._run("check", "--text", "CVE-2024-3400 is fixed on 20 assets.")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["results"][0]["status"], "blocked")

    def test_brief_writes_outputs(self):
        with tempfile.TemporaryDirectory() as d:
            code, _ = self._run("brief", "--prev", str(DEMO_PREV), "--curr", str(DEMO_CURR),
                                "--state", str(Path(d, "s.sqlite3")), "--out", d)
            self.assertEqual(code, 0)
            episode = json.loads(Path(d, "episode.json").read_text())
            self.assertTrue(episode["gate"]["passed"])
            self.assertNotIn("affected_hosts", json.dumps(episode["ledger"]))


if __name__ == "__main__":
    unittest.main()
