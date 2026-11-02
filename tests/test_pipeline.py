import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from exposure_radio import cli
from exposure_radio.pipeline import run_episode, write_outputs
from tests.common import FIX, PREVIOUS, demo_episode, first_episode, held_episode


class PipelineTests(unittest.TestCase):
    def test_demo_episode_passes_and_speaks_the_week(self):
        episode = demo_episode()
        self.assertTrue(episode.gate.passed)
        text = "\n".join(episode.sentences)
        self.assertIn("16 critical findings were closed on rescanned assets", text)
        self.assertIn("1 CVE in your estate was added to the CISA KEV catalogue", text)
        self.assertIn("3 findings vanished from assets that were absent from this scan", text)
        self.assertIn("Lead item: CVE-2026-110447", text)
        self.assertNotIn("northwind", text)
        self.assertNotIn("10.20.", text)
        self.assertEqual(episode.sentences[0], "This is Exposure Radio.")
        self.assertEqual(episode.sentences[-1], "End of briefing.")
        self.assertTrue(all(not v for k, v in episode.pii_issues.items()), episode.pii_issues)

    def test_held_episode_withholds_closures(self):
        episode = held_episode()
        self.assertTrue(episode.held)
        self.assertTrue(episode.gate.passed)
        text = "\n".join(episode.sentences)
        self.assertIn("this edition is held", text)
        self.assertNotIn("were closed", text)
        self.assertNotIn("assets closed", text)
        self.assertTrue(any("chunks" in r for r in episode.hold_reasons))

    def test_first_episode_without_previous_export(self):
        episode = first_episode()
        self.assertTrue(episode.gate.passed)
        self.assertIsNone(episode.previous)
        text = "\n".join(episode.sentences)
        self.assertNotIn("Since the previous export", text)
        self.assertNotIn("rescanned", text)
        self.assertEqual(len(episode.memory_trend), 1)

    def test_transcript_cites_every_claim(self):
        episode = demo_episode()
        transcript = episode.transcript()
        self.assertEqual(len(transcript), len(episode.sentences))
        cited = sum(len(row["cites"]) for row in transcript)
        self.assertEqual(cited, episode.gate.receipt.claims_accepted)
        self.assertTrue(all(c["fact"].startswith("f") and c["source"] for row in transcript for c in row["cites"]))

    def test_memory_trend_records_both_episodes(self):
        trend = demo_episode().memory_trend
        self.assertEqual([t["episode_date"] for t in trend], ["2026-10-20", "2026-10-27"])
        self.assertEqual(trend[0]["open_critical"], 28)
        self.assertEqual(trend[1]["open_critical"], 11)

    def test_nessus_and_csv_inputs_produce_the_same_open_numbers(self):
        episode_nessus = run_episode(os.path.join(FIX, "current.nessus"), PREVIOUS)
        episode_csv = run_episode(os.path.join(FIX, "current.csv"), PREVIOUS)
        json_facts = demo_episode().facts
        for store in (episode_nessus.facts, episode_csv.facts):
            for predicate in ("asset_count", "open_critical_count", "open_high_count", "kev_open_cve_count"):
                self.assertEqual(store.value("episode", predicate), json_facts.value("episode", predicate), predicate)
            self.assertEqual(store.value("priority", "items"), json_facts.value("priority", "items"))

    def test_second_tenant_in_the_real_export_layout(self):
        tenant = os.path.join(FIX, "tenant-b")
        episode = run_episode(os.path.join(tenant, "2026-10-30"), os.path.join(tenant, "2026-10-29"))
        self.assertTrue(episode.gate.passed, episode.gate.receipt.rejections or episode.gate.receipt.issues)
        self.assertEqual(episode.facts.value("episode", "asset_count"), 65)  # 76 in inventory, 11 not scanned this cycle
        self.assertEqual(episode.facts.value("episode", "assets_newly_in_scope"), 12)
        self.assertEqual(episode.facts.value("episode", "assets_not_rescanned"), 11)
        self.assertGreater(episode.facts.value("delta", "unverified_open_count"), 0)  # stale rows on assets not rescanned
        self.assertIn("they stay open and unverified", "\n".join(episode.sentences))
        self.assertEqual(episode.decision.kind, "BREAK_IN")
        self.assertIn("CVE-2026-118527", episode.facts.value("delta", "kev_new_entries"))
        self.assertTrue(all(not v for k, v in episode.pii_issues.items()), episode.pii_issues)
        self.assertNotIn("corp.example", "\n".join(episode.sentences))

    def test_write_outputs(self):
        episode = demo_episode()
        with tempfile.TemporaryDirectory() as tmp:
            paths = write_outputs(episode, tmp)
            for name in ("briefing.txt", "transcript.json", "receipt.json", "packet_full.md", "packet_ciso.json", "alert.json", "ledger.json"):
                self.assertIn(name, paths)
                self.assertTrue(os.path.getsize(paths[name]) > 0)
            with open(paths["receipt.json"], encoding="utf-8") as handle:
                receipt = json.load(handle)
            self.assertTrue(receipt["passed"])
            with open(paths["briefing.txt"], encoding="utf-8") as handle:
                self.assertEqual(handle.read().strip().splitlines(), episode.sentences)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_demo_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = self.run_cli("demo", "--out", tmp)
            self.assertEqual(code, 0)
            self.assertIn("Gate receipt: PASS", out)
            self.assertIn("Lead item: CVE-2026-110447", out)
            self.assertIn("ACTION CARD", out)
            self.assertIn("Identifier audit: clean", out)
            self.assertTrue(os.path.exists(os.path.join(tmp, "receipt.json")))

    def test_gate_demo_command(self):
        code, out, _ = self.run_cli("gate-demo")
        self.assertEqual(code, 0)
        self.assertIn("planted cases blocked", out)
        self.assertNotIn("MISSED", out)

    def test_audit_command(self):
        code, out, _ = self.run_cli("audit")
        self.assertEqual(code, 0)
        self.assertIn("ciso_packet      clean", out)
        self.assertIn("alert            clean", out)

    def test_packet_command_filters_by_cve(self):
        code, out, _ = self.run_cli("packet", "--cve", "CVE-2024-3400", "--edition", "ciso")
        self.assertEqual(code, 0)
        self.assertIn("Patch CVE-2024-3400", out)
        self.assertNotIn("northwind", out)
        code, _, err = self.run_cli("packet", "--cve", "CVE-1999-0001")
        self.assertEqual(code, 2)

    def test_briefing_json_and_check_claims(self):
        code, out, _ = self.run_cli("briefing", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertTrue(data["passed"])
        cite = data["sentences"][2]["cites"][0]
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "claims.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump([
                    {"subject": cite["subject"], "predicate": cite["predicate"], "value": cite["value"], "cite": cite["fact"]},
                    {"subject": cite["subject"], "predicate": cite["predicate"], "value": "2031-01-01", "cite": cite["fact"]},
                ], handle)
            code, out, _ = self.run_cli("check-claims", path)
            self.assertEqual(code, 1)
            result = json.loads(out)
            self.assertEqual(len(result["accepted"]), 1)
            self.assertEqual(result["rejected"][0]["code"], "VALUE_MISMATCH")

    def test_missing_export_is_a_clean_error(self):
        code, _, err = self.run_cli("briefing", "--current", "/nonexistent.json")
        self.assertEqual(code, 2)
        self.assertIn("export error", err)

    def test_feeds_status(self):
        code, out, _ = self.run_cli("feeds", "status")
        self.assertEqual(code, 0)
        self.assertIn("KEV: 1766 entries, version 2026.10.30", out)
        self.assertIn("EPSS: 19 scores, score date 2026-10-30", out)
        self.assertIn("kev:2026.10.30: full", out)


if __name__ == "__main__":
    unittest.main()
