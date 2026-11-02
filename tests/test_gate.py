import json
import unittest

from exposure_radio import gate as gate_mod
from exposure_radio import gate_demo
from exposure_radio.claims import Claim, claim_from_fact
from exposure_radio.facts import FactStore
from exposure_radio.templates import Segment
from tests.common import demo_episode


def small_store():
    store = FactStore()
    store.add("episode", "export_date", "2026-10-27", "export:current")
    store.add("episode", "asset_count", 51, "export:current")
    store.add("episode", "finding_count", 53, "export:current")
    store.add("cve:CVE-2024-3400", "open_asset_count", 2, "export:current")
    return store


class GateTests(unittest.TestCase):
    def test_clean_segments_pass_and_receipt_covers_script(self):
        store = small_store()
        segments = [
            Segment("intro.station"),
            Segment("episode.date", (claim_from_fact(store.get("episode", "export_date")),)),
            Segment("episode.scope", (claim_from_fact(store.get("episode", "asset_count")), claim_from_fact(store.get("episode", "finding_count")))),
            Segment("outro.end"),
        ]
        result = gate_mod.run_gate(segments, store, None, now="2026-11-02T00:00:00Z")
        self.assertTrue(result.passed)
        self.assertEqual(result.receipt.claims_total, 3)
        self.assertEqual(result.receipt.claims_accepted, 3)
        self.assertEqual(result.receipt.sentence_count, 4)
        self.assertTrue(result.receipt.covers(result.sentences))
        self.assertFalse(result.receipt.covers(result.sentences[:-1]))
        self.assertEqual(result.receipt.sources, ["export:current"])
        self.assertIn("episode.scope", result.receipt.templates_used)
        self.assertEqual(result.receipt.generated_at, "2026-11-02T00:00:00Z")

    def test_one_bad_claim_fails_the_whole_edition(self):
        store = small_store()
        segments = [
            Segment("intro.station"),
            Segment("episode.date", (Claim("episode", "export_date", "2026-10-28", store.get("episode", "export_date").fact_id),)),
        ]
        result = gate_mod.run_gate(segments, store)
        self.assertFalse(result.passed)
        self.assertEqual(len(result.receipt.rejections), 1)
        self.assertEqual(result.receipt.rejections[0]["reasons"][0]["code"], "VALUE_MISMATCH")
        self.assertFalse(result.receipt.checks["claims_validated"])
        self.assertEqual(result.sentences, ["This is Exposure Radio."])  # what would have aired, for the record

    def test_template_error_is_reported(self):
        store = small_store()
        segments = [Segment("intro.station", (claim_from_fact(store.get("episode", "export_date")),))]
        result = gate_mod.run_gate(segments, store)
        self.assertFalse(result.passed)
        self.assertEqual(result.receipt.rejections[0]["reasons"][0]["code"], "TEMPLATE")

    def test_receipt_round_trip(self):
        store = small_store()
        result = gate_mod.run_gate([Segment("intro.station")], store)
        data = json.loads(result.receipt.to_json())
        back = gate_mod.GateReceipt.from_dict(data)
        self.assertEqual(back.script_sha256, result.receipt.script_sha256)
        self.assertTrue(back.covers(result.sentences))

    def test_empty_script_fails(self):
        result = gate_mod.run_gate([], small_store())
        self.assertFalse(result.passed)
        self.assertFalse(result.receipt.checks["nonempty"])


class GateDemoTests(unittest.TestCase):
    def test_every_planted_case_is_blocked_and_clean_briefing_passes(self):
        episode = demo_episode()
        ok, cases = gate_demo.run(episode)
        self.assertTrue(episode.gate.passed)
        names = {c.name for c in cases}
        for required in (
            "wrong_relation",
            "negation_claim",
            "negation_text",
            "number_words",
            "all_clear",
            "uncited_directive",
            "unknown_cve_claim",
            "unknown_cve_text",
            "hostname_leak",
            "plugin_output_injection",
            "ciso_edition_leak",
        ):
            self.assertIn(required, names)
        for case in cases:
            self.assertTrue(case.ok, f"{case.name} was not blocked: {case.codes}")
        self.assertTrue(ok)
        table = gate_demo.render_table(episode, cases)
        self.assertIn(f"{len(cases)}/{len(cases)} planted cases blocked", table)

    def test_injection_never_reaches_facts_or_script(self):
        episode = demo_episode()
        blob = json.dumps(episode.facts.to_list()) + "\n".join(episode.sentences) + json.dumps(episode.packet_full)
        self.assertNotIn(gate_demo.INJECTION_MARKER, blob)
        self.assertNotIn("hunter2", blob)
        self.assertGreater(episode.current.text_fields_discarded, 100)


if __name__ == "__main__":
    unittest.main()
