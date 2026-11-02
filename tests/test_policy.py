import os
import tempfile
import unittest

from exposure_radio import policy
from exposure_radio.facts import FactStore
from exposure_radio.memory import Memory
from exposure_radio.model import AssetPluginFinding
from exposure_radio.pipeline import run_episode
from tests.common import CURRENT, PREVIOUS, demo_episode, first_episode, held_episode


def apf(asset, plugin, sev=4, state="OPEN"):
    return AssetPluginFinding(asset, plugin, "p", sev, (), ("443/tcp",), state, None, None, None, None, None, None, ())


class DemoDecisionTests(unittest.TestCase):
    def test_demo_breaks_in_on_the_new_kev_entry(self):
        episode = demo_episode()
        decision = episode.decision
        self.assertEqual(decision.kind, policy.BREAK_IN)
        self.assertEqual(decision.lead, "CVE-2026-110447")
        self.assertTrue(any("newly listed by CISA" in r for r in decision.reasons))
        self.assertTrue(any("not rescanned" in h for h in decision.health))
        self.assertEqual([a.cve for a in decision.fresh_alerts], ["CVE-2026-110447"])
        self.assertEqual(episode.facts.value("episode", "decision"), "BREAK_IN")
        self.assertIn("This is a break-in bulletin: a KEV-listed exposure is new since the previous export.", episode.sentences)
        self.assertEqual(len(decision.fingerprint), 64)

    def test_first_episode_is_a_break_in_on_visibility(self):
        decision = first_episode().decision
        self.assertEqual(decision.kind, policy.BREAK_IN)
        self.assertTrue(all("new to the scan" in r for r in decision.reasons))

    def test_held_episode_keeps_health_notes(self):
        decision = held_episode().decision
        self.assertIn("export incomplete: nothing counts as fixed", decision.health)

    def test_rerun_with_persistent_memory_is_silent(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "memory.sqlite3")
            memory = Memory(path)
            first = run_episode(CURRENT, PREVIOUS, memory=memory)
            memory.close()
            memory = Memory(path)
            second = run_episode(CURRENT, PREVIOUS, memory=memory)
            memory.close()
        self.assertEqual(first.decision.kind, policy.BREAK_IN)
        self.assertEqual(second.decision.kind, policy.SILENT)
        self.assertEqual(second.decision.previously_briefed, "2026-10-27")
        self.assertTrue(second.alert["suppressed"])
        self.assertEqual(second.alert["body"], "")
        self.assertTrue(all(a.duplicate_of for a in second.decision.alerts))
        # The narration itself is still produced and gated; only the interruption is withheld.
        self.assertTrue(second.gate.passed)
        self.assertNotIn("break-in bulletin", "\n".join(second.sentences))
        # Re-running replaces the episode records instead of duplicating them.
        self.assertEqual([t["episode_date"] for t in second.memory_trend], ["2026-10-20", "2026-10-27"])


class RuleTests(unittest.TestCase):
    def store(self, **episode_values):
        store = FactStore()
        store.add("episode", "assets_not_rescanned", episode_values.get("missed", 0), "delta:x")
        store.add("priority", "lead_cve", "CVE-2024-6387", "delta:x")
        for cve, values in episode_values.get("cves", {}).items():
            for predicate, value in values.items():
                store.add(f"cve:{cve}", predicate, value, "export:current")
        return store

    def test_scheduled_when_nothing_new_and_coverage_complete(self):
        store = self.store(cves={"CVE-2024-6387": {"severity": "high", "open_asset_count": 2}})
        memory = Memory(":memory:")
        self.addCleanup(memory.close)
        decision = policy.decide(store, [apf("a", 1, sev=3)], {("a", 1): "CVE-2024-6387"}, frozenset(), memory, "2026-10-27", False)
        self.assertEqual(decision.kind, policy.SCHEDULED)
        self.assertEqual(decision.lead, "CVE-2024-6387")

    def test_health_when_assets_missed(self):
        store = self.store(missed=4, cves={"CVE-2024-6387": {"severity": "high", "open_asset_count": 2}})
        memory = Memory(":memory:")
        self.addCleanup(memory.close)
        decision = policy.decide(store, [apf("a", 1, sev=3)], {("a", 1): "CVE-2024-6387"}, frozenset(), memory, "2026-10-27", False)
        self.assertEqual(decision.kind, policy.HEALTH)
        self.assertEqual(decision.health, ["4 previously scanned asset(s) were not rescanned"])

    def test_alert_key_changes_when_an_asset_joins(self):
        base = policy.alert_key("CVE-2024-3400", ["a", "b"])
        self.assertEqual(base, policy.alert_key("CVE-2024-3400", ["b", "a"]))
        self.assertNotEqual(base, policy.alert_key("CVE-2024-3400", ["a", "b", "c"]))

    def test_duplicate_alert_does_not_break_in_again(self):
        store = self.store(cves={"CVE-2024-3400": {"severity": "critical", "open_asset_count": 1, "kev_listed": True, "new_exposure_count": 1}})
        memory = Memory(":memory:")
        self.addCleanup(memory.close)
        kev = frozenset({"CVE-2024-3400"})
        first = policy.decide(store, [apf("a", 1)], {("a", 1): "CVE-2024-3400"}, kev, memory, "2026-10-27", False)
        self.assertEqual(first.kind, policy.BREAK_IN)
        # Same alert key, different overall evidence (a low finding appeared): no second interruption.
        second = policy.decide(store, [apf("a", 1), apf("a", 2, sev=1)], {("a", 1): "CVE-2024-3400"}, kev, memory, "2026-10-28", False)
        self.assertEqual(second.kind, policy.SCHEDULED)
        self.assertEqual(second.alerts[0].duplicate_of, "2026-10-27")


if __name__ == "__main__":
    unittest.main()
