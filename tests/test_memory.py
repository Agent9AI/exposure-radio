import unittest

from exposure_radio.memory import Memory
from exposure_radio.model import AssetPluginFinding


def apf(asset, plugin, state="OPEN", sev=4):
    return AssetPluginFinding(asset, plugin, "p", sev, (), ("0/tcp",), state, None, None, None, None, None, None, ())


class MemoryTests(unittest.TestCase):
    def memory(self):
        memory = Memory(":memory:")
        self.addCleanup(memory.close)
        return memory

    def test_record_and_read_back(self):
        memory = self.memory()
        findings = [apf("a", 1), apf("b", 2, sev=3), apf("c", 3, state="FIXED")]
        primary = {("a", 1): "CVE-2024-3400", ("b", 2): "CVE-2024-6387", ("c", 3): "CVE-2025-53770"}
        kev = frozenset({"CVE-2024-3400", "CVE-2025-53770"})
        episode_id = memory.record_episode("2026-10-20", "previous", ["a", "b", "c"], findings, primary, kev, False, "v1", {"x": 1})
        record = memory.episodes()[0]
        self.assertEqual(record.episode_id, episode_id)
        self.assertEqual(record.asset_count, 3)
        self.assertEqual(record.open_critical, 1)
        self.assertEqual(record.open_high, 1)
        self.assertEqual(record.kev_open_cves, 1)  # the FIXED SharePoint finding does not count
        self.assertEqual(record.summary, {"x": 1})
        self.assertEqual(memory.assets_of(episode_id), {"a", "b", "c"})
        self.assertEqual(memory.kev_cves_of(episode_id), {"CVE-2024-3400"})

    def test_previous_episode_and_trend(self):
        memory = self.memory()
        memory.record_episode("2026-10-13", "e1", ["a"], [apf("a", 1)], {("a", 1): None}, frozenset(), False, "v1")
        memory.record_episode("2026-10-20", "e2", ["a", "b"], [apf("a", 1), apf("b", 1)], {}, frozenset(), True, "v1")
        previous = memory.previous_episode("2026-10-27")
        self.assertIsNotNone(previous)
        self.assertEqual(previous.episode_date, "2026-10-20")
        self.assertTrue(previous.held)
        self.assertEqual(memory.previous_episode("2026-10-13"), None)
        trend = memory.trend()
        self.assertEqual([t["episode_date"] for t in trend], ["2026-10-13", "2026-10-20"])
        self.assertEqual(trend[1]["open_critical"], 2)

    def test_memory_stores_no_hostnames(self):
        memory = self.memory()
        memory.record_episode("2026-10-20", "p", ["uuid-1"], [apf("uuid-1", 1)], {}, frozenset(), False, "v1")
        rows = memory.conn.execute("SELECT * FROM episode_assets").fetchall()
        self.assertEqual(rows, [(1, "uuid-1")])
        columns = [r[1] for r in memory.conn.execute("PRAGMA table_info(episode_findings)").fetchall()]
        for forbidden in ("hostname", "fqdn", "ip", "output", "name"):
            self.assertNotIn(forbidden, columns)


if __name__ == "__main__":
    unittest.main()
