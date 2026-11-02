import unittest

from exposure_radio import delta as d
from exposure_radio.evidence import Coverage
from exposure_radio.model import AssetPluginFinding


def apf(asset, plugin, state="OPEN", sev=4, cves=("CVE-2024-38063",)):
    return AssetPluginFinding(
        asset_id=asset,
        plugin_id=plugin,
        plugin_name="p",
        severity=sev,
        cves=tuple(cves),
        ports=("0/tcp",),
        state=state,
        first_found=None,
        last_found=None,
        cvss3=None,
        vpr=None,
        exploit_available=None,
        has_patch=None,
        record_refs=(),
    )


class ClassificationTests(unittest.TestCase):
    def setUp(self):
        self.cov = Coverage(previous=frozenset({"a", "b", "c", "d"}), current=frozenset({"a", "b", "c", "e"}))

    def test_matrix(self):
        previous = [apf("a", 1), apf("b", 1), apf("c", 1), apf("d", 1), apf("a", 2, state="FIXED")]
        current = [apf("a", 1), apf("b", 1, state="FIXED"), apf("a", 2), apf("a", 3), apf("e", 1)]
        result = d.compute_delta(previous, current, self.cov)
        cats = {(c.finding.asset_id, c.finding.plugin_id): c.category for c in result.changes}
        self.assertEqual(cats[("a", 1)], d.PERSISTING)
        self.assertEqual(cats[("b", 1)], d.CLOSED)  # rescanned, now FIXED
        self.assertEqual(cats[("c", 1)], d.CLOSED)  # rescanned, finding gone
        self.assertEqual(cats[("d", 1)], d.UNVERIFIED_ABSENCE)  # asset absent from current export
        self.assertEqual(cats[("a", 2)], d.REOPENED)  # was FIXED, open again
        self.assertEqual(cats[("a", 3)], d.NEW_EXPOSURE)  # asset scanned before, finding is new
        self.assertEqual(cats[("e", 1)], d.NEW_VISIBILITY)  # asset new to the scan

    def test_summary_counts_by_severity(self):
        previous = [apf("a", 1, sev=4), apf("b", 1, sev=3), apf("d", 1, sev=4)]
        current = [apf("e", 1, sev=4)]
        summary = d.compute_delta(previous, current, self.cov).summary()
        self.assertEqual(summary["critical_closed"], 1)
        self.assertEqual(summary["high_closed"], 1)
        self.assertEqual(summary["critical_unverified_absence"], 1)
        self.assertEqual(summary["critical_new_visibility"], 1)
        self.assertEqual(summary["assets_not_rescanned"], 1)
        self.assertEqual(summary["assets_newly_in_scope"], 1)

    def test_informational_rows_ignored(self):
        previous = [apf("a", 19506, sev=0)]
        current = [apf("b", 19506, sev=0)]
        result = d.compute_delta(previous, current, self.cov)
        self.assertEqual(result.changes, [])

    def test_no_previous_export_is_all_new_visibility(self):
        result = d.compute_delta(None, [apf("a", 1), apf("b", 2, state="FIXED")], Coverage(frozenset(), frozenset({"a", "b"})))
        self.assertFalse(result.has_previous)
        self.assertEqual([c.category for c in result.changes], [d.NEW_VISIBILITY])

    def test_cves_counts_distinct_assets(self):
        previous = [apf("a", 1), apf("b", 1), apf("b", 2)]
        current = []
        result = d.compute_delta(previous, current, Coverage(frozenset({"a", "b"}), frozenset({"a", "b"})))
        self.assertEqual(result.cves(d.CLOSED), {"CVE-2024-38063": 2})


if __name__ == "__main__":
    unittest.main()
