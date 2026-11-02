import unittest

from exposure_radio import evidence
from exposure_radio.model import Asset, Export, Finding


def finding(asset, plugin, port, state="OPEN", cves=(), cvss=None, sev=3, first=None, last=None):
    return Finding(
        asset_id=asset,
        plugin_id=plugin,
        plugin_name=f"plugin {plugin}",
        severity=sev,
        cves=tuple(cves),
        port=port,
        protocol="tcp",
        state=state,
        first_found=first,
        last_found=last,
        cvss3=cvss,
        record_ref=f"r-{asset}-{plugin}-{port}",
    )


class DedupeTests(unittest.TestCase):
    def test_ports_fold_into_one_record(self):
        rows = [finding("a", 51192, 443), finding("a", 51192, 8443), finding("a", 51192, 443)]
        out = evidence.dedupe(rows)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].ports, ("443/tcp", "8443/tcp"))
        self.assertEqual(len(out[0].record_refs), 3)

    def test_distinct_assets_stay_distinct(self):
        out = evidence.dedupe([finding("a", 1, 80), finding("b", 1, 80)])
        self.assertEqual({o.asset_id for o in out}, {"a", "b"})

    def test_open_wins_over_fixed_and_values_aggregate(self):
        rows = [
            finding("a", 7, 443, state="FIXED", cvss=7.0, first="2026-01-01T00:00:00Z", last="2026-02-01T00:00:00Z"),
            finding("a", 7, 8443, state="OPEN", cvss=9.8, first="2025-12-01T00:00:00Z", last="2026-03-01T00:00:00Z", cves=["CVE-2024-3400"]),
        ]
        out = evidence.dedupe(rows)[0]
        self.assertTrue(out.is_open)
        self.assertEqual(out.cvss3, 9.8)
        self.assertEqual(out.first_found, "2025-12-01T00:00:00Z")
        self.assertEqual(out.last_found, "2026-03-01T00:00:00Z")
        self.assertEqual(out.cves, ("CVE-2024-3400",))


class PrimaryCveTests(unittest.TestCase):
    def test_kev_listing_wins(self):
        pick = evidence.select_primary_cve(["CVE-2023-46805", "CVE-2024-21887"], frozenset({"CVE-2023-46805"}), {"CVE-2024-21887": 0.97})
        self.assertEqual(pick, "CVE-2023-46805")

    def test_epss_breaks_ties_within_kev(self):
        pick = evidence.select_primary_cve(["CVE-2023-46805", "CVE-2024-21887"], frozenset({"CVE-2023-46805", "CVE-2024-21887"}), {"CVE-2023-46805": 0.5, "CVE-2024-21887": 0.9})
        self.assertEqual(pick, "CVE-2024-21887")

    def test_newest_cve_is_the_final_tiebreak(self):
        pick = evidence.select_primary_cve(["CVE-2024-9999", "CVE-2024-10000"], frozenset(), {})
        self.assertEqual(pick, "CVE-2024-10000")

    def test_empty_list(self):
        self.assertIsNone(evidence.select_primary_cve([], frozenset(), {}))


def export(label, assets, completed=None):
    return Export(
        label=label,
        source=label,
        format="tenable-json",
        assets={asset_id: Asset(asset_id, last_activity=activity) for asset_id, activity in assets.items()},
        scan_completed=completed,
    )


class CoverageTests(unittest.TestCase):
    def test_sets(self):
        prev = export("p", {"a": "2026-10-20T02:00:00Z", "b": "2026-10-20T02:00:00Z"}, completed="2026-10-20T02:14:09Z")
        cur = export("c", {"b": "2026-10-27T02:00:00Z", "c": "2026-10-27T02:00:00Z"}, completed="2026-10-27T02:11:52Z")
        cov = evidence.coverage(prev, cur)
        self.assertEqual(cov.rescanned, {"b"})
        self.assertEqual(cov.not_rescanned, {"a"})
        self.assertEqual(cov.newly_in_scope, {"c"})

    def test_presence_in_the_export_is_not_a_scan(self):
        # Asset "a" is carried in the current export with stale activity: it was not rescanned.
        prev = export("p", {"a": "2026-10-29T04:00:00Z", "b": "2026-10-29T06:00:00Z"}, completed="2026-10-29T07:00:00Z")
        cur = export("c", {"a": "2026-10-29T04:00:00Z", "b": "2026-10-30T05:00:00Z", "d": None}, completed="2026-10-30T07:00:00Z")
        cov = evidence.coverage(prev, cur)
        self.assertEqual(cov.current, {"b", "d"})  # unknown activity counts as scanned
        self.assertEqual(cov.not_rescanned, {"a"})
        self.assertEqual(cov.rescanned, {"b"})

    def test_same_export_twice_rescans_nothing(self):
        prev = export("p", {"a": "2026-10-29T04:00:00Z"}, completed="2026-10-29T07:00:00Z")
        cov = evidence.coverage(prev, export("c", {"a": "2026-10-29T04:00:00Z"}, completed="2026-10-29T07:00:00Z"))
        self.assertEqual(cov.not_rescanned, {"a"})

    def test_no_previous(self):
        cov = evidence.coverage(None, export("c", {"b": None}))
        self.assertEqual(cov.newly_in_scope, {"b"})
        self.assertEqual(cov.not_rescanned, frozenset())


if __name__ == "__main__":
    unittest.main()
