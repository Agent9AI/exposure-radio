import unittest

from exposure_radio import facts as facts_mod
from exposure_radio.facts import FactStore
from tests.common import demo_episode, first_episode, held_episode


class DemoFactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = demo_episode().facts

    def v(self, subject, predicate):
        return self.store.value(subject, predicate)

    def test_episode_numbers_match_the_fixture_design(self):
        self.assertEqual(self.v("episode", "export_date"), "2026-10-27")
        self.assertEqual(self.v("episode", "previous_export_date"), "2026-10-20")
        self.assertEqual(self.v("episode", "asset_count"), 51)
        self.assertEqual(self.v("episode", "assets_rescanned"), 48)
        self.assertEqual(self.v("episode", "assets_not_rescanned"), 3)
        self.assertEqual(self.v("episode", "assets_newly_in_scope"), 3)
        self.assertEqual(self.v("episode", "open_critical_count"), 11)
        self.assertEqual(self.v("episode", "open_high_count"), 13)
        self.assertEqual(self.v("episode", "kev_open_cve_count"), 5)
        self.assertEqual(self.v("episode", "kev_open_asset_count"), 6)
        self.assertIs(self.v("episode", "held"), False)
        self.assertIs(self.v("episode", "export_complete"), True)

    def test_delta_numbers(self):
        self.assertEqual(self.v("delta", "critical_closed"), 16)
        self.assertEqual(self.v("delta", "high_closed"), 9)
        self.assertEqual(self.v("delta", "new_exposure_count"), 1)
        self.assertEqual(self.v("delta", "new_visibility_count"), 4)
        self.assertEqual(self.v("delta", "unverified_absence_count"), 3)
        self.assertEqual(self.v("delta", "kev_new_entries"), ("CVE-2026-110447",))
        self.assertEqual(self.v("delta", "kev_new_entry_count"), 1)
        self.assertEqual(self.v("delta", "kev_newly_exposed"), ("CVE-2026-110447",))

    def test_cve_facts_and_sources(self):
        subject = "cve:CVE-2024-3400"
        self.assertEqual(self.v(subject, "open_asset_count"), 2)
        self.assertEqual(self.v(subject, "severity"), "critical")
        self.assertIs(self.v(subject, "kev_listed"), True)
        self.assertEqual(self.v(subject, "kev_date_added"), "2024-04-12")
        self.assertEqual(self.v(subject, "kev_catalogue_due_date"), "2024-04-19")
        self.assertIs(self.v(subject, "kev_ransomware_use"), True)
        self.assertIs(self.v(subject, "kev_added_since_previous"), False)
        self.assertEqual(self.v(subject, "owner"), "Network Engineering")
        self.assertEqual(self.v(subject, "research_count"), 1)
        self.assertEqual(self.store.get(subject, "kev_listed").source, "kev:2026.10.30")
        self.assertEqual(self.store.get(subject, "open_asset_count").source, "export:current")
        self.assertEqual(len(self.store.get(subject, "open_asset_count").evidence), 2)
        self.assertEqual(self.store.get(subject, "epss_score").source, "epss:2026-10-30")
        self.assertGreater(self.v(subject, "epss_score"), 0.9)
        self.assertTrue(str(self.v(subject, "kev_required_action")).startswith("Apply"))
        self.assertIsNone(self.store.get("cve:CVE-2026-110447", "epss_score"))  # not in the EPSS snapshot
        self.assertIs(self.v("cve:CVE-2026-110447", "kev_ransomware_use"), False)

    def test_primary_cve_selection_on_multi_cve_plugin(self):
        # Both Ivanti CVEs are KEV-listed and there is no EPSS; the newest id wins.
        self.assertEqual(self.v("cve:CVE-2024-21887", "open_asset_count"), 1)
        self.assertIsNone(self.store.get("cve:CVE-2023-46805", "open_asset_count"))

    def test_priority_ranking(self):
        items = self.v("priority", "items")
        self.assertEqual(items[0], "CVE-2026-110447")  # KEV, critical, added since the previous export
        self.assertEqual(items[1], "CVE-2024-3400")  # KEV, critical, two assets
        self.assertEqual(self.v("priority", "lead_cve"), "CVE-2026-110447")
        self.assertEqual(self.v("cve:CVE-2026-110447", "priority_rank"), 1)
        self.assertIs(self.v("cve:CVE-2026-110447", "kev_added_since_previous"), True)
        non_kev_rank = self.v("cve:CVE-2024-38063", "priority_rank")
        self.assertGreater(non_kev_rank, 5)

    def test_sla_deadline_distinct_from_kev_dates(self):
        subject = "cve:CVE-2026-110447"
        self.assertEqual(self.v(subject, "sla_deadline"), "2026-10-31")  # 7 KEV days - 3 exploit days from 2026-10-27
        self.assertEqual(self.v(subject, "sla_days"), 4)
        self.assertEqual(self.v(subject, "kev_catalogue_due_date"), "2026-10-26")
        self.assertEqual(self.store.get(subject, "sla_deadline").source, "sla:data/sla.json")
        high = "cve:CVE-2024-6387"
        self.assertEqual(self.v(high, "sla_deadline"), "2026-11-23")  # 30 high days - 3 exploit days

    def test_redacted_dump_has_no_evidence_rows(self):
        rows = self.store.to_list(redact=True)
        self.assertTrue(all("evidence" not in r for r in rows))
        self.assertTrue(all("evidence_count" in r for r in rows))


class RuleTests(unittest.TestCase):
    def test_sla_deadline_rules(self):
        sla = {"deadline_days": {"kev_listed": 7, "critical": 14, "high": 30, "medium": 90, "low": 180}, "exploit_available_bonus_days": -3, "minimum_days": 2}
        self.assertEqual(facts_mod.sla_deadline(sla, "2026-10-27", 4, True, False), ("2026-11-03", 7))
        self.assertEqual(facts_mod.sla_deadline(sla, "2026-10-27", 4, False, False), ("2026-11-10", 14))
        self.assertEqual(facts_mod.sla_deadline(sla, "2026-10-27", 2, False, True), ("2027-01-22", 87))
        self.assertEqual(facts_mod.sla_deadline({"deadline_days": {"kev_listed": 1}, "exploit_available_bonus_days": -5, "minimum_days": 2}, "2026-10-27", 4, True, True), ("2026-10-29", 2))

    def test_owner_mapping(self):
        owners = {"default": "UNASSIGNED", "by_tag": {"group:edge": "Net"}}
        self.assertEqual(facts_mod.owner_for(["env:prod", "group:edge"], owners), "Net")
        self.assertEqual(facts_mod.owner_for(["group:other"], owners), "UNASSIGNED")

    def test_fact_store_basics(self):
        store = FactStore()
        fact = store.add("cve:CVE-1", "open_asset_count", [1, 2], "s")
        self.assertEqual(fact.value, (1, 2))
        self.assertEqual(store.by_id(fact.fact_id), fact)
        self.assertEqual(store.cves(), ["CVE-1"])
        self.assertEqual(store.value("cve:CVE-1", "missing", "d"), "d")


class OtherEpisodeShapes(unittest.TestCase):
    def test_held_episode_facts(self):
        store = held_episode().facts
        self.assertIs(store.value("episode", "held"), True)
        self.assertIs(store.value("episode", "export_complete"), False)
        self.assertTrue(store.value("episode", "hold_reasons"))

    def test_first_episode_has_no_delta_progress(self):
        store = first_episode().facts
        self.assertIs(store.value("delta", "has_previous"), False)
        self.assertIsNone(store.get("episode", "previous_export_date"))
        self.assertEqual(store.value("delta", "new_visibility_count"), store.value("episode", "finding_count"))


if __name__ == "__main__":
    unittest.main()
