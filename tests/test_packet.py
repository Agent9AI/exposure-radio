import json
import unittest

from exposure_radio import alert as alert_mod
from exposure_radio import packet as packet_mod
from exposure_radio.textaudit import audit_free_text
from tests.common import demo_episode, held_episode


class PacketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.episode = demo_episode()
        cls.full = cls.episode.packet_full
        cls.ciso = cls.episode.packet_ciso

    def test_three_items_in_priority_order(self):
        self.assertEqual([i["cve"] for i in self.full["items"]], ["CVE-2026-110447", "CVE-2024-3400", "CVE-2025-53770"])
        self.assertEqual([i["rank"] for i in self.full["items"]], [1, 2, 3])

    def test_three_kinds_of_date_are_separate_fields(self):
        item = self.full["items"][0]
        self.assertEqual(item["kev"]["date_added"], "2026-10-23")
        self.assertEqual(item["kev"]["catalogue_due_date"], "2026-10-26")
        self.assertEqual(item["deadline"]["internal_sla"], "2026-10-31")
        self.assertIn("BOD 26-04", item["deadline"]["policy_note"])
        self.assertIn("replaced BOD 22-01", item["deadline"]["policy_note"])
        ticket = item["ticket_markdown"]
        self.assertNotIn("KEV due date", ticket)
        self.assertIn("Catalogue dueDate field: 2026-10-26 (CISA catalogue value)", ticket)
        self.assertIn("Deadline (internal SLA):** 2026-10-31", ticket)

    def test_owner_and_evidence_on_the_card(self):
        item = self.full["items"][1]
        self.assertEqual(item["owner"], "Network Engineering")
        predicates = {e["predicate"] for e in item["evidence"]}
        self.assertTrue({"open_asset_count", "kev_listed", "sla_deadline", "owner"} <= predicates)
        self.assertTrue(all(e["fact"].startswith("f") for e in item["evidence"]))
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2024-3400", item["references"])
        self.assertIn("https://www.tenable.com/plugins/nessus/193255", item["references"])
        self.assertTrue(any("tenable.com/blog" in r for r in item["references"]))
        self.assertEqual(item["plugin_ids"], [193255])

    def test_full_edition_lists_assets_and_ciso_edition_does_not(self):
        full_item = self.full["items"][1]
        ciso_item = self.ciso["items"][1]
        self.assertEqual(sorted(full_item["assets"]), ["fw-edge-01.northwind.internal", "fw-edge-02.northwind.internal"])
        self.assertEqual(ciso_item["assets"], [])
        self.assertEqual(ciso_item["plugin_names"], [])
        self.assertEqual(ciso_item["open_asset_count"], 2)
        self.assertIn("identifiers withheld", ciso_item["ticket_markdown"])
        self.assertNotIn("northwind", json.dumps(self.ciso))

    def test_ciso_packet_passes_identifier_audit(self):
        self.assertEqual(audit_free_text(json.dumps(self.ciso), self.episode.forbidden), [])
        self.assertFalse(self.ciso.get("withheld"))

    def test_epss_absent_is_said_plainly(self):
        self.assertIsNone(self.full["items"][0]["epss"])
        self.assertIn("EPSS: no score in the offline snapshot", self.full["items"][0]["ticket_markdown"])

    def test_change_block(self):
        lead = self.full["items"][0]
        self.assertEqual(lead["change_since_previous"]["new_exposure"], 1)
        sharepoint = self.full["items"][2]
        self.assertEqual(sharepoint["change_since_previous"]["closed"], 1)

    def test_packet_summary_and_receipt(self):
        self.assertEqual(self.full["summary"]["critical_closed"], 16)
        self.assertEqual(self.full["summary"]["kev_new_entries"], ["CVE-2026-110447"])
        self.assertTrue(self.full["gate_receipt"]["passed"])
        self.assertEqual(self.full["edition"], "full")
        self.assertTrue(any(s["id"] == "export:current" for s in self.full["sources"]))

    def test_held_packet_flags_hold(self):
        held = held_episode().packet_full
        self.assertTrue(held["held"])
        self.assertTrue(held["hold_reasons"])

    def test_render_ticket_without_kev(self):
        item = packet_mod.CardItem(
            cve="CVE-2024-6387", rank=4, severity="high", open_asset_count=2, owner="Platform Engineering",
            sla_deadline="2026-11-23", sla_days=27, export_date="2026-10-27", kev=None, epss={"score": 0.1234, "percentile": 0.9},
            exploit_available=True, cvss3=8.1, first_seen="2026-07-03", plugin_ids=(201194,), plugin_names=("OpenSSH",),
            ports=("22/tcp",), asset_groups=("group:web",), assets=(), change={"new_exposure": 0, "closed": 6, "unverified_absence": 0, "reopened": 0},
            research=None, evidence=[], references=[],
        )
        text = packet_mod.render_ticket(item)
        self.assertIn("Not in the CISA KEV catalogue snapshot.", text)
        self.assertIn("EPSS: 12.3% probability", text)
        self.assertIn("identifiers withheld in this edition (group:web)", text)


class AlertTests(unittest.TestCase):
    def test_alert_has_counts_only(self):
        episode = demo_episode()
        alert = episode.alert
        self.assertEqual(alert["title"], "Exposure Radio")
        self.assertIn("3 priority items today, 5 KEV-listed CVEs open.", alert["body"])
        self.assertIn("16 critical findings closed", alert["body"])
        self.assertIn("1 KEV catalogue addition touches the estate.", alert["body"])
        self.assertEqual(len(alert["reference"]), 12)
        self.assertEqual(alert_mod.audit_alert(alert, episode.forbidden), [])
        self.assertNotIn("CVE-", alert["body"])
        self.assertNotIn("northwind", alert["body"])

    def test_held_alert(self):
        episode = held_episode()
        self.assertIn("incomplete", episode.alert["body"])
        self.assertIn("held", episode.alert["body"])
        self.assertEqual(alert_mod.audit_alert(episode.alert, episode.forbidden), [])


if __name__ == "__main__":
    unittest.main()
