import unittest

from exposure_radio import templates
from exposure_radio.claims import Claim
from exposure_radio.facts import FactStore
from exposure_radio.textaudit import audit_sentences

SAMPLE_VALUES = {
    "export_date": "2026-10-27",
    "asset_count": 51,
    "finding_count": 53,
    "assets_rescanned": 48,
    "assets_not_rescanned": 3,
    "assets_newly_in_scope": 3,
    "open_critical_count": 11,
    "open_high_count": 13,
    "kev_open_cve_count": 5,
    "kev_open_asset_count": 6,
    "critical_closed": 16,
    "kev_new_entry_count": 1,
    "new_exposure_count": 1,
    "new_visibility_count": 4,
    "unverified_absence_count": 3,
    "kev_new_entries": ("CVE-2026-110447", "CVE-2024-3400"),
    "priority_rank": 1,
    "severity": "critical",
    "open_asset_count": 2,
    "kev_listed": True,
    "kev_vendor": "Palo Alto Networks",
    "kev_product": "PAN-OS",
    "kev_date_added": "2024-04-12",
    "kev_ransomware_use": True,
    "epss_score": 0.94321,
    "exploit_available": True,
    "closed_asset_count": 0,
    "owner": "Network Engineering",
    "sla_deadline": "2026-10-31",
    "research_count": 1,
    "first_seen": "2024-04-16",
    "count": 3,
    "decision": "SCHEDULED",
}


def segment_for(template, rank=1):
    subject = {"cve": "cve:CVE-2024-3400", "episode": "episode", "delta": "delta", "priority": "priority"}[template.subject_kind]
    values = dict(SAMPLE_VALUES)
    values["priority_rank"] = rank
    for predicate, required in template.requires:
        values[predicate] = required
    return templates.Segment(template.template_id, tuple(Claim(subject, p, values[p], f"f{i:04d}") for i, p in enumerate(template.slots, start=1)))


class RenderTests(unittest.TestCase):
    def test_every_template_renders_and_passes_the_text_audit(self):
        store = FactStore()
        store.add("cve:CVE-2024-3400", "open_asset_count", 2, "export:current")
        store.add("cve:CVE-2026-110447", "open_asset_count", 1, "export:current")
        for template in templates.TEMPLATES.values():
            rank = 1 if template.template_id == "cve.lead" else 2
            sentence = templates.render_segment(segment_for(template, rank))
            self.assertTrue(sentence.endswith("."), sentence)
            issues = audit_sentences([sentence], store)
            self.assertEqual([i.code for i in issues], [], f"{template.template_id}: {sentence} -> {issues}")

    def test_fixed_sentences_take_no_claims(self):
        self.assertEqual(templates.render_segment(templates.Segment("intro.station")), "This is Exposure Radio.")
        with self.assertRaises(templates.TemplateError):
            templates.render_segment(templates.Segment("intro.station", (Claim("episode", "export_date", "2026-10-27", "f1"),)))

    def test_slot_order_and_subject_are_enforced(self):
        bad_order = templates.Segment(
            "episode.scope",
            (Claim("episode", "finding_count", 53, "f1"), Claim("episode", "asset_count", 51, "f2")),
        )
        with self.assertRaises(templates.TemplateError):
            templates.render_segment(bad_order)
        mixed = templates.Segment(
            "episode.scope",
            (Claim("episode", "asset_count", 51, "f1"), Claim("delta", "finding_count", 53, "f2")),
        )
        with self.assertRaises(templates.TemplateError):
            templates.render_segment(mixed)
        wrong_kind = templates.Segment("cve.epss", (Claim("episode", "epss_score", 0.5, "f1"),))
        with self.assertRaises(templates.TemplateError):
            templates.render_segment(wrong_kind)

    def test_required_values(self):
        seg = templates.Segment("cve.exploit", (Claim("cve:CVE-2024-3400", "exploit_available", False, "f1"),))
        with self.assertRaises(templates.TemplateError):
            templates.render_segment(seg)
        seg = templates.Segment("cve.exploit", (Claim("cve:CVE-2024-3400", "exploit_available", 1, "f1"),))
        with self.assertRaises(templates.TemplateError):
            templates.render_segment(seg)

    def test_unknown_template(self):
        with self.assertRaises(templates.TemplateError):
            templates.render_segment(templates.Segment("cve.free_text", ()))

    def test_formatting_helpers(self):
        self.assertEqual(templates.long_date("2026-10-27"), "27 October 2026")
        self.assertEqual(templates.count(1, "asset"), "1 asset")
        self.assertEqual(templates.count(2, "asset"), "2 assets")
        self.assertEqual(templates.percent(0.94321), "94.3")
        self.assertEqual(templates.join_list(("a", "b", "c")), "a, b and c")
        with self.assertRaises(templates.TemplateError):
            templates.long_date("not a date")
        with self.assertRaises(templates.TemplateError):
            templates.count(-1, "asset")
        with self.assertRaises(templates.TemplateError):
            templates.percent(1.5)

    def test_segment_round_trip_and_limits(self):
        seg = segment_for(templates.TEMPLATES["cve.kev"])
        back = templates.Segment.from_dict(seg.to_dict())
        self.assertEqual(back, seg)
        with self.assertRaises(templates.TemplateError):
            templates.Segment.from_dict({"template": "x", "claims": [{"subject": "s", "predicate": "p", "value": 1, "cite": "c"}] * 9})
        with self.assertRaises(templates.TemplateError):
            templates.Segment.from_dict({"claims": []})


if __name__ == "__main__":
    unittest.main()
