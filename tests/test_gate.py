"""Claims, the narration grammar and the gate."""

import unittest

from exposure_radio.adversarial import cases, run_all, run_case
from exposure_radio.claims import BY_ID, FIXED_LINES, TEMPLATES, Claim, parse_sentence, render, validate_claim
from exposure_radio.gate import BLOCKED, SUPPORTED, UNVERIFIABLE, audit_sentence, gate_script, receipt_matches
from exposure_radio.numbers import find_numbers, spoken, to_int

from .helpers import demo_cycle


class Numbers(unittest.TestCase):
    def test_words_and_digits(self):
        for text, n in (("20", 20), ("twenty", 20), ("twenty-one", 21), ("no", 0), ("a dozen", 12),
                        ("one hundred and five", 105), ("both", 2)):
            self.assertEqual(to_int(text), n, text)
        self.assertIsNone(to_int("several"))
        self.assertEqual(find_numbers("fixed on twenty assets, open on 2"), [20, 2])

    def test_spoken_round_trip(self):
        for n in (0, 7, 13, 20, 21, 99, 100, 345, 1000, 2026):
            self.assertEqual(to_int(spoken(n)), n)


class Grammar(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.L = demo_cycle().ledger

    def test_every_template_round_trips(self):
        values = {"cve": "CVE-2024-3400", "n": 2, "m": 5, "date": "2026-10-30", "name": "Example Name"}
        for t in TEMPLATES:
            text = render(t.id, **values)
            parsed = parse_sentence(text)
            self.assertIsNotNone(parsed, text)
            self.assertEqual(parsed.template.id, t.id, text)

    def test_singular_and_plural(self):
        self.assertEqual(render("C_OPEN", cve="CVE-2024-3400", n=1), "CVE-2024-3400 is open on 1 asset.")
        self.assertEqual(render("T_FIXED", n=1), "1 priority finding was verified fixed by a rescan.")
        self.assertEqual(render("T_FIXED", n=3), "3 priority findings were verified fixed by a rescan.")

    def test_claim_validation_rules(self):
        L = self.L
        ok = validate_claim(Claim("CVE-2024-3400", "cve.open_assets", "two"), L)
        self.assertTrue(ok.ok)
        wrong_type = validate_claim(Claim("CVE-2024-3400", "cve.open_assets", "several"), L)
        self.assertFalse(wrong_type.ok)
        bad_subject = validate_claim(Claim("tenant", "cve.open_assets", 2), L)
        self.assertFalse(bad_subject.ok)
        ghost = validate_claim(Claim("CVE-2024-3400", "cve.open_assets", 2, "F999"), L)
        self.assertIn("does not exist", ghost.reason)

    def test_host_membership(self):
        L = self.L
        self.assertTrue(validate_claim(Claim("CVE-2024-3400", "cve.affected_hosts", ["fw-edge-01"]), L).ok)
        self.assertFalse(validate_claim(Claim("CVE-2024-3400", "cve.affected_hosts", ["vpn-gw-01"]), L).ok)


class Gate(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cycle = demo_cycle()
        cls.L = cls.cycle.ledger

    def test_adversarial_suite(self):
        results, scripts = run_all(self.L, self.cycle.episode.lines)
        failures = [(r.case.name, r.status, r.reasons) for r in results if not r.passed]
        self.assertEqual(failures, [])
        self.assertTrue(scripts["clean_script_passed"])
        self.assertFalse(scripts["tampered_script_passed"])

    def test_false_cases_block_on_evidence_not_vocabulary(self):
        for case in cases(self.L):
            if case.expect != BLOCKED:
                continue
            reasons = " ".join(run_case(case, self.L).reasons)
            self.assertNotIn("controlled vocabulary", reasons, case.name)

    def test_the_two_mandatory_rejections(self):
        v = audit_sentence("CVE-2024-3400 is fixed on 20 assets.", self.L, strict=False)
        self.assertEqual(v.status, BLOCKED)
        self.assertIn("says 0, not 20", v.reasons[0])
        self.assertIn("open on 2", v.reasons[0])
        for sentence in ("Everything is safe.", "Disable your monitoring.", "You are fully patched.",
                         "No action is required.", "There are no open vulnerabilities.",
                         "You can safely ignore the Ivanti alert."):
            self.assertEqual(audit_sentence(sentence, self.L, strict=False).status, BLOCKED, sentence)

    def test_strict_mode_blocks_true_free_text(self):
        true_prose = "The firewall CVE-2024-3400 remains open on 2 assets."
        self.assertEqual(audit_sentence(true_prose, self.L, strict=False).status, SUPPORTED)
        self.assertEqual(audit_sentence(true_prose, self.L, strict=True).status, BLOCKED)

    def test_unverifiable_prose_is_flagged(self):
        v = audit_sentence("Our team has been working hard.", self.L, strict=False)
        self.assertEqual(v.status, UNVERIFIABLE)

    def test_fixed_lines_only_exact(self):
        for line in FIXED_LINES:
            self.assertTrue(audit_sentence(line, self.L).ok)
        self.assertFalse(audit_sentence("That is the bulletin, and everything is fine.", self.L).ok)

    def test_hostnames_never_air(self):
        v = audit_sentence("CVE-2024-3400 is open on fw-edge-01.", self.L, strict=True)
        self.assertFalse(v.ok)
        self.assertTrue(any("names tenant systems" in r for r in v.reasons))

    def test_injected_name_is_not_speakable(self):
        name = self.L.value("CVE-2025-9316", "cve.name")
        sentence = render("C_NAME", cve="CVE-2025-9316", name=name)
        self.assertFalse(gate_script([{"voice": "ANALYST", "text": sentence}], self.L).passed)

    def test_receipt_binds_text_and_ledger(self):
        lines = self.cycle.episode.lines
        receipt = gate_script(lines, self.L).receipt()
        self.assertTrue(receipt_matches(receipt, lines, self.L))
        edited = [dict(l) for l in lines]
        edited[-1]["text"] = "That is the bulletin!"
        self.assertFalse(receipt_matches(receipt, edited, self.L))

    def test_every_script_line_is_cited_or_fixed(self):
        for line in self.cycle.episode.lines:
            if line["template"]:
                self.assertTrue(line["cites"], line["text"])
                self.assertIn(line["voice"], ("ANCHOR", "ANALYST"))
                self.assertEqual(BY_ID[line["template"]].voice, line["voice"])
            else:
                self.assertIn(line["text"], FIXED_LINES)


if __name__ == "__main__":
    unittest.main()
