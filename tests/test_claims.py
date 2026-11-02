import unittest

from exposure_radio import claims
from exposure_radio.facts import FactStore


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.store = FactStore()
        self.open_fact = self.store.add("cve:CVE-2024-3400", "open_asset_count", 2, "export:current", ["a", "b"])
        self.kev_fact = self.store.add("cve:CVE-2024-3400", "kev_listed", True, "kev:v1")
        self.score_fact = self.store.add("cve:CVE-2024-3400", "epss_score", 0.94, "epss:v1")
        self.list_fact = self.store.add("delta", "kev_new_entries", ("CVE-2026-110447",), "kev:v1")

    def check(self, claim):
        return claims.validate_claim(claim, self.store)

    def test_supported_claim_passes(self):
        self.assertIsNone(self.check(claims.claim_from_fact(self.open_fact)))

    def test_unknown_cite(self):
        rejection = self.check(claims.Claim("cve:CVE-2024-3400", "open_asset_count", 2, "f9999"))
        self.assertEqual(rejection.code, claims.UNKNOWN_CITE)

    def test_unknown_subject(self):
        rejection = self.check(claims.Claim("cve:CVE-2031-99999", "open_asset_count", 2, "f9999"))
        self.assertEqual(rejection.code, claims.UNKNOWN_SUBJECT)

    def test_subject_mismatch(self):
        rejection = self.check(claims.Claim("cve:CVE-2031-99999", "open_asset_count", 2, self.open_fact.fact_id))
        self.assertEqual(rejection.code, claims.SUBJECT_MISMATCH)

    def test_predicate_mismatch_is_the_wrong_relation_case(self):
        rejection = self.check(claims.Claim("cve:CVE-2024-3400", "closed_asset_count", 20, self.open_fact.fact_id))
        self.assertEqual(rejection.code, claims.PREDICATE_MISMATCH)

    def test_value_mismatch(self):
        rejection = self.check(claims.Claim("cve:CVE-2024-3400", "open_asset_count", 3, self.open_fact.fact_id))
        self.assertEqual(rejection.code, claims.VALUE_MISMATCH)

    def test_type_discipline(self):
        self.assertFalse(claims.values_equal(True, 1))
        self.assertFalse(claims.values_equal(1, True))
        self.assertTrue(claims.values_equal(2, 2.0))
        self.assertFalse(claims.values_equal(0.94, 0.094))
        self.assertTrue(claims.values_equal(0.94, 0.94))
        self.assertTrue(claims.values_equal(("a", "b"), ["a", "b"]))
        self.assertFalse(claims.values_equal("2", 2))
        rejection = self.check(claims.Claim("cve:CVE-2024-3400", "kev_listed", 1, self.kev_fact.fact_id))
        self.assertEqual(rejection.code, claims.VALUE_MISMATCH)

    def test_list_values_round_trip(self):
        claim = claims.Claim.from_dict({"subject": "delta", "predicate": "kev_new_entries", "value": ["CVE-2026-110447"], "cite": self.list_fact.fact_id})
        self.assertIsNone(self.check(claim))
        self.assertEqual(claim.to_dict()["value"], ["CVE-2026-110447"])

    def test_malformed_input(self):
        with self.assertRaises(ValueError):
            claims.Claim.from_dict({"subject": 1, "predicate": "x", "value": 1, "cite": "f1"})
        with self.assertRaises(ValueError):
            claims.Claim.from_dict("nope")
        rejection = self.check(claims.Claim("", "x", 1, ""))
        self.assertEqual(rejection.code, claims.MALFORMED)

    def test_validate_batches(self):
        good = claims.claim_from_fact(self.kev_fact)
        bad = claims.Claim("cve:CVE-2024-3400", "kev_listed", False, self.kev_fact.fact_id)
        accepted, rejected = claims.validate([good, bad], self.store)
        self.assertEqual(accepted, [good])
        self.assertEqual(rejected[0].code, claims.VALUE_MISMATCH)

    def test_claims_for_skips_missing_predicates(self):
        out = claims.claims_for(self.store, "cve:CVE-2024-3400", ("open_asset_count", "missing"))
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()
