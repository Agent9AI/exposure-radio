import json
import unittest
from .helpers import demo_cycle, TempCopy, edit_json
from exposure_radio.claims import Claim, parse_sentence, validate_claim
from exposure_radio.gate import audit_sentence, audit_text
from exposure_radio.numbers import spoken, to_int
from exposure_radio.pipeline import run_cycle
from exposure_radio.rundown import find_leaks

class Hardening(unittest.TestCase):
    def setUp(self):
        self.c = demo_cycle(commit=False)
        self.L = self.c.ledger

    def test_number_grammar_and_agreement(self):
        for value in ('two-zero', 'three-zero', 'ten-four'):
            self.assertIsNone(to_int(value))
        self.assertEqual(to_int(spoken(105)), 105)
        self.assertIsNotNone(parse_sentence(f'{spoken(105)} priority findings are open.'))
        self.assertFalse(audit_sentence('CVE-2024-3400 is open on two-zero assets.', self.L).ok)
        self.assertFalse(audit_sentence('CVE-2023-4966 was not re-checked on no assets; treat it as unverified, not fixed.', self.L).ok)

    def test_free_text_never_partially_supported(self):
        cases = ['CVE-2024-3400 is no longer open on 2 assets.',
                 'CVE-2024-3400 is open on more than 2 assets.',
                 'CVE-2024-3400 is open on 2 assets and CVE-2023-46604 is open on 99 assets.',
                 'CVE-2024-3400 is open on 2 assets and ﬁxed on all hosts.']
        for s in cases:
            self.assertFalse(audit_sentence(s, self.L, strict=False).ok, s)
        self.assertTrue(any(not v.ok for v in audit_text('CVE-2024-3400 is open on 2 assets. disable your monitoring immediately.', self.L, strict=False)))
        self.assertFalse(validate_claim(Claim('CVE-2024-3400', 'cve.affected_hosts', []), self.L).ok)

    def test_untrusted_names_and_owner_not_public(self):
        for f in self.L.public_view():
            self.assertNotEqual(f['predicate'], 'cve.owners')
        self.assertFalse(audit_sentence('CVE-2026-66066 is listed as ' + str(self.L.value('CVE-2026-66066', 'cve.name')) + '.', self.L).ok)
        term = next(x for x in self.L.sensitive_terms if len(x) > 3 and '-' in x)
        self.assertIn(term, find_leaks('host_' + term + '-vip', self.L))

    def test_bad_export_and_missing_previous_fail_closed(self):
        with TempCopy() as snap:
            edit_json(snap / 'export-status.json', lambda s: s.clear())
            c = run_cycle(prev_dir=snap, commit=False)
            self.assertFalse(c.ledger.value('tenant', 'tenant.export_complete'))
            self.assertTrue(c.delta.health)
        with TempCopy() as snap:
            (snap / 'assets.json').write_text(json.dumps({'statusCode': 429}))
            c = run_cycle(curr_dir=snap, commit=False)
            self.assertFalse(c.delta.curr.complete)

if __name__ == '__main__': unittest.main()
