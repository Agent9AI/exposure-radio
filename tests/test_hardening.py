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

class CoverageAndPolicy(unittest.TestCase):
    def setUp(self):
        from copy import deepcopy
        self.base = demo_cycle(commit=False)
        self.prev = deepcopy(self.base.delta.prev)
        self.curr = deepcopy(self.base.delta.curr)
        self.kev = self.base.kev

    def delta(self):
        from exposure_radio.delta import compute_delta
        return compute_delta(self.prev, self.curr, self.kev, self.kev)

    def test_fixed_requires_current_scan_and_fresh_fixed_timestamp(self):
        from dataclasses import replace
        from datetime import timedelta
        from exposure_radio.delta import Kind
        f = next(f for f in self.curr.findings.values() if 'CVE-2023-4966' in f.cves)
        self.curr.assets[f.asset_id] = replace(self.curr.assets[f.asset_id], last_scan=self.curr.window_start - timedelta(days=1))
        self.assertIn(Kind.UNVERIFIED, [c.kind for c in self.delta().changes if c.finding.key == f.key])
        self.curr.assets[f.asset_id] = self.base.delta.curr.assets[f.asset_id]
        self.curr.findings[f.key] = replace(f, last_fixed=self.curr.window_start - timedelta(days=1))
        self.assertIn(Kind.UNVERIFIED, [c.kind for c in self.delta().changes if c.finding.key == f.key])

    def test_lost_credentials_leave_disappeared_finding_unverified(self):
        from dataclasses import replace
        from datetime import timedelta
        from exposure_radio.delta import Kind
        f = next(f for f in self.prev.findings.values() if 'CVE-2023-46604' in f.cves)
        self.assertTrue(self.prev.authenticated(f.asset_id))
        self.curr.assets[f.asset_id] = replace(self.curr.assets[f.asset_id], last_auth_scan=self.curr.window_start - timedelta(days=1))
        self.curr.findings.pop(f.key, None)
        self.assertIn(Kind.UNVERIFIED, [c.kind for c in self.delta().changes if c.finding.key == f.key])

    def test_new_credentials_are_visibility(self):
        from dataclasses import replace
        from datetime import timedelta
        from exposure_radio.delta import Kind
        f = next(f for f in self.curr.findings.values() if 'CVE-2024-3400' in f.cves)
        self.prev.findings.pop(f.key, None)
        self.prev.assets[f.asset_id] = replace(self.prev.assets[f.asset_id], last_auth_scan=self.prev.window_start - timedelta(days=1))
        self.curr.assets[f.asset_id] = replace(self.curr.assets[f.asset_id], last_auth_scan=self.curr.exported_at)
        d = self.delta()
        self.assertIn(Kind.NEW_VISIBILITY, [c.kind for c in d.changes if c.finding.key == f.key])
        self.assertIn(f.asset_id, d.new_assets)

    def test_incomplete_previous_does_not_invent_new_exposure(self):
        from exposure_radio.delta import Kind
        f = next(f for f in self.curr.findings.values() if 'CVE-2024-3400' in f.cves)
        self.prev.findings.pop(f.key, None)
        self.prev.complete = False
        d = self.delta()
        self.assertNotIn(Kind.NEW_EXPOSURE, [c.kind for c in d.changes if c.finding.key == f.key])
        self.assertTrue(d.health)

    def test_reopen_and_asset_subset_alert_memory(self):
        from exposure_radio.policy import Memory, decide
        from exposure_radio.delta import CveRollup
        d = self.delta()
        d.cves = {'CVE-2024-3400': CveRollup('CVE-2024-3400', severity='high', in_kev=True,
                      open_assets={'a', 'b'}, reopened_assets={'a'})}
        mem = Memory()
        first = decide(d, self.kev, mem)
        self.assertEqual(first.kind, 'BREAK_IN')
        mem.commit(first, d, self.kev)
        # Change evidence digest without changing the alert's known asset set.
        d.curr.sources['test'] = 'different'
        d.cves['CVE-2024-3400'].open_assets = {'a'}
        self.assertTrue(decide(d, self.kev, mem).alerts[0].duplicate)
        d.cves['CVE-2024-3400'].open_assets = {'a', 'c'}
        self.assertFalse(decide(d, self.kev, mem).alerts[0].duplicate)

    def test_api_error_chunk_is_incomplete(self):
        with TempCopy() as snap:
            (snap / 'vulns' / 'chunk-1.json').write_text(json.dumps({'statusCode': 429}))
            c = run_cycle(curr_dir=snap, commit=False)
            self.assertFalse(c.delta.curr.complete)

    def test_first_known_kev_alerts_without_scan_delta(self):
        from exposure_radio.policy import Memory, decide
        from exposure_radio.delta import CveRollup
        d = self.delta()
        d.cves = {'CVE-2024-3400': CveRollup('CVE-2024-3400', severity='high', in_kev=True, open_assets={'a'})}
        decision = decide(d, self.kev, Memory())
        self.assertEqual(decision.kind, 'BREAK_IN')
        self.assertEqual(decision.lead, 'CVE-2024-3400')


class ReopenedLifecycleTests(unittest.TestCase):
    def test_confirmed_fix_rearms_same_asset(self):
        from exposure_radio.pipeline import run_cycle
        from exposure_radio.policy import Memory, decide
        from exposure_radio.delta import CveRollup
        c = run_cycle(commit=False)
        d, memory = c.delta, Memory()
        def cycle(marker, **fields):
            d.curr.sources['lifecycle-test'] = marker
            d.cves = {'CVE-2024-3400': CveRollup('CVE-2024-3400', in_kev=True, severity='high', **fields)}
            decision = decide(d, c.kev, memory)
            memory.commit(decision, d, c.kev)
            return decision
        self.assertEqual(cycle('open', open_assets={'a'}).kind, 'BREAK_IN')
        cycle('fixed', fixed_assets={'a'})
        self.assertEqual(cycle('reopened', open_assets={'a'}, reopened_assets={'a'}).kind, 'BREAK_IN')
        self.assertNotEqual(cycle('unchanged-exposure', open_assets={'a'}).kind, 'BREAK_IN')
        memory.close()
