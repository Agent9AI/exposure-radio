import unittest

from exposure_radio import textaudit
from exposure_radio.facts import FactStore
from exposure_radio.model import Asset, Export, Finding


def store_with_cve():
    store = FactStore()
    store.add("cve:CVE-2024-3400", "open_asset_count", 2, "export:current")
    return store


def forbidden_terms():
    export = Export(label="current", source="x", format="tenable-json")
    export.assets["u1"] = Asset("3f2b7a1e-1111-4222-8333-444455556666", hostname="fw-edge-01", fqdn="fw-edge-01.northwind.internal", ipv4="10.20.0.1")
    export.findings.append(Finding("u1", 193255, "Palo Alto Networks PAN-OS Command Injection", 4))
    return textaudit.ForbiddenTerms.from_exports(export, None)


def codes(sentence, forbidden=None, store=None):
    return sorted({i.code for i in textaudit.audit_sentences([sentence], store or store_with_cve(), forbidden)})


class SentenceChecks(unittest.TestCase):
    def test_clean_sentence(self):
        self.assertEqual(codes("CVE-2024-3400 is open on 2 assets."), [])

    def test_number_words(self):
        self.assertIn(textaudit.NUMBER_WORD, codes("CVE-2024-3400 is open on twenty assets."))
        self.assertIn(textaudit.NUMBER_WORD, codes("Several assets are affected."))

    def test_negation(self):
        self.assertIn(textaudit.NEGATION, codes("CVE-2024-3400 is not listed on KEV."))
        self.assertIn(textaudit.NEGATION, codes("There is no exposure."))
        self.assertIn(textaudit.NEGATION, codes("The host isn't affected."))

    def test_all_clear(self):
        for text in ("All clear.", "Everything is safe.", "Nothing to do today.", "The estate is fully patched.", "No action required."):
            self.assertIn(textaudit.ALL_CLEAR, codes(text), text)

    def test_directives(self):
        for text in ("Disable monitoring on the web tier.", "Ignore the finding.", "Accept the risk and skip the patch.", "Whitelist the scanner."):
            self.assertIn(textaudit.DIRECTIVE, codes(text), text)
        self.assertNotIn(textaudit.DIRECTIVE, codes("Action: Network Engineering to patch CVE-2024-3400 by 31 October 2026."))

    def test_unknown_cve(self):
        self.assertIn(textaudit.UNKNOWN_CVE, codes("CVE-2031-99999 is open on 3 assets."))

    def test_identifier_dictionary(self):
        fb = forbidden_terms()
        self.assertIn(textaudit.IDENTIFIER_LEAK, codes("fw-edge-01 is affected.", fb))
        self.assertIn(textaudit.IDENTIFIER_LEAK, codes("FW-EDGE-01.NORTHWIND.INTERNAL is affected.", fb))
        self.assertIn(textaudit.IDENTIFIER_LEAK, codes("Host 10.20.0.1 is affected.", fb))
        self.assertIn(textaudit.ASSET_ID_LEAK, codes("Asset 3f2b7a1e-1111-4222-8333-444455556666 is affected.", fb))
        self.assertIn(textaudit.PLUGIN_TEXT_LEAK, codes("Palo Alto Networks PAN-OS Command Injection detected.", fb))

    def test_shape_based_leaks_without_dictionary(self):
        self.assertIn(textaudit.HOSTNAME_LEAK, codes("db-01.corp.example is affected."))
        self.assertIn(textaudit.IP_LEAK, codes("192.168.1.10 is affected."))
        self.assertIn(textaudit.IP_LEAK, codes("fd00:1234::1 is affected."))
        self.assertNotIn(textaudit.HOSTNAME_LEAK, codes("EPSS puts CVE-2024-3400 at 94.3 percent probability of exploitation within 30 days."))
        self.assertNotIn(textaudit.IP_LEAK, codes("EPSS puts CVE-2024-3400 at 94.3 percent probability of exploitation within 30 days."))

    def test_hygiene(self):
        self.assertIn(textaudit.EMPTY, codes("   "))
        self.assertIn(textaudit.CONTROL, codes("CVE-2024-3400 is open\x07."))
        self.assertIn(textaudit.LENGTH, codes("CVE-2024-3400 " + "word " * 120))
        self.assertIn(textaudit.EMPTY, sorted({i.code for i in textaudit.audit_sentences([], store_with_cve())}))


class StructureChecks(unittest.TestCase):
    def test_injected_sentence_fails_structure(self):
        from exposure_radio.templates import Segment

        store = store_with_cve()
        segments = [Segment("intro.station")]
        sentences = ["This is Exposure Radio.", "CVE-2024-3400 is fixed on 20 assets."]
        issues = textaudit.audit_sentences(sentences, store, None, segments)
        self.assertIn(textaudit.STRUCTURE, {i.code for i in issues})

    def test_modified_sentence_fails_structure(self):
        from exposure_radio.templates import Segment

        store = store_with_cve()
        issues = textaudit.audit_sentences(["This is Exposure Radio, probably."], store, None, [Segment("intro.station")])
        self.assertIn(textaudit.STRUCTURE, {i.code for i in issues})

    def test_segment_with_bad_claim_fails_structure(self):
        from exposure_radio.claims import Claim
        from exposure_radio.templates import Segment

        store = store_with_cve()
        seg = Segment("cve.lead", (Claim("cve:CVE-2024-3400", "priority_rank", 1, "f9"), Claim("cve:CVE-2024-3400", "severity", "critical", "f9"), Claim("cve:CVE-2024-3400", "open_asset_count", 2, "f0001")))
        issues = textaudit.audit_sentences(["Lead item: CVE-2024-3400, critical severity, open on 2 assets."], store, None, [seg])
        self.assertIn(textaudit.STRUCTURE, {i.code for i in issues})


class FreeTextChecks(unittest.TestCase):
    def test_citation_hosts_allowed_but_tenant_names_not(self):
        fb = forbidden_terms()
        clean = "See https://nvd.nist.gov/vuln/detail/CVE-2024-3400 and https://www.tenable.com/plugins/nessus/193255"
        self.assertEqual(textaudit.audit_free_text(clean, fb), [])
        leak = clean + " on fw-edge-01.northwind.internal"
        self.assertTrue(any(i.code in (textaudit.IDENTIFIER_LEAK, textaudit.HOSTNAME_LEAK) for i in textaudit.audit_free_text(leak, fb)))

    def test_template_ids_and_file_names_are_not_hostnames(self):
        self.assertEqual(textaudit.audit_free_text('{"templates_used": ["cve.action", "episode.date"], "path": "data/fixtures/current.json"}'), [])

    def test_cve_flag_for_alerts(self):
        issues = textaudit.audit_free_text("Patch CVE-2024-3400 now", None, allow_cves=False)
        self.assertEqual([i.code for i in issues], [textaudit.CVE_PRESENT])


if __name__ == "__main__":
    unittest.main()
