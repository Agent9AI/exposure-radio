import unittest

from exposure_radio import sanitize


class CleanTextTests(unittest.TestCase):
    def test_strips_markup_and_shell_characters(self):
        dirty = 'SSL Self-Signed Certificate <img src=x onerror="alert(1)">; drop table findings; --'
        clean = sanitize.clean_name(dirty)
        for ch in "<>\";`$":
            self.assertNotIn(ch, clean)
        self.assertIn("SSL Self-Signed Certificate", clean)

    def test_caps_length_and_collapses_whitespace(self):
        clean = sanitize.clean_name("a   b\t\tc" + "x" * 500)
        self.assertTrue(clean.startswith("a b c"))
        self.assertLessEqual(len(clean), sanitize.MAX_NAME_LEN)

    def test_nfkc_folds_fullwidth_lookalikes(self):
        self.assertEqual(sanitize.clean_name("ＡＢＣ１２３"), "ABC123")

    def test_control_characters_removed(self):
        self.assertEqual(sanitize.clean_name("evil\x00name\x1b[31m"), "evil name 31m")


class HostnameAndIpTests(unittest.TestCase):
    def test_valid_hostname_lowercased(self):
        self.assertEqual(sanitize.clean_hostname("Web-01.Northwind.INTERNAL."), "web-01.northwind.internal")

    def test_invalid_hostnames_rejected(self):
        for bad in ("", "-bad.example", "under_score.example", "a" * 300, "space here", "<script>"):
            self.assertIsNone(sanitize.clean_hostname(bad), bad)

    def test_ip_addresses(self):
        self.assertEqual(sanitize.clean_ip("10.20.0.1"), "10.20.0.1")
        self.assertEqual(sanitize.clean_ip("::1"), "::1")
        self.assertIsNone(sanitize.clean_ip("999.1.1.1"))
        self.assertIsNone(sanitize.clean_ip("10.20.0.1; rm -rf /"))


class IdentifierTests(unittest.TestCase):
    def test_cve_canonical_form(self):
        self.assertEqual(sanitize.clean_cve(" cve-2024-3400 "), "CVE-2024-3400")
        self.assertIsNone(sanitize.clean_cve("CVE-24-3400"))
        self.assertIsNone(sanitize.clean_cve("CVE-2024-3400; DROP"))
        self.assertIsNone(sanitize.clean_cve("CVE-1980-0001"))

    def test_extract_cves_from_string_and_list(self):
        self.assertEqual(sanitize.extract_cves("CVE-2024-3400, cve-2023-4966 and junk"), ("CVE-2023-4966", "CVE-2024-3400"))
        self.assertEqual(sanitize.extract_cves(["CVE-2024-3400", "CVE-2024-3400", 12]), ("CVE-2024-3400",))
        self.assertEqual(sanitize.extract_cves(None), ())

    def test_numbers_and_bounds(self):
        self.assertEqual(sanitize.to_int("443", 0, 65535), 443)
        self.assertIsNone(sanitize.to_int("70000", 0, 65535))
        self.assertIsNone(sanitize.to_int(True, 0, 10))
        self.assertEqual(sanitize.to_float("9.8", 0, 10), 9.8)
        self.assertIsNone(sanitize.to_float("nan", 0, 10))
        self.assertIsNone(sanitize.to_float("11", 0, 10))

    def test_bool_and_severity(self):
        self.assertIs(sanitize.to_bool("true"), True)
        self.assertIs(sanitize.to_bool("No"), False)
        self.assertIsNone(sanitize.to_bool("maybe"))
        self.assertEqual(sanitize.clean_severity("Critical"), 4)
        self.assertEqual(sanitize.clean_severity(2), 2)
        self.assertIsNone(sanitize.clean_severity("extreme"))

    def test_dates(self):
        self.assertEqual(sanitize.clean_datetime("2026-10-27T02:11:52.000Z"), "2026-10-27T02:11:52Z")
        self.assertEqual(sanitize.clean_date("Mon Oct 27 02:11:52 2026"), "2026-10-27")
        self.assertEqual(sanitize.clean_date(1761530000), "2025-10-27")
        self.assertIsNone(sanitize.clean_date("yesterday"))
        self.assertIsNone(sanitize.clean_date("3000-01-01"))


if __name__ == "__main__":
    unittest.main()
