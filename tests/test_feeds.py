import gzip
import json
import os
import tempfile
import unittest

from exposure_radio import feeds

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDS = os.path.join(ROOT, "data", "feeds")

EPSS_CSV = (
    "#model_version:v2025.03.14,score_date:2026-10-30T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2024-3400,0.94321,0.99987\n"
    "CVE-2026-110447,0.12345,0.95000\n"
    "CVE-BAD,0.5,0.5\n"
    "CVE-2024-6387,1.5,0.5\n"
)


class SnapshotTests(unittest.TestCase):
    def test_bundled_kev_snapshot_loads(self):
        snap = feeds.KevSnapshot.load(os.path.join(FEEDS, "kev.json"))
        self.assertEqual(len(snap.entries), 7)
        entry = snap.get("CVE-2024-3400")
        self.assertEqual(entry.vendor, "Palo Alto Networks")
        self.assertEqual(entry.date_added, "2024-04-12")
        self.assertEqual(entry.due_date, "2024-04-19")
        self.assertIs(entry.ransomware, True)
        self.assertIsNone(snap.get("CVE-2026-110447").ransomware)  # unverified field left out, not guessed
        self.assertEqual([e.cve for e in snap.added_between("2026-10-20", "2026-10-27")], ["CVE-2026-110447"])
        self.assertEqual(snap.added_between("2026-10-24", "2026-10-27"), [])

    def test_kev_schema_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "kev.json")
            with open(path, "w") as handle:
                json.dump([1, 2], handle)
            with self.assertRaises(ValueError):
                feeds.KevSnapshot.load(path)

    def test_epss_csv_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "epss.csv")
            with open(path, "w") as handle:
                handle.write(EPSS_CSV)
            snap = feeds.EpssSnapshot.load(path)
        self.assertEqual(snap.model_version, "v2025.03.14")
        self.assertEqual(snap.score_date, "2026-10-30")
        self.assertEqual(snap.score("CVE-2024-3400"), 0.94321)
        self.assertEqual(snap.percentile("CVE-2024-3400"), 0.99987)
        self.assertIsNone(snap.score("CVE-BAD"))
        self.assertIsNone(snap.score("CVE-2024-6387"))  # out of range score dropped

    def test_epss_gzip_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "epss.csv.gz")
            with gzip.open(path, "wb") as handle:
                handle.write(EPSS_CSV.encode())
            snap = feeds.EpssSnapshot.load(path)
        self.assertEqual(len(snap.scores), 2)

    def test_research_snapshot_accepts_only_tenable_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "r.json")
            with open(path, "w") as handle:
                json.dump(
                    {
                        "captured": "2026-11-02",
                        "items": [
                            {"id": "ok", "title": "T", "published": "2025-07-20", "url": "https://www.tenable.com/blog/x", "cves": ["CVE-2025-53770"]},
                            {"id": "bad", "title": "T", "published": "2025-07-20", "url": "https://evil.example/blog/x", "cves": ["CVE-2025-53770"]},
                        ],
                    },
                    handle,
                )
            snap = feeds.ResearchSnapshot.load(path)
        self.assertEqual([p.pub_id for p in snap.items], ["ok"])
        self.assertEqual(len(snap.for_cve("CVE-2025-53770")), 1)

    def test_load_feeds_builds_ledger(self):
        loaded = feeds.load_feeds(FEEDS)
        ids = set(loaded.ledger.sources)
        self.assertIn("kev:subset-2026.11.02", ids)
        self.assertTrue(any(i.startswith("tenable-research:") for i in ids))
        self.assertFalse(any(i.startswith("epss:") for i in ids))  # no EPSS snapshot committed
        kev_source = loaded.ledger.get("kev:subset-2026.11.02")
        self.assertEqual(kev_source.coverage, "subset")
        self.assertEqual(len(kev_source.sha256), 64)

    def test_feed_size_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "big.json")
            with open(path, "wb") as handle:
                handle.write(b"0" * 10)
            original = feeds.MAX_FEED_BYTES
            feeds.MAX_FEED_BYTES = 5
            try:
                with self.assertRaises(ValueError):
                    feeds.KevSnapshot.load(path)
            finally:
                feeds.MAX_FEED_BYTES = original


class RefreshTests(unittest.TestCase):
    def test_refresh_validates_before_replacing(self):
        kev_json = json.dumps(
            {
                "title": "t",
                "catalogVersion": "2026.10.30",
                "dateReleased": "2026-10-30T15:00:00.0000Z",
                "count": 1,
                "vulnerabilities": [
                    {"cveID": "CVE-2024-3400", "vendorProject": "Palo Alto Networks", "product": "PAN-OS", "vulnerabilityName": "n", "dateAdded": "2024-04-12", "dueDate": "2024-04-19", "knownRansomwareCampaignUse": "Known"}
                ],
            }
        ).encode()
        responses = {
            feeds.DEFAULT_URLS["kev"]: kev_json,
            feeds.DEFAULT_URLS["epss"]: gzip.compress(EPSS_CSV.encode()),
        }
        with tempfile.TemporaryDirectory() as tmp:
            summary = feeds.refresh(tmp, fetch=lambda url: responses[url])
            self.assertIn("1 entries", summary["kev"])
            self.assertIn("2026-10-30", summary["epss"])
            loaded = feeds.load_feeds(tmp)
            self.assertEqual(loaded.kev.catalog_version, "2026.10.30")
            self.assertEqual(loaded.epss.score_date, "2026-10-30")
            self.assertIn("epss:2026-10-30", loaded.ledger.sources)
            with open(os.path.join(tmp, "MANIFEST.json"), encoding="utf-8") as handle:
                manifest = json.load(handle)
            self.assertEqual(manifest["kev"]["coverage"], "full")

            # a broken download must not clobber the good snapshot
            with self.assertRaises(ValueError):
                feeds.refresh(tmp, fetch=lambda url: b"not json at all" if url == feeds.DEFAULT_URLS["kev"] else responses[url])
            self.assertEqual(feeds.load_feeds(tmp).kev.catalog_version, "2026.10.30")

    def test_refresh_refuses_plain_http(self):
        with self.assertRaises(ValueError):
            feeds._default_fetch("http://example.invalid/feed.json")


if __name__ == "__main__":
    unittest.main()
