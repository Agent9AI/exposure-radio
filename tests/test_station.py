import json
import os
import re
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from exposure_radio import station
from exposure_radio.desks import learn_segment, learn_topics, news_segment, weather_segment
from exposure_radio.onair import BANTER, OnAirError, build_segments, verify_segment
from exposure_radio.pipeline import run_cycle
from exposure_radio.tenable_api import Client, TenableError, pull


def _segments():
    c = run_cycle(edition="executive", commit=False)
    today = c.ledger.clock.date()
    return c, build_segments(c.episode.lines, c.ledger, c.kev, c.decision.kind, today=today), today


class OnAirTests(unittest.TestCase):
    def test_spoken_lines_never_read_identifiers(self):
        _, segs, _ = _segments()
        spoken = [t["text"] for s in segs for t in s["turns"]]
        self.assertTrue(spoken)
        for text in spoken:
            self.assertNotRegex(text, r"CVE-\d")
            self.assertNotRegex(text, r"\b\d{1,3}\b", "small numbers are spoken as words")

    def test_captions_keep_the_identifier_once_per_line(self):
        _, segs, _ = _segments()
        priority = segs[0]
        self.assertTrue(priority["priority"])
        self.assertIn("Ivanti Connect Secure", " ".join(t["text"] for t in priority["turns"]))
        self.assertTrue(any(re.search(r"CVE-\d{4}-\d+", t["caption"]) for t in priority["turns"]))

    def test_watch_list_does_not_repeat_the_same_count(self):
        _, segs, _ = _segments()
        watch = [t["text"] for t in segs[1]["turns"]]
        for a, b in zip(watch, watch[1:]):
            na = re.search(r"\bon (\w+) assets?\b", a)
            nb = re.search(r"\bopen on (\w+) assets?\b", b)
            if na and nb:
                self.assertNotEqual(na.group(1), nb.group(1), f"repeated count: {a!r} then {b!r}")

    def test_four_tenable_segment_kinds(self):
        _, segs, _ = _segments()
        self.assertEqual([s["kind"] for s in segs], ["exposure", "exposure", "wins", "blindspots"])

    def test_drifted_spoken_line_is_refused(self):
        c, segs, today = _segments()
        seg = json.loads(json.dumps(segs[2]))
        for t in seg["turns"]:
            if t["template"] == "T_FIXED":
                t["text"] = t["text"].replace("Fourteen", "Forty")
        with self.assertRaises(OnAirError):
            verify_segment(seg, c.ledger, c.kev, today)

    def test_false_caption_is_refused_even_when_spoken_matches(self):
        c, segs, today = _segments()
        seg = json.loads(json.dumps(segs[2]))
        for t in seg["turns"]:
            if t["template"] == "T_FIXED":
                t["caption"] = t["caption"].replace("14", "40")
        with self.assertRaises(OnAirError):
            verify_segment(seg, c.ledger, c.kev, today)

    def test_unknown_connective_line_is_refused(self):
        c, segs, today = _segments()
        seg = json.loads(json.dumps(segs[0]))
        seg["turns"].insert(0, {"host": "avery", "text": "Everything is patched, relax.",
                                "caption": "Everything is patched, relax.", "banter": "exposure_open"})
        with self.assertRaises(OnAirError):
            verify_segment(seg, c.ledger, c.kev, today)

    def test_connective_lines_carry_no_facts(self):
        for host, text in BANTER.values():
            self.assertIn(host, ("avery", "cole"))
            self.assertNotRegex(text, r"\d|CVE-")


class DeskTests(unittest.TestCase):
    def test_weather_from_snapshot(self):
        snap = {"fetched": "2026-11-03T18:00-05:00", "place": "Washington, DC", "source": "https://api.weather.gov/x",
                "periods": [{"name": "Tonight", "isDaytime": False, "temperature": 53, "temperatureUnit": "F",
                             "shortForecast": "Patchy Fog", "windSpeed": "5 mph", "windDirection": "S"},
                            {"name": "Wednesday", "isDaytime": True, "temperature": 71, "temperatureUnit": "F",
                             "shortForecast": "Sunny", "windSpeed": "10 to 20 mph", "windDirection": "W"}],
                "alerts": [{"event": "Wind Advisory"}]}
        seg = weather_segment(snap, "Washington, DC")
        text = " ".join(t["text"] for t in seg["turns"])
        self.assertIn("low near fifty-three", text)
        self.assertIn("miles an hour", text)
        self.assertIn("a Wind Advisory", text)
        self.assertTrue(seg["sources"])

    def test_news_from_snapshot(self):
        snap = {"catalog_version": "2026.11.03", "days": 7, "advisories": [{"title": "Vendor X Controller",
                                                                         "link": "https://www.cisa.gov/a"}],
                "kev_recent": [{"cve": "CVE-2026-1", "vendor": "Cisco", "product": "Secure Firewall ASA and FTD",
                                "added": "2026-11-01", "ransomware": True}]}
        seg = news_segment(snap)
        text = " ".join(t["text"] for t in seg["turns"])
        self.assertIn("One vulnerability joined", text)
        self.assertIn("Cisco Secure Firewall ASA", text)
        self.assertIn("ransomware", text)
        self.assertNotIn("CVE-", text)

    def test_bundled_learn_topics_have_sources(self):
        topics = learn_topics()
        self.assertGreaterEqual(len(topics), 3)
        for topic in topics:
            seg = learn_segment(topic)
            self.assertTrue(seg["sources"])
            self.assertTrue(all(t["host"] in ("avery", "cole") for t in seg["turns"]))


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = station.Store(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_keys_are_masked_and_private(self):
        self.store.set_keys("gemini", {"api_key": "fixture-key"})
        settings = self.store.settings()
        self.assertEqual(settings["keys"]["gemini"], {"configured": True})
        self.assertNotIn("fixture-key", json.dumps(settings))
        self.assertEqual(stat.S_IMODE(os.stat(self.store.path).st_mode), 0o600)

    def test_settings_update_keeps_secrets(self):
        self.store.set_keys("gemini", {"api_key": "fixture-key"})
        self.store.update({"gemini": {"tier": "paid"}, "segments": {"music": {"enabled": False, "per_hour": 0}}})
        self.assertEqual(self.store.secret("gemini")["api_key"], "fixture-key")
        self.assertEqual(self.store.settings()["gemini"]["tier"], "paid")

    def test_rejects_unknown_or_bad_settings(self):
        for bad in ({"secrets": {}}, {"gemini": {"tier": "maybe"}}, {"segments": {"music": {"per_hour": 99}}},
                    {"tenable": {"host": "http://insecure"}}, {"priority_interrupts": "yes"}):
            with self.assertRaises(ValueError, msg=bad):
                self.store.update(bad)

    def test_exposure_stays_local_on_free_tier(self):
        self.store.set_keys("gemini", {"api_key": "fixture-key"})
        self.store.update({"voices": {"engine": "gemini"}})
        s = self.store.settings()
        self.assertTrue(station.cloud_voice_allowed(s, "news"))
        self.assertFalse(station.cloud_voice_allowed(s, "exposure"))
        s = self.store.update({"gemini": {"tier": "paid"}})
        self.assertTrue(station.cloud_voice_allowed(s, "exposure"))


class HostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        store = station.Store(Path(cls.tmp.name))
        handler = type("H", (station.Handler,), {"store": store, "token": "t0ken-for-tests",
                                                 "allowed_hosts": {"127.0.0.1", "localhost"}})
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None, token=None, host=None):
        req = urllib.request.Request(self.base + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None)
        if token:
            req.add_header("X-Admin-Token", token)
        if host:
            req.add_header("Host", host)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def test_station_document_is_served(self):
        status, doc = self.call("GET", "/api/station")
        self.assertEqual(status, 200)
        self.assertTrue(doc["rundown"])

    def test_writes_need_the_token(self):
        self.assertEqual(self.call("PUT", "/api/settings", {"gemini": {"tier": "paid"}})[0], 401)
        self.assertEqual(self.call("PUT", "/api/settings", {"gemini": {"tier": "paid"}}, "wrong")[0], 401)
        status, doc = self.call("PUT", "/api/settings", {"gemini": {"tier": "paid"}}, "t0ken-for-tests")
        self.assertEqual((status, doc["gemini"]["tier"]), (200, "paid"))

    def test_keys_never_come_back(self):
        status, keys = self.call("POST", "/api/keys", {"provider": "tenable", "values": {
            "access_key": "a" * 64, "secret_key": "b" * 64}}, "t0ken-for-tests")
        self.assertEqual((status, keys["tenable"]["configured"]), (200, True))
        _, settings = self.call("GET", "/api/settings")
        self.assertNotIn("a" * 64, json.dumps(settings))

    def test_rebinding_host_is_refused(self):
        self.assertEqual(self.call("GET", "/api/settings", host="evil.example")[0], 421)


class TenableApiTests(unittest.TestCase):
    def test_refuses_plain_http_and_missing_keys(self):
        with self.assertRaises(TenableError):
            Client("a", "b", "http://cloud.tenable.com")
        with self.assertRaises(TenableError):
            Client("", "", "https://cloud.tenable.com")

    def test_pull_writes_loader_layout(self):
        calls = []

        class Fake:
            def request(self, method, path, body=None):
                calls.append((method, path))
                if path == "/vulns/export":
                    return {"export_uuid": "v1"}
                if path == "/assets/export":
                    return {"export_uuid": "a1"}
                if path.endswith("/status"):
                    return {"status": "FINISHED", "chunks_available": [1]}
                if "/vulns/export/v1/chunks/" in path:
                    return [{"asset": {"uuid": "x"}, "plugin": {"id": 1}, "state": "OPEN"}]
                return [{"id": "x"}]

        with tempfile.TemporaryDirectory() as tmp:
            summary = pull(tmp, Fake(), poll=0)
            self.assertEqual((summary["findings"], summary["assets"]), (1, 1))
            for name in ("export-status.json", "assets.json", "vulns/chunk-1.json"):
                self.assertTrue((Path(tmp) / name).exists(), name)
        self.assertEqual(calls[0], ("POST", "/vulns/export"))
        self.assertTrue(all(m in ("GET", "POST") for m, _ in calls))


if __name__ == "__main__":
    unittest.main()
