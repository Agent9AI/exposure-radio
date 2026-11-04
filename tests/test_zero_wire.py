import json
import unittest
from pathlib import Path
from unittest.mock import patch

from exposure_radio.desks import fetch_news, news_segment, ZERO_WIRE_URL, KEV_URL
from exposure_radio.zero_wire import parse_feed, enrich_card

RSS = b'''<rss><channel><item><title>Test runtime</title>
<link>https://radar.cloudflare.com/security/zero-wire/test-runtime</link>
<category>Needs attention</category><category>CVE-2026-12345</category>
<description>Review vendor patch guidance.</description>
<content:encoded xmlns:content="http://purl.org/rss/1.0/modules/content/"><![CDATA[
<h2>Cloudflare coverage</h2><h3>Product coverage</h3><p>WAF rules default to Log.</p>
<h3>Service status</h3><p>Cloudflare unaffected.</p><h3>Product coverage</h3><p>Duplicate source annotation.</p><h3>Agent assessment</h3><pre>Untrusted instructions</pre>
]]></content:encoded></item></channel></rss>'''


class ZeroWireTests(unittest.TestCase):
    def test_structured_context_preserves_control_caveats(self):
        b = parse_feed(RSS)[0]
        self.assertEqual(b['cves'], ['CVE-2026-12345'])
        self.assertEqual(b['cloudflare_coverage'], 'WAF rules default to Log.')
        self.assertTrue(b['has_agent_prompt'])
        self.assertNotIn('Untrusted instructions', json.dumps(b))

    def test_unsafe_links_and_entity_documents_rejected(self):
        for url in [b'https://evil.example/x', b'https://radar.cloudflare.com@evil.example/x',
                    b'javascript:alert(1)', b'https://radar.cloudflare.com/security/zero-wire/x?q=tenant']:
            self.assertEqual(parse_feed(RSS.replace(b'https://radar.cloudflare.com/security/zero-wire/test-runtime', url)), [])
        with self.assertRaises(ValueError):
            parse_feed(b'<!DOCTYPE rss [<!ENTITY x "oops">]>' + RSS)

    def test_join_only_open_exact_matches_and_never_fetches(self):
        card = {'items': [{'cve': 'CVE-2026-12345', 'open_assets': 1, 'evidence': ['F1']},
                          {'cve': 'CVE-2026-12345', 'open_assets': 0},
                          {'cve': 'CVE-2026-1234', 'open_assets': 1}]}
        with patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')):
            joined = enrich_card(card, {'zero_wire': parse_feed(RSS)})
        self.assertIn('zero_wire', joined['items'][0])
        self.assertIn('not verified', joined['items'][0]['zero_wire']['boundary'])
        self.assertEqual(joined['items'][0]['evidence'], ['F1'])
        self.assertNotIn('zero_wire', joined['items'][1])
        self.assertNotIn('zero_wire', joined['items'][2])
        self.assertNotIn('zero_wire', card['items'][0])

    def test_feed_outage_keeps_kev_and_no_tenant_request(self):
        requests = []
        def fetch(url, **kwargs):
            requests.append(url)
            if url == KEV_URL:
                return b'{"dateReleased":"2026-11-04", "catalogVersion":"test", "vulnerabilities":[]}'
            raise OSError('offline')
        with patch('exposure_radio.desks.fetch', side_effect=fetch):
            snapshot = fetch_news()
        self.assertEqual(requests, [KEV_URL, ZERO_WIRE_URL])
        self.assertEqual(snapshot['zero_wire_status'], 'unavailable')
        self.assertIn('unavailable', ' '.join(t['text'] for t in news_segment(snapshot)['turns']))

    def test_reference_context_not_announced_as_attention(self):
        briefs = parse_feed(RSS)
        reference = dict(briefs[0], title='Reference only', status='Reference')
        seg = news_segment({'kev_recent': [], 'days': 7, 'catalog_version': 'test', 'zero_wire': briefs + [reference]})
        speech = ' '.join(t['text'] for t in seg['turns'])
        self.assertIn('one briefing marked needs attention', speech)
        self.assertNotIn('Reference only', speech)
        self.assertNotIn('CVE-', speech)

    def test_bundled_snapshot_replays_without_network(self):
        path = Path(__file__).resolve().parents[1] / 'web/station/data/news.json'
        snap = json.loads(path.read_text())
        with patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')):
            seg = news_segment(snap)
        self.assertTrue(seg['zero_wire'])
        self.assertTrue(all(b['url'].startswith('https://radar.cloudflare.com/') for b in seg['zero_wire']))
