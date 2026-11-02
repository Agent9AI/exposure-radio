"""A stale or changed media artifact cannot accompany another script's receipt."""
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from scripts.build_site import BuildError, build

ROOT = Path(__file__).resolve().parents[1]


class SiteMediaTests(unittest.TestCase):
    def web_copy(self, directory):
        web = Path(directory) / 'web'
        shutil.copytree(ROOT / 'web' / 'assets', web / 'assets')
        return web

    def test_included_priority_break_matches_source(self):
        result = build(ROOT / 'web')
        episode = result['episode.json']
        self.assertTrue(episode['gate']['passed'])
        self.assertEqual(episode['gate']['sentences_checked'], 14)
        self.assertEqual(len(episode['lines']), 14)
        self.assertLessEqual(episode['media']['duration_seconds'], 90)
        self.assertEqual(episode['full_episode_gate']['sentences_checked'], 54)

    def test_changed_media_is_refused(self):
        for change in ('order', 'hash', 'receipt', 'caption', 'full-receipt'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                web = self.web_copy(directory)
                path = web / 'assets' / ('full-audio.json' if change == 'full-receipt' else 'audio.json')
                manifest = json.loads(path.read_text())
                if change == 'order':
                    manifest['line_indices'] = [1, 0]
                elif change == 'hash':
                    manifest['audio_sha256'] = '0' * 64
                else:
                    manifest['receipt']['script_sha256'] = '0' * 64
                if change == 'caption':
                    cues = web / 'assets' / 'cues.json'
                    data = json.loads(cues.read_text())
                    data[0]['text'] = 'Everything is safe.'
                    cues.write_text(json.dumps(data))
                    # Keep the valid receipt; the changed caption must be rejected itself.
                else:
                    path.write_text(json.dumps(manifest))
                with self.assertRaises(BuildError):
                    build(web)
