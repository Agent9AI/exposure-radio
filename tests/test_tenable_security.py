import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

from exposure_radio.tenable_api import Client, TenableError, pull


class TenableSecurityTests(unittest.TestCase):
    def test_only_official_origin(self):
        for host in ('https://evil.example', 'https://cloud.tenable.com.evil.example',
                     'https://cloud.tenable.com@evil.example', 'https://cloud.tenable.com/path'):
            with self.subTest(host=host), self.assertRaises(TenableError):
                Client('access', 'secret', host)
        Client('access', 'secret', 'https://cloud.tenable.com')

    def test_redirect_handler_never_follows(self):
        from exposure_radio.tenable_api import _NoRedirect
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, '', {}, 'https://evil.example'))

    def test_export_permissions_with_permissive_umask(self):
        class Fake:
            def request(self, method, path, body=None):
                if path.endswith('/export'): return {'export_uuid': 'id'}
                if path.endswith('/status'): return {'status': 'FINISHED', 'chunks_available': [1]}
                return []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'snapshot'
            old = os.umask(0)
            try: pull(root, Fake())
            finally: os.umask(old)
            for path in (root, root / 'vulns'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
            for path in (root / 'assets.json', root / 'export-status.json', root / 'vulns/chunk-1.json'):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
