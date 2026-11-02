import copy
import unittest
from exposure_radio.audio import AudioError, verify_speech
from exposure_radio.gate import script_sha256
from tests.helpers import demo_cycle


class AudioGateTests(unittest.TestCase):
    def setUp(self):
        cycle = demo_cycle()
        self.ledger = cycle.ledger
        self.lines = copy.deepcopy(cycle.episode.lines)
        self.receipt = cycle.episode.gate.receipt()

    def test_valid_receipt(self):
        self.assertTrue(verify_speech(self.lines, self.receipt, self.ledger).passed)

    def test_tampered_text_and_voice_rejected(self):
        for key, value in [('text', 'Everything is safe.'), ('voice', 'ANALYST')]:
            lines = copy.deepcopy(self.lines)
            lines[0][key] = value
            with self.subTest(key=key), self.assertRaises(AudioError):
                verify_speech(lines, self.receipt, self.ledger)

    def test_forged_digest_does_not_authorize_false_text(self):
        self.lines[0]['text'] = 'Everything is safe.'
        self.receipt['script_sha256'] = script_sha256(self.lines)
        with self.assertRaises(AudioError):
            verify_speech(self.lines, self.receipt, self.ledger)

    def test_forged_receipt_fields_and_blank_line_rejected(self):
        self.receipt['sentences_checked'] += 1
        with self.assertRaises(AudioError):
            verify_speech(self.lines, self.receipt, self.ledger)
        self.lines[0]['text'] = ' '
        self.receipt['script_sha256'] = script_sha256(self.lines)
        with self.assertRaises(AudioError):
            verify_speech(self.lines, self.receipt, self.ledger)


    def test_changed_citation_cannot_reuse_speech_receipt(self):
        self.lines[0]['cites'] = ['F999']
        with self.assertRaises(AudioError):
            verify_speech(self.lines, self.receipt, self.ledger)
