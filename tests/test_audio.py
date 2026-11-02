import math
import os
import shutil
import struct
import tempfile
import unittest
import wave

from exposure_radio.audio import lexicon, loudness, vtt

EBUR_STDERR = """
[Parsed_ebur128_0 @ 0x1] Summary:

  Integrated loudness:
    I:         -16.2 LUFS
    Threshold: -26.6 LUFS

  Loudness range:
    LRA:         6.1 LU
    Threshold: -36.7 LUFS
    LRA low:   -20.4 LUFS
    LRA high:  -14.3 LUFS

  True peak:
    Peak:       -1.4 dBFS
"""

LOUDNORM_STDERR = """
[Parsed_loudnorm_0 @ 0x2]
{
\t"input_i" : "-23.45",
\t"input_tp" : "-6.21",
\t"input_lra" : "5.90",
\t"input_thresh" : "-33.70",
\t"output_i" : "-16.01",
\t"output_tp" : "-1.50",
\t"output_lra" : "5.80",
\t"output_thresh" : "-26.20",
\t"normalization_type" : "dynamic",
\t"target_offset" : "0.01"
}
"""


class LexiconTests(unittest.TestCase):
    def test_cve_spoken_form(self):
        self.assertEqual(lexicon.spoken_cve("CVE-2026-110447"), "C V E twenty twenty-six, one one zero, four four seven")
        self.assertEqual(lexicon.spoken_cve("CVE-2024-3400"), "C V E twenty twenty-four, three four, zero zero")
        self.assertEqual(lexicon.spoken_cve("CVE-2025-53770"), "C V E twenty twenty-five, five three, seven seven zero")
        self.assertEqual(lexicon.spoken_cve("not a cve"), "not a cve")

    def test_years(self):
        self.assertEqual(lexicon.spoken_year(1999), "nineteen ninety-nine")
        self.assertEqual(lexicon.spoken_year(2000), "two thousand")
        self.assertEqual(lexicon.spoken_year(2007), "two thousand seven")
        self.assertEqual(lexicon.spoken_year(2010), "twenty ten")
        self.assertEqual(lexicon.spoken_year(2026), "twenty twenty-six")
        self.assertEqual(lexicon.spoken_year(2100), "twenty-one hundred")

    def test_sentence_spoken_form_with_bundled_lexicon(self):
        terms = lexicon.load_lexicon()
        self.assertIn("KEV", terms)
        spoken = lexicon.spoken_form(
            "CVE-2024-3400 affects Palo Alto Networks PAN-OS and has been on the CISA KEV catalogue since 12 April 2024.", terms
        )
        self.assertEqual(
            spoken,
            "C V E twenty twenty-four, three four, zero zero affects Palo Alto Networks pan O S and has been on the sissa K E V catalogue since 12 April twenty twenty-four.",
        )
        self.assertEqual(lexicon.spoken_form("5 KEV-listed CVEs", terms), "5 K E V listed CVEs")
        self.assertEqual(lexicon.spoken_form("EPSS puts it at 94.3 percent.", terms), "E P S S puts it at 94.3 percent.")

    def test_missing_lexicon_file_is_empty(self):
        self.assertEqual(lexicon.load_lexicon("/nonexistent/lexicon.json"), {})


class VttTests(unittest.TestCase):
    def test_round_trip(self):
        cues = [(0.0, 1.25, "This is Exposure Radio."), (1.7, 4.0, "Lead item: CVE-2026-110447 --> be careful.")]
        text = vtt.build_vtt(cues, notes=["gate receipt sha256 abc"])
        self.assertTrue(text.startswith("WEBVTT\n\nNOTE gate receipt sha256 abc"))
        self.assertIn("00:00:00.000 --> 00:00:01.250", text)
        parsed = vtt.parse_vtt(text)
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0][2], "This is Exposure Radio.")
        self.assertNotIn("-->", parsed[1][2])
        self.assertAlmostEqual(parsed[1][0], 1.7, places=3)

    def test_timestamp_formatting(self):
        self.assertEqual(vtt.format_timestamp(3661.5), "01:01:01.500")
        self.assertEqual(vtt.format_timestamp(0.9996), "00:00:01.000")
        self.assertEqual(vtt.format_timestamp(-1), "00:00:00.000")


class LoudnessParsingTests(unittest.TestCase):
    def test_parse_ebur128(self):
        parsed = loudness.parse_ebur128_summary(EBUR_STDERR)
        self.assertEqual(parsed["integrated_lufs"], -16.2)
        self.assertEqual(parsed["true_peak_dbtp"], -1.4)
        self.assertEqual(parsed["lra_lu"], 6.1)
        self.assertTrue(loudness.within_targets(parsed))
        self.assertFalse(loudness.within_targets({"integrated_lufs": -18.0, "true_peak_dbtp": -1.4}))
        self.assertFalse(loudness.within_targets({"integrated_lufs": -16.0, "true_peak_dbtp": -0.5}))
        with self.assertRaises(ValueError):
            loudness.parse_ebur128_summary("nothing here")

    def test_parse_loudnorm_json(self):
        parsed = loudness.parse_loudnorm_json(LOUDNORM_STDERR)
        self.assertEqual(parsed["input_i"], "-23.45")
        self.assertEqual(parsed["target_offset"], "0.01")


@unittest.skipUnless(shutil.which("ffmpeg"), "ffmpeg not installed")
class LoudnessFfmpegTests(unittest.TestCase):
    def test_measure_and_normalise_a_tone(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = os.path.join(tmp, "tone.wav")
            with wave.open(src, "wb") as handle:
                handle.setnchannels(1)
                handle.setsampwidth(2)
                handle.setframerate(24000)
                frames = bytearray()
                for i in range(24000 * 3):
                    frames += struct.pack("<h", int(6000 * math.sin(2 * math.pi * 440 * i / 24000)))
                handle.writeframes(bytes(frames))
            before = loudness.measure(src)
            self.assertIn("integrated_lufs", before)
            dst = os.path.join(tmp, "norm.wav")
            loudness.normalise(src, dst)
            after = loudness.measure(dst)
            self.assertTrue(loudness.within_targets(after, tolerance_lu=1.5), after)
            mp3 = os.path.join(tmp, "tone.mp3")
            loudness.encode_mp3(dst, mp3)
            self.assertGreater(os.path.getsize(mp3), 1000)
            self.assertIsNotNone(loudness.duration_seconds(mp3))


if __name__ == "__main__":
    unittest.main()
