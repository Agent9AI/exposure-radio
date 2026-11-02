import os
import unittest

from exposure_radio import bench
from tests.common import FIX

BENCH_CURRENT = os.path.join(FIX, "bench", "current_500.json")
BENCH_PREVIOUS = os.path.join(FIX, "bench", "previous_500.json")


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = bench.run_benchmark(BENCH_CURRENT, BENCH_PREVIOUS, runs=2)

    def test_fixture_is_the_documented_size(self):
        counts = self.report["counts"]
        self.assertGreaterEqual(counts["raw_rows_both_exports"], 1000)
        self.assertGreaterEqual(counts["deduped_pairs_compared"], 500)
        self.assertGreaterEqual(counts["unique_cves"], 8)
        self.assertGreater(counts["assets_not_rescanned"], 0)
        self.assertEqual(counts["priority_tickets"], 3)

    def test_measurement_and_model_are_separated(self):
        self.assertEqual(self.report["runs"], 2)
        self.assertEqual(len(self.report["pipeline_seconds"]["all"]), 2)
        self.assertTrue(self.report["gate_passed"])
        self.assertGreater(self.report["manual_total_seconds"], self.report["tool_total_seconds"])
        self.assertEqual(self.report["manual_unit_seconds"], bench.MANUAL_UNIT_SECONDS)
        self.assertIn("MANUAL_TRIAGE.md", self.report["note"])
        self.assertAlmostEqual(
            self.report["manual_total_seconds"],
            sum(self.report["manual_step_seconds"].values()),
            places=0,
        )

    def test_report_renders(self):
        text = bench.render_report(self.report)
        self.assertIn("Prep time saved", text)
        self.assertIn("not remediation time", text)
        self.assertIn("Pipeline wall-clock over 2 runs", text)


if __name__ == "__main__":
    unittest.main()
