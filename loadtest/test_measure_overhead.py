import tempfile
import unittest
from pathlib import Path

from measure_overhead import RunStats, _parse_stats_csv

STATS_CSV = """Type,Name,Request Count,Failure Count,Median Response Time,Average Response Time,Min Response Time,Max Response Time,Average Content Size,Requests/s,Failures/s,50%,66%,75%,80%,90%,95%,98%,99%,99.9%,99.99%,100%
GET,/api/health/,120,0,8,11.8,3,45,32,12.0,0.0,8,10,12,13,17,21,30,40,45,45,45
,Aggregated,120,0,8,11.8,3,45,32,12.0,0.0,8,10,12,13,17,21,30,40,45,45,45
"""


class ParseStatsCsvTests(unittest.TestCase):
    def test_reads_the_aggregated_row(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "stats.csv"
            csv_path.write_text(STATS_CSV, encoding="utf-8")

            stats = _parse_stats_csv(csv_path)

        self.assertEqual(
            stats,
            RunStats(
                request_count=120, failure_count=0, average_ms=11.8, median_ms=8.0, p95_ms=21.0
            ),
        )

    def test_raises_when_no_aggregated_row_is_present(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "stats.csv"
            csv_path.write_text(STATS_CSV.splitlines()[0] + "\n", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                _parse_stats_csv(csv_path)


if __name__ == "__main__":
    unittest.main()
