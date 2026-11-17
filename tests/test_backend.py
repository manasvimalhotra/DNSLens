import tempfile
import unittest
from unittest import mock

import dns.exception

from backend import dns_engine
from backend.experiment import FIELDS, run_experiment


class FakeResponse:
    def rcode(self):
        return 0
    answer = []


class BackendTests(unittest.TestCase):
    def test_query_is_type_a(self):
        q = dns_engine.build_query("example.com")
        self.assertEqual(q.question[0].rdtype, 1)  # A

    def test_success_row_has_fields(self):
        with mock.patch.object(dns_engine, "_send", return_value=FakeResponse()):
            r = dns_engine.query_once("DoT", "example.com")
        self.assertTrue(r["request_success"])
        self.assertEqual(r["dns_rcode"], "NOERROR")
        self.assertGreaterEqual(r["elapsed_ms"], 0)

    def test_timeout_is_failed_row(self):
        with mock.patch.object(dns_engine, "_send", side_effect=dns.exception.Timeout()):
            r = dns_engine.query_once("DNS-UDP", "example.com", 1.0)
        self.assertFalse(r["request_success"])
        self.assertIn("Timeout", r["error"])

    def test_unexpected_error_does_not_raise(self):
        with mock.patch.object(dns_engine, "_send", side_effect=OSError("blocked")):
            r = dns_engine.query_once("DoH", "example.com")
        self.assertFalse(r["request_success"])
        self.assertIn("OSError", r["error"])

    def test_runner_row_count_fields_and_rotation(self):
        with mock.patch.object(dns_engine, "_send", return_value=FakeResponse()), tempfile.TemporaryDirectory() as tmp:
            rows = run_experiment(["a.com", "b.com", "A.com", ""], 5, "test", out_dir=tmp)
        self.assertEqual(len(rows), 2 * 3 * 5)  # duplicates/blanks removed
        self.assertEqual(set(rows[0]), set(FIELDS))
        firsts = {rows[i]["protocol"] for i in range(0, len(rows), 3)}
        self.assertGreater(len(firsts), 1)  # UDP is not always first


if __name__ == "__main__":
    unittest.main()
