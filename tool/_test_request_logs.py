import json
import tempfile
import unittest
from pathlib import Path

from defence import request_logs, waf_manager


class RequestLogsTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.log = self.directory / "test.http"

    def summary(self):
        return request_logs.summarize_request(str(self.log), self.log.stat().st_mtime_ns)

    def test_legacy_log_still_shows_request_and_unknown_disposition(self):
        raw = b"GET /notes?name=hello%20world HTTP/1.1\r\nHost: local.test\r\n\r\n"
        self.log.write_bytes(raw)
        summary = self.summary()
        self.assertEqual(summary["target"], "/notes?name=hello%20world")
        self.assertEqual(summary["decision"], "unknown")
        self.assertIsNone(summary["peer"])
        self.assertEqual(waf_manager.read_local_request_log(self.log), raw.decode().replace("\r\n", "\n"))

    def test_capture_can_be_filtered_and_exported_without_reencoding(self):
        metadata = {
            "captured_at": 1762000700,
            "peer_ip": "2001:db8::1",
            "decision": "matched",
            "matched_areas": ["headers", "raw_body"],
            "body_state": "captured",
        }
        raw = b"POST /notes HTTP/1.1\r\n\r\n" + b"\x00\xff" + b"x" * request_logs.PREVIEW_BYTES
        self.log.write_bytes(request_logs.CAPTURE_PREFIX + json.dumps(metadata).encode() + b"\r\n" + raw)
        summary = self.summary()
        self.assertEqual(summary["peer"], "2001:db8::1")
        self.assertEqual(summary["matchedAreas"], ["headers", "raw_body"])
        preview = request_logs.read_request_preview(self.log)
        self.assertTrue(preview["truncated"])
        self.assertTrue(preview["hasBinary"])
        self.assertTrue(preview["text"].startswith("POST /notes"))
        destination = self.directory / "export.http"
        request_logs.export_request(self.log, destination)
        self.assertEqual(destination.read_bytes(), raw)
        with self.assertRaises(ValueError):
            request_logs.export_request(self.log, self.log)

    def test_damaged_metadata_does_not_hide_the_request(self):
        raw = b"GET /status HTTP/1.1\r\n\r\n"
        self.log.write_bytes(request_logs.CAPTURE_PREFIX + b"{}invalid\n" + raw)
        self.assertEqual(self.summary()["decision"], "unknown")
        self.assertEqual(request_logs.read_request_preview(self.log)["text"], raw.decode())


if __name__ == "__main__":
    unittest.main()
