import unittest
from io import BytesIO

from logscan_web.app import app
from logscan_web.scanner import ScanError, _plain_title, scan_log


VALID_LOG = b"\n".join(
    [
        b"[2026-01-01 00:00:00,000] [kometa.py:1] [INFO] | Version: 2.2.0",
        b"[2026-01-01 00:00:00,000] [kometa.py:2] [INFO] | Run Command: --run",
        b"[2026-01-01 00:00:01,000] [kometa.py:3] [INFO] | WARNING test",
    ]
)


class ScannerTests(unittest.TestCase):
    def test_scan_returns_normalized_recommendations(self):
        result = scan_log("kometa.log", VALID_LOG)
        self.assertEqual(result.metadata["kometa_version"], "2.2.0")
        self.assertFalse(result.metadata["complete"])
        self.assertTrue(all("severity" in item for item in result.recommendations))

    def test_rejects_non_kometa_content(self):
        with self.assertRaises(ScanError):
            scan_log("notes.txt", b"ordinary text")

    def test_rejects_unsupported_extension(self):
        with self.assertRaises(ScanError):
            scan_log("log.exe", VALID_LOG)

    def test_title_cleanup_removes_markdown_and_trailing_bracket(self):
        self.assertEqual(_plain_title("⚠️ **WARNING]**"), "WARNING")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_home_page(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_scan_requires_file(self):
        self.assertEqual(self.client.post("/api/scan").status_code, 400)

    def test_scan_accepts_valid_log(self):
        response = self.client.post(
            "/api/scan",
            data={"log": (BytesIO(VALID_LOG), "sample.log")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("recommendations", response.get_json())


if __name__ == "__main__":
    unittest.main()

