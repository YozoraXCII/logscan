import unittest
from datetime import UTC, datetime, timedelta
from io import BytesIO
import json
import tempfile
import time

from logscan_web.app import app
from logscan_web.scanner import ScanError, _plain_title, _strip_emojis, scan_log
from logscan_web.storage import ScanStore


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

    def test_recommendation_emojis_are_removed(self):
        self.assertEqual(_strip_emojis("❌⏱️ **TIMEOUT ERROR**"), " **TIMEOUT ERROR**")
        result = scan_log("kometa.log", VALID_LOG)
        self.assertTrue(all("⚠" not in item["message"] for item in result.recommendations))

    def test_reworked_title_does_not_change_severity(self):
        warning_log = VALID_LOG.replace(b"[kometa.py:3] [INFO]", b"[kometa.py:3] [WARNING]")
        result = scan_log("kometa.log", warning_log)
        warning = next(item for item in result.recommendations if item["severity"] == "warning")
        self.assertEqual(warning["title"], "Kometa warnings detected")

    def test_expired_scans_are_deleted(self):
        with tempfile.TemporaryDirectory() as root:
            store = ScanStore(root)
            result = scan_log("sample.log", VALID_LOG)
            scan_id, _token = store.create("sample.log", VALID_LOG, result)
            record_path = store.root / scan_id / "result.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))
            record["created_at"] = (datetime.now(UTC) - timedelta(hours=49)).isoformat()
            record_path.write_text(json.dumps(record), encoding="utf-8")
            self.assertEqual(store.delete_expired(48 * 60 * 60), 1)
            self.assertIsNone(store.get(scan_id))


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

    def test_scan_is_persisted_and_can_be_deleted_with_token(self):
        response = self.client.post(
            "/api/scan",
            data={"log": (BytesIO(VALID_LOG), "sample.log")},
            content_type="multipart/form-data",
        )
        payload = response.get_json()
        self.assertGreater(payload["expires_at"], int(time.time()) + (47 * 60 * 60))
        self.assertLessEqual(payload["expires_at"], int(time.time()) + (48 * 60 * 60))
        self.assertEqual(self.client.get(f"/scan/{payload['id']}").status_code, 200)
        log_response = self.client.get(f"/api/scans/{payload['id']}/log")
        self.assertEqual(log_response.data, VALID_LOG)
        log_response.close()
        self.assertEqual(self.client.delete(f"/api/scans/{payload['id']}").status_code, 403)
        deleted = self.client.delete(
            f"/api/scans/{payload['id']}",
            headers={"X-Delete-Token": payload["delete_token"]},
        )
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(self.client.get(f"/scan/{payload['id']}").status_code, 404)


if __name__ == "__main__":
    unittest.main()

