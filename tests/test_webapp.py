import unittest
from datetime import UTC, datetime, timedelta
from io import BytesIO
import json
import tempfile
import time

from logscan_web.app import app
from logscan_web.models import ScanContext
from logscan_web.parity import DISCORD_BRANCH_TO_RULE, DISCORD_PRIORITY_BY_RULE
from logscan_web.recommendations import RULES as RECOMMENDATION_RULES
from logscan_web.rules.base import TextRule
from logscan_web.rules import RuleRegistry, migrated_rules
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
        self.assertIn("error", result.metadata["counts"])

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
        warning = next(item for item in result.recommendations if item["id"] == "kometa_warning")
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


class RecommendationParityTests(unittest.TestCase):
    @staticmethod
    def evaluate(*lines):
        content = "\n".join(lines)
        context = ScanContext.from_content("kometa.log", content, complete=True)
        registry = RuleRegistry()
        for rule in migrated_rules():
            registry.register(rule)
        return {finding.id: finding.as_dict() for finding in registry.evaluate(context)}

    def test_every_web_rule_has_a_discord_source_and_sort_priority(self):
        web_ids = {rule.id for rule in RECOMMENDATION_RULES.values()}
        self.assertEqual(web_ids, set(DISCORD_PRIORITY_BY_RULE))
        self.assertEqual(web_ids, set(DISCORD_BRANCH_TO_RULE.values()))

    def test_every_recommendation_retains_rich_discord_guidance(self):
        for rule in RECOMMENDATION_RULES.values():
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.details.strip())

    def test_every_text_detector_has_a_positive_characterization_fixture(self):
        text_rules = [rule for rule in migrated_rules() if isinstance(rule, TextRule)]
        for rule in text_rules:
            with self.subTest(rule=rule.id):
                lines = []
                if rule.any_of:
                    lines.append(rule.any_of[0])
                if rule.word_bounded_any_of:
                    lines.append(rule.word_bounded_any_of[0])
                lines.extend(rule.all_of)
                if rule.all_on_same_line:
                    lines.append(" ".join(rule.all_on_same_line))
                context = ScanContext.from_content("fixture.log", "\n".join(lines), complete=True)
                self.assertEqual([finding.id for finding in rule.evaluate(context)], [rule.id])

    def test_scan_uses_discord_equivalent_priority_bands(self):
        log = b"\n".join((
            VALID_LOG,
            b"cache: false",
            b"[WARNING] warning",
            b"Request timed out.",
            b"[CRITICAL] critical",
            b"Newest Version: 2.3.0",
        ))
        result = scan_log("priority.log", log)
        priorities = [DISCORD_PRIORITY_BY_RULE[item["id"]] for item in result.recommendations]
        self.assertEqual(priorities, sorted(priorities))
        self.assertLess(
            next(i for i, item in enumerate(result.recommendations) if item["id"] == "kometa_update"),
            next(i for i, item in enumerate(result.recommendations) if item["id"] == "kometa_critical"),
        )

    def test_custom_detectors_have_characterization_fixtures(self):
        security = self.evaluate("Connected to server Main (Version: 1.41.7.0-abcd)")
        self.assertIn("plex_security", security)

        run_order = self.evaluate("run_order:", "  - metadata", "  - operations")
        self.assertIn("run_order", run_order)

    def test_runtime_helper_outcomes_have_characterization_fixtures(self):
        missing = self.evaluate("ordinary completed log line")
        self.assertIn("memory_unavailable", missing)
        self.assertIn("schedule_unavailable", missing)

        low_overlay = self.evaluate("Memory: 3 GB", "overlay_files:")
        self.assertIn("memory_overlay_insufficient", low_overlay)

        low_memory = self.evaluate("Memory: 3 GB")
        self.assertIn("memory_low", low_memory)

        overlay_memory = self.evaluate("Memory: 6 GB", "overlay_path:")
        self.assertIn("memory_overlay_low", overlay_memory)

        cache_high = self.evaluate("Memory: 8 GB", "Plex DB cache setting: 8 GB")
        self.assertIn("db_cache_exceeds_memory", cache_high)

        cache_low = self.evaluate("Memory: 8 GB", "Plex DB cache setting: 512 MB")
        self.assertIn("db_cache_undersized", cache_low)

    def test_schedule_helper_outcomes_have_characterization_fixtures(self):
        def schedule_findings(start, maintenance, run_time):
            content = "\n".join((
                "Memory: 16 GB",
                f"--time (KOMETA_TIME): {start}",
                f"Scheduled maintenance running between {maintenance[0]} and {maintenance[1]}",
            ))
            context = ScanContext.from_content("fixture.log", content, run_time=run_time, complete=True)
            registry = RuleRegistry()
            for rule in migrated_rules():
                registry.register(rule)
            return {finding.id for finding in registry.evaluate(context)}

        self.assertIn("schedule_over_24_hours", schedule_findings("01:00", ("02:00", "03:00"), "1 days, 01:00:00"))
        self.assertIn("schedule_maintenance_buffer", schedule_findings("01:00", ("02:00", "03:00"), "23:30:00"))
        self.assertIn("schedule_conflict", schedule_findings("02:30", ("02:00", "03:00"), "00:10:00"))
        self.assertIn("schedule_overlap", schedule_findings("01:00", ("02:00", "03:00"), "01:30:00"))

    def test_rating_rounding_uses_original_plex_range(self):
        findings = self.evaluate(
            "Connected to server Main (Version: 1.40.1.8000-abcd)",
            "mass_user_rating_update: mdb_average",
        )
        self.assertIn("rating_rounding", findings)
        self.assertIn("1.40.1.8000-abcd", findings["rating_rounding"]["message"])
        self.assertNotIn("plex_security", findings)

    def test_rating_rounding_excludes_original_boundaries_and_security_range(self):
        for version in ("1.40.0.7998-abcd", "1.40.3.8555-abcd", "1.41.7.1000-abcd"):
            with self.subTest(version=version):
                findings = self.evaluate(
                    f"Connected to server Main (Version: {version})",
                    "mass_episode_user_ratings_update: mdb_average",
                )
                self.assertNotIn("rating_rounding", findings)

    def test_flixpatrol_advice_says_paid_access_will_not_work(self):
        finding = self.evaluate("- pmm: flixpatrol")["flixpatrol_subscription"]
        self.assertIn("even with a paid subscription", finding["description"])
        self.assertIn("Remove the FlixPatrol source", finding["solution"])

    def test_metadata_advice_recommends_modern_file_attributes(self):
        finding = self.evaluate("YAML Error: metadata attribute is required")["metadata_attribute"]
        self.assertIn("metadata_files", finding["solution"])
        self.assertIn("overlay_files", finding["solution"])
        self.assertIn("Do not blindly add", finding["message"])

    def test_legacy_replacements_are_explicit(self):
        findings = self.evaluate("- PMM: anime", "missing_path: config/missing.yml")
        self.assertEqual(findings["legacy_pmm"]["solution"], "Replace `- pmm:` with `- default:`.")
        self.assertIn("report_path", findings["legacy_missing"]["solution"])

    def test_api_limit_advice_preserves_daily_limit_and_cache_behavior(self):
        for line, rule_id in (
            ("MDBList Error: API Limit Reached", "mdblist_limit"),
            ("OMDb Error: Request limit reached", "omdb_limit"),
        ):
            with self.subTest(rule_id=rule_id):
                finding = self.evaluate(line)[rule_id]
                self.assertIn("1,000 requests per day", finding["description"])
                self.assertIn("cache enabled", finding["solution"])

    def test_timeout_and_wsl_advice_are_actionable(self):
        findings = self.evaluate("Request timed out.", "Platform: Linux-WSL")
        self.assertIn("timeout: 360", findings["timeout"]["solution"])
        self.assertIn(".wslconfig", findings["wsl_memory"]["solution"])
        self.assertIn("wsl --shutdown", findings["wsl_memory"]["solution"])

    def test_broadened_rules_require_original_phrase_context(self):
        findings = self.evaluate(
            "helper in _upload_image",
            "mdblist_list attribute not allowed with Collection Level: Movie",
            "Overlay Image not found in documentation",
        )
        self.assertNotIn("image_size", findings)
        self.assertNotIn("mdblist_attribute", findings)
        self.assertNotIn("overlay_image", findings)

    def test_matching_remains_case_insensitive_for_log_robustness(self):
        findings = self.evaluate("- PMM: anime")
        self.assertIn("legacy_pmm", findings)


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

