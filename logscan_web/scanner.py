import re
from dataclasses import dataclass
from pathlib import Path

from .models import ScanContext
from .rules import RuleRegistry, migrated_rules
from .categories import category_configuration


MAX_FILE_BYTES = 100 * 1024 * 1024
ALLOWED_SUFFIXES = {".txt", ".log", ".yml", ".yaml"}


class ScanError(ValueError):
    pass


@dataclass(frozen=True)
class ScanResult:
    filename: str
    recommendations: list[dict]
    metadata: dict
    overview: dict
    categories: list[dict]


def _plain_title(value: str) -> str:
    value = re.sub(r"[*_`]+", "", value or "")
    value = re.sub(
        r"^[^\w]+",
        "",
        value,
        flags=re.UNICODE,
    )
    value = re.sub(r"\]+$", "", value.strip()).strip()
    return value or "Recommendation"


def _strip_emojis(value: str) -> str:
    """Remove emoji glyphs and selectors while preserving ordinary punctuation."""
    value = re.sub(
        "["
        "\U0001F1E6-\U0001F1FF"
        "\U0001F300-\U0001FAFF"
        "\u2300-\u23FF"
        "\u2600-\u27BF"
        "]+",
        "",
        value or "",
    )
    return value.replace("\uFE0F", "").replace("\u200D", "")


def _severity(first_line: str) -> str:
    if first_line.startswith(("🚀", "💥", "❌")):
        return "critical"
    if first_line.startswith("⚠"):
        return "warning"
    title = _plain_title(first_line).lower()
    if any(term in title for term in (
        "failed", "invalid", "error", "vulnerable", "exceeds available",
        "required api key", "required service", "unhandled", "incomplete",
        "unreadable", "subscription", "prerequisite", "api limit",
        "request limit", "could not be parsed", "already contains",
        "image file is missing", "font file is missing", "unknown plex library",
        "plex library was not found", "connection timed out",
    )):
        return "critical"
    if any(term in title for term in (
        "warning", "legacy", "detected", "matched no items", "no matching",
        "low memory", "memory below", "insufficient memory", "run order",
        "maintenance", "run exceeds", "rounding issue",
    )):
        return "warning"
    return "advice"


def _first_value(content: str, label: str) -> str | None:
    match = re.search(rf"\b{re.escape(label)}:\s*(.+?)(?:\s*\|)?\s*$", content, re.MULTILINE)
    return match.group(1).strip() if match else None


def _date_first(value: str | None) -> str | None:
    if not value:
        return None
    match = re.fullmatch(r"(\d{1,2}:\d{2}:\d{2})\s+(\d{4}-\d{2}-\d{2})", value)
    return f"{match.group(2)} {match.group(1)}" if match else value


def _log_overview(
    filename: str,
    content: str,
    kometa_version: str | None,
    run_time: str | None,
    recommendations: list[dict],
) -> dict:
    yaml_findings = [item for item in recommendations if item["severity"] == "schema"]
    yaml_status = "Schema issues detected" if yaml_findings else "No YAML or schema issues detected"
    completed_run = re.search(
        r"Start Time:\s*(?P<start>.*?)\s+Finished:\s*(?P<end>.*?)\s+Run Time:\s*(?P<runtime>[^|\r\n]+)",
        content,
    )
    return {
        "log_name": filename,
        "recommendation_count": len(recommendations),
        "kometa_version": kometa_version,
        "platform": _first_value(content, "Platform"),
        "total_memory": _first_value(content, "Memory"),
        "available_memory": _first_value(content, "Available Memory"),
        "run_command": _first_value(content, "Run Command"),
        "start_time": _date_first(completed_run.group("start").strip()) if completed_run else _first_value(content, "Started"),
        "finished": _date_first(completed_run.group("end").strip()) if completed_run else _first_value(content, "Finished"),
        "run_time": (
            completed_run.group("runtime").strip()
            if completed_run else run_time
        ),
        "yaml_validation": yaml_status,
        "yaml_issue_count": len(yaml_findings),
    }


def scan_log(filename: str, content_bytes: bytes) -> ScanResult:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_SUFFIXES and not suffix.lstrip(".").isdigit():
        raise ScanError("Choose a Kometa .log, .txt, .yml, .yaml, or rotated log file.")
    if not content_bytes:
        raise ScanError("The selected file is empty.")
    if len(content_bytes) > MAX_FILE_BYTES:
        raise ScanError("The selected file is larger than the 100 MB limit.")

    content = content_bytes.decode("utf-8", errors="replace")
    lowered = content.lower()
    if "[kometa.py:" not in lowered and "[plex_meta_manager.py:" not in lowered:
        raise ScanError("This does not appear to be a complete Kometa log file.")

    version_match = re.search(r"\bVersion:\s*([^|\r\n]+)", content)
    kometa_version = version_match.group(1).strip() if version_match else None
    run_match = re.search(r"\bFinished:.*?\bRun Time:\s*([^|\r\n]+)", content)
    detected_run_time = run_match.group(1).strip() if run_match else None
    context = ScanContext.from_content(
        filename,
        content,
        kometa_version=kometa_version,
        run_time=detected_run_time,
        complete=detected_run_time is not None,
    )
    registry = RuleRegistry()
    for rule in migrated_rules():
        registry.register(rule)
    normalized = [finding.as_dict() for finding in registry.evaluate(context)]
    normalized.sort(key=lambda item: {"critical": 0, "error": 1, "warning": 2, "schema": 3, "advice": 4}[item["severity"]])

    metadata = {
        "kometa_version": kometa_version,
        "run_time": str(detected_run_time) if detected_run_time else None,
        "complete": detected_run_time is not None,
        "header_found": kometa_version is not None,
        "line_count": len(content.splitlines()),
        "size_bytes": len(content_bytes),
        "counts": {
            level: sum(item["severity"] == level for item in normalized)
            for level in ("critical", "warning", "schema", "advice")
        },
    }
    return ScanResult(
        filename=filename,
        recommendations=normalized,
        metadata=metadata,
        overview=_log_overview(filename, content, kometa_version, detected_run_time, normalized),
        categories=category_configuration(),
    )
