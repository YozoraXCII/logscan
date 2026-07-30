import asyncio
import re
from dataclasses import dataclass
from pathlib import Path

from .engine import StandaloneLogScanner


MAX_FILE_BYTES = 100 * 1024 * 1024
ALLOWED_SUFFIXES = {".txt", ".log", ".yml", ".yaml"}


class ScanError(ValueError):
    pass


@dataclass(frozen=True)
class ScanResult:
    filename: str
    recommendations: list[dict]
    metadata: dict


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


def _new_scanner() -> StandaloneLogScanner:
    return StandaloneLogScanner()


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

    scanner = _new_scanner()
    parsed = asyncio.run(scanner.parse_attachment_content(content_bytes))
    header = scanner.extract_header_lines(parsed)
    scanner.extract_last_lines(parsed)
    detected_run_time = scanner.run_time
    incomplete = "" if detected_run_time else "The log may be incomplete."

    recommendations = scanner.make_recommendations(content, incomplete)
    recommendations = scanner.reorder_recommendations(recommendations)
    normalized = [
        {
            "title": _plain_title(
                _strip_emojis(item.get("message", "").splitlines()[0] if item.get("message") else "")
            ),
            "message": _strip_emojis(item.get("message", "")).lstrip(),
            "severity": _severity(item.get("first_line", "")),
        }
        for item in recommendations
    ]
    normalized.sort(key=lambda item: {"critical": 0, "warning": 1, "advice": 2}[item["severity"]])

    metadata = {
        "kometa_version": scanner.current_kometa_version,
        "run_time": str(detected_run_time) if detected_run_time else None,
        "complete": detected_run_time is not None,
        "header_found": bool(header),
        "line_count": len(content.splitlines()),
        "size_bytes": len(content_bytes),
        "counts": {
            level: sum(item["severity"] == level for item in normalized)
            for level in ("critical", "warning", "advice")
        },
    }
    return ScanResult(filename=filename, recommendations=normalized, metadata=metadata)
