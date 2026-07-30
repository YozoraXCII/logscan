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


def _severity(first_line: str) -> str:
    if first_line.startswith(("🚀", "💥", "❌")):
        return "critical"
    if first_line.startswith("⚠"):
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
            "title": _plain_title(item.get("first_line", "")),
            "message": item.get("message", ""),
            "severity": _severity(item.get("first_line", "")),
        }
        for item in recommendations
    ]

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
