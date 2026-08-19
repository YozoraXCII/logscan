"""Runtime and host-environment recommendation rules."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .base import TextRule
from ..models import Finding, ScanContext
from ..recommendations import RULES


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


RULES = (
    TextRule(next(rule for rule in RULES.values() if rule.id == "wsl_memory"), all_of=("Platform:", "-WSL")),
    _rule("plexapi_update", "requires an update to:"),
    _rule("kometa_update", "Newest Version:"),
    TextRule(next(rule for rule in RULES.values() if rule.id == "linuxserver"), all_on_same_line=("(Linuxserver", "Version:")),
    _rule("checkfiles", "checkFiles=1"),
)


def _definition(rule_id: str):
    return next(rule for rule in RULES_BY_TITLE.values() if rule.id == rule_id)


# Preserve the catalogue lookup after this module's RULES constant is assigned.
RULES_BY_TITLE = __import__("logscan_web.recommendations", fromlist=["RULES"]).RULES


def _memory_gb(context: ScanContext, label: str) -> float | None:
    match = re.search(rf"(?<!Available ){re.escape(label)}:\s*([\d.]+)\s*(GB|MB|TB)", context.content, re.I)
    if not match:
        return None
    value = float(match.group(1))
    return value / 1024 if match.group(2).upper() == "MB" else value * 1024 if match.group(2).upper() == "TB" else value


@dataclass(frozen=True)
class RuntimeAnalysisRule:
    """Handles checks that require values parsed from more than one log line."""

    id: str = "runtime-analysis"

    def evaluate(self, context: ScanContext) -> list[Finding]:
        findings: list[Finding] = []

        def add(rule_id: str, evidence: tuple[int, ...] = ()) -> None:
            rule = _definition(rule_id)
            findings.append(Finding(
                rule.id,
                rule.category,
                rule.title,
                rule.description,
                rule.solution,
                evidence,
            ))

        memory = _memory_gb(context, "Memory")
        cache = _memory_gb(context, "Plex DB cache setting")
        overlay = bool(re.search(r"\boverlay_(?:path|files):", context.content, re.I))
        if memory is None:
            add("memory_unavailable")
        elif memory < 4:
            add("memory_overlay_insufficient" if overlay else "memory_low")
        elif memory < 8 and overlay:
            add("memory_overlay_low")
        if cache is not None and memory is not None:
            add("db_cache_exceeds_memory" if cache >= memory else "db_cache_undersized" if cache < 1 else "memory_low") if cache >= memory or cache < 1 else None

        if re.search(r"Platform:.*-WSL", context.content, re.I):
            add("wsl_memory")
        if not re.search(r"--times? \((?:KOMETA|PMM)_TIMES?\)", context.content, re.I):
            add("schedule_unavailable")
        if not context.complete:
            add("incomplete_log")
        return findings
