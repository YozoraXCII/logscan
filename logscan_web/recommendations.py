"""Single-source recommendation catalogue."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml
from jsonschema import Draft7Validator


KOMETA_CONFIG_SCHEMA_URL = "https://raw.githubusercontent.com/Kometa-Team/Kometa/refs/heads/nightly/json-schema/config-schema.json"

@dataclass(frozen=True)
class RecommendationRule:
    id: str
    category: str
    title: str
    description: str
    solution: str
    details: str = ""
    detector: str | None = None
    captures: tuple[str, ...] = ()

    def capture_lines(self, content: str) -> list[int]:
        needles = tuple(value.lower() for value in self.captures)
        return [number for number, line in enumerate(content.splitlines(), start=1) if any(needle in line.lower() for needle in needles)] if needles else []


def extract_redacted_config(log_content: str) -> tuple[str, list[int]]:
    """Return Kometa's redacted config block and its source log-line numbers."""
    started = False
    extracted: list[tuple[str, int]] = []
    tagged_config = re.compile(r"\[config\.py:\d+\]\s+\[[A-Z]+\]\s*\|(.*)$")
    for line_number, line in enumerate(log_content.splitlines(), start=1):
        if not started:
            if "Redacted Config" in line:
                started = True
            continue
        if "Config Warning:" in line or "Initializing cache database at" in line:
            break
        match = tagged_config.search(line)
        if not match:
            break
        extracted.append((match.group(1).rstrip(" |"), line_number))
    if len(extracted) > 1:
        extracted.pop()
    return "\n".join(line[1:] if line.startswith(" ") else line for line, _number in extracted), [
        line_number for _line, line_number in extracted
    ]


def _node_at_path(node, path, unexpected_property: str | None = None):
    """Find the YAML node corresponding to a JSON Schema validation path."""
    for component in path:
        if isinstance(node, yaml.MappingNode):
            pair = next((pair for pair in node.value if pair[0].value == str(component)), None)
            if pair is None:
                break
            node = pair[1]
        elif isinstance(node, yaml.SequenceNode) and isinstance(component, int) and component < len(node.value):
            node = node.value[component]
        else:
            break
    if unexpected_property and isinstance(node, yaml.MappingNode):
        pair = next((pair for pair in node.value if pair[0].value == unexpected_property), None)
        if pair is not None:
            return pair[0]
    return node


def validate_redacted_config(log_content: str) -> list[dict[str, str | int]]:
    """Validate a log's extracted config against the latest Kometa nightly schema.

    The schema is deliberately downloaded for every call; it is not cached so the
    validation always reflects the current nightly branch.
    """
    config_text, log_lines = extract_redacted_config(log_content)
    if not config_text.strip():
        raise ValueError("No redacted configuration block was found in this log.")
    try:
        config = yaml.safe_load(config_text)
        config_node = yaml.compose(config_text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        line = log_lines[mark.line] if mark and mark.line < len(log_lines) else log_lines[0]
        return [{"line": line, "message": f"Invalid YAML: {getattr(exc, 'problem', str(exc))}", "path": ""}]
    try:
        schema_request = Request(
            KOMETA_CONFIG_SCHEMA_URL,
            headers={"Accept": "application/json", "Cache-Control": "no-cache", "User-Agent": "Kometa-Logscan/1.0"},
        )
        with urlopen(schema_request, timeout=15) as response:
            schema = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("The latest Kometa configuration schema could not be fetched.") from exc

    failures = []
    for error in sorted(Draft7Validator(schema).iter_errors(config), key=lambda item: list(item.absolute_path)):
        unexpected = None
        if error.validator == "additionalProperties":
            match = re.search(r"'([^']+)' was unexpected", error.message)
            unexpected = match.group(1) if match else None
        node = _node_at_path(config_node, error.absolute_path, unexpected)
        config_line = node.start_mark.line if node is not None else 0
        log_line = log_lines[config_line] if config_line < len(log_lines) else log_lines[0]
        path = ".".join(str(part) for part in error.absolute_path)
        failures.append({"line": log_line, "message": error.message, "path": path})
    return failures

# Each record contains its category, issue description, proposed solution, and capture text.
RULE_SPECS = (
    {'id': 'anidb_connection', 'category': 'error', 'title': 'AniDB connection test failed', 'description': "Kometa's AniDB connectivity test failed, so AniDB-backed features cannot retrieve data.", 'solution': 'Kometa could not reach AniDB.', 'captures': ('No Anime Found for AniDB ID: 69',)},
    {'id': 'anidb_auth', 'category': 'error', 'title': 'AniDB authentication failed', 'description': 'AniDB rejected the configured credentials or settings.', 'solution': 'Check the AniDB settings in config.yml.', 'captures': ('Config Error: anidb sub-attribute', 'AniDB Error: Login failed')},
    {'id': 'api_key_missing', 'category': 'error', 'title': 'API key is missing', 'description': 'A third-party service API key is blank.', 'solution': 'Add the API key to the affected service configuration.', 'captures': ('apikey is blank',)},
    {'id': 'plex_version', 'category': 'critical', 'title': 'Incompatible Plex version detected', 'description': 'The detected Plex version is known to cause Kometa compatibility problems.', 'solution': 'Upgrade or downgrade Plex to a compatible release.', 'captures': ('1.32.7', 'Connected to server')},
    {'id': 'cache_disabled', 'category': 'advice', 'title': 'Kometa cache is disabled', 'description': 'Kometa caching is disabled, which can increase processing time and external API traffic.', 'solution': 'Enable the cache to improve performance and reduce API requests.', 'captures': ('cache: false',)},
    {'id': 'checkfiles', 'category': 'advice', 'title': 'Diagnostic file check enabled', 'description': 'Diagnostic file checking is enabled in this run.', 'solution': 'This diagnostic mode is intended for support investigation.', 'captures': ('checkFiles=1',)},
    {'id': 'legacy_other_award', 'category': 'schema', 'title': 'Legacy other_award setting detected', 'description': 'The configuration uses the removed other_award setting.', 'solution': 'Replace the deprecated setting with its current schema equivalent.', 'captures': ('other_award',)},
    {'id': 'kometa_critical', 'category': 'critical', 'title': 'Critical Kometa messages detected', 'description': 'Critical log entries indicate that part or all of the run may have stopped early. Review each detailed issue and proposed solution below.', 'solution': 'Review the referenced critical log messages.', 'captures': ('[CRITICAL]',)},
    {'id': 'kometa_error', 'category': 'error', 'title': 'Kometa errors detected', 'description': 'Error log entries indicate that one or more requested operations may not have completed. Review each detailed issue and proposed solution below.', 'solution': 'Review the referenced error log messages.', 'captures': ('[ERROR]',)},
    {'id': 'kometa_warning', 'category': 'warning', 'title': 'Kometa warnings detected', 'description': 'Warning log entries were recorded; many are informational, but the referenced lines should be reviewed. Review each detailed issue and proposed solution below.', 'solution': 'Review the referenced warning log messages.', 'captures': ('[WARNING]',)},
    {'id': 'id_conversion', 'category': 'warning', 'title': 'Metadata ID conversion failed', 'description': 'A metadata provider record could not be cross-referenced to the requested identifier.', 'solution': 'Check the source item and identifier mapping.', 'captures': ('Convert Warning: No ', 'ID Found for')},
    {'id': 'image_unreadable', 'category': 'error', 'title': 'Unreadable image file detected', 'description': 'Kometa could not read an image file, commonly because it is corrupt or unsupported.', 'solution': 'Replace or repair the referenced image.', 'captures': ('PIL.UnidentifiedImageError',)},
    {'id': 'legacy_delete_unmanaged', 'category': 'schema', 'title': 'Legacy collection deletion setting detected', 'description': 'The configuration uses a legacy collection-deletion setting.', 'solution': 'Update this deprecated collection setting.', 'captures': ('delete_unmanaged_collections',)},
    {'id': 'flixpatrol_parse', 'category': 'warning', 'title': 'FlixPatrol data could not be parsed', 'description': 'Kometa could not parse data returned by FlixPatrol.', 'solution': 'Check the source data and service availability.', 'captures': ('FlixPatrol Error:', 'failed to parse')},
    {'id': 'flixpatrol_subscription', 'category': 'advice', 'title': 'Unsupported FlixPatrol source detected', 'description': 'FlixPatrol introduced a paywall and Kometa can no longer gather data from it, even with a paid subscription.', 'solution': 'Remove the FlixPatrol source and replace it with a supported data source.', 'details': 'FlixPatrol support was removed as of Kometa 1.20.0-nightly34. Paying for FlixPatrol will not make this source work with Kometa.\n\nMore information: https://github.com/Kometa-Team/Kometa/discussions/1837', 'captures': ('flixpatrol', '- pmm:')},
    {'id': 'legacy_git', 'category': 'schema', 'title': 'Legacy Kometa repository reference detected', 'description': 'The configuration contains the pre-1.18 `- git: PMM` repository syntax.', 'solution': 'Replace the legacy Git entry with the equivalent current `- default:` entry.', 'details': 'Kometa 1.18 replaced the old PMM repository references with default files. Review the referenced line and select the matching default file.\n\nMore information: https://kometa.wiki/en/latest/kometa/faqs/', 'captures': ('- git: PMM',)},
    {'id': 'legacy_pmm', 'category': 'schema', 'title': 'Legacy PMM configuration detected', 'description': 'The configuration uses the removed `- pmm:` file-source syntax.', 'solution': 'Replace `- pmm:` with `- default:`.', 'details': 'Keep the value after the colon; only the source key changes from `pmm` to `default`.', 'captures': ('- pmm:',)},
    {'id': 'image_size', 'category': 'warning', 'title': 'Image exceeds the permitted size', 'description': "Artwork exceeds Plex's supported upload size.", 'solution': 'Reduce the image dimensions or file size.', 'captures': ('in _upload_image',)},
    {'id': 'incomplete_log', 'category': 'warning', 'title': 'Log appears incomplete', 'description': 'The uploaded log does not contain a completed-run marker, limiting diagnostic accuracy.', 'solution': 'Upload a complete run log for accurate recommendations.', 'detector': 'LOG_INCOMPLETE'},
    {'id': 'internal_server', 'category': 'error', 'title': 'Remote service returned an internal error', 'description': 'An upstream service returned an internal-server error.', 'solution': 'Retry later and check the affected service status.', 'captures': ('internal_server_error',)},
    {'id': 'linuxserver', 'category': 'advice', 'title': 'LinuxServer container image detected', 'description': 'The log identifies a non-official LinuxServer container image.', 'solution': 'Review the container-specific Kometa guidance.', 'captures': ('(Linuxserver', 'Version:')},
    {'id': 'mal_connection', 'category': 'warning', 'title': 'MyAnimeList connection failed', 'description': 'Kometa could not connect to MyAnimeList.', 'solution': 'Check MyAnimeList credentials and connectivity.', 'captures': ('My Anime List Connection Failed',)},
    {'id': 'mass_update', 'category': 'error', 'title': 'Mass update prerequisite failed', 'description': 'A mass-update operation started without its required successful prerequisite.', 'solution': 'Resolve the failed prerequisite before running mass updates.', 'captures': ('Config Error: Operation mass_', 'without a successful')},
    {'id': 'mdblist_attribute', 'category': 'schema', 'title': 'MDBList attribute is invalid at season level', 'description': '`mdblist_list` is not allowed when the collection level is Season.', 'solution': 'Remove the MDBList builder from the season-level collection or change the collection design.', 'details': 'More information: https://kometa.wiki/en/latest/files/builders/mdblist/', 'captures': ('mdblist_list attribute not allowed with Collection Level: Season',)},
    {'id': 'mdblist_api_key', 'category': 'critical', 'title': 'MDBList API key is invalid', 'description': 'MDBList rejected the configured API key.', 'solution': 'Replace the MDBList API key.', 'captures': ('MdbList Error: Invalid API key',)},
    {'id': 'mdblist_limit', 'category': 'warning', 'title': 'MDBList API limit reached', 'description': 'The MDBList free API key limit of 1,000 requests per day has been reached.', 'solution': 'Wait for the daily limit to reset and keep the Kometa cache enabled so the next run can continue where this run stopped.', 'details': 'Verify that `cache: true` is set in config.yml before the next run.', 'captures': ('MDBList Error: API',)},
    {'id': 'metadata_attribute', 'category': 'schema', 'title': 'Legacy metadata or overlay path detected', 'description': 'The `metadata attribute is required` message commonly occurs when legacy `metadata_path` or `overlay_path` configuration is used.', 'solution': 'Migrate legacy path entries to `metadata_files`, `collection_files`, `overlay_files`, or `playlist_files`, according to the top-level keys in each YAML file.', 'details': 'On releases where this is an expected migration warning, it can be ignored after confirming the files are already referenced by the correct modern attribute. Do not blindly add a `metadata` attribute to the referenced file.\n\nMore information: https://kometa.wiki/en/latest/config/files/', 'captures': ('metadata attribute is required',)},
    {'id': 'metadata_load', 'category': 'error', 'title': 'Metadata file failed to load', 'description': 'A metadata file could not be loaded.', 'solution': 'Correct the referenced metadata file.', 'captures': ('Metadata File Failed To Load',)},
    {'id': 'overlay_load', 'category': 'error', 'title': 'Overlay file failed to load', 'description': 'An overlay file could not be loaded.', 'solution': 'Correct the referenced overlay file.', 'captures': ('Overlay File Failed To Load',)},
    {'id': 'playlist_load', 'category': 'error', 'title': 'Playlist file failed to load', 'description': 'A playlist file could not be loaded.', 'solution': 'Correct the referenced playlist file.', 'captures': ('Playlist File Failed To Load',)},
    {'id': 'legacy_missing', 'category': 'schema', 'title': 'Legacy missing-item setting detected', 'description': 'The removed `missing_path` or `save_missing` setting is present.', 'solution': 'Remove the legacy setting and use `report_path` when a missing-items report is required.', 'details': 'More information: https://kometa.wiki/en/latest/config/settings/#report-path', 'captures': ('missing_path', 'save_missing')},
    {'id': 'plexapi_update', 'category': 'advice', 'title': 'Python dependency update required', 'description': 'The installed Plex API dependency is older than the version required by Kometa.', 'solution': 'Update the required Python dependency.', 'captures': ('requires an update to:',)},
    {'id': 'kometa_update', 'category': 'advice', 'title': 'Kometa update available', 'description': 'The log reports that a newer Kometa version was available at run time.', 'solution': 'Update to the newest release for your selected branch after reviewing its release notes.', 'details': 'Kometa has separate master, develop, and nightly branches; remain on the branch you intentionally selected. In a Kometa Discord support thread, `!update` provides update guidance.\n\nMore information: https://kometa.wiki/en/latest/kometa/install/', 'captures': ('Newest Version:',)},
    {'id': 'plex_no_items', 'category': 'advice', 'title': 'No matching Plex items found', 'description': 'A Plex search or filter returned no items.', 'solution': 'Confirm the filter is expected and uses correct case.', 'captures': ('Plex Error: No Items found in Plex',)},
    {'id': 'omdb_api_key', 'category': 'critical', 'title': 'OMDb API key is invalid', 'description': 'OMDb rejected the configured API key.', 'solution': 'Replace the OMDb API key.', 'captures': ('OMDb Error: Invalid API key',)},
    {'id': 'omdb_limit', 'category': 'warning', 'title': 'OMDb request limit reached', 'description': 'The OMDb free API key limit of 1,000 requests per day has been reached.', 'solution': 'Wait for the daily limit to reset and keep the Kometa cache enabled so the next run can continue where this run stopped.', 'details': 'Verify that `cache: true` is set in config.yml before the next run.', 'captures': ('OMDb Error: Request limit',)},
    {'id': 'overlay_font', 'category': 'error', 'title': 'Overlay font file is missing', 'description': 'An overlay references a font file that Kometa cannot find.', 'solution': 'Install or correctly reference the font file.', 'captures': ('Overlay Error: font:',)},
    {'id': 'overlay_reset', 'category': 'warning', 'title': 'Overlay reapplication or reset detected', 'description': 'The run requests overlay reapplication or reset, which can create unnecessary artwork churn.', 'solution': 'Use reapply/reset only when a full overlay rebuild is intended.', 'captures': ('Reapply Overlays: True', 'Reset Overlays:')},
    {'id': 'overlay_existing', 'category': 'warning', 'title': 'Poster already contains an overlay', 'description': 'Kometa found artwork that already contains an overlay.', 'solution': 'Restore original artwork or follow the overlay reset process.', 'captures': ('Poster already has an Overlay',)},
    {'id': 'overlay_image', 'category': 'error', 'title': 'Overlay image file is missing', 'description': 'An overlay references an image file that cannot be found.', 'solution': 'Verify the image path, filename, case, and container access.', 'captures': ('Overlay Image not found',)},
    {'id': 'legacy_overlay_level', 'category': 'schema', 'title': 'Legacy overlay_level setting detected', 'description': 'The configuration uses the removed overlay_level setting.', 'solution': 'Replace overlay_level with builder_level.', 'captures': ('overlay_level:',)},
    {'id': 'playlist_library', 'category': 'error', 'title': 'Playlist references an unknown Plex library', 'description': 'A playlist references a Plex library that is not defined.', 'solution': 'Correct the library name or template variable.', 'captures': ('Playlist Error: Library:', 'not defined')},
    {'id': 'plex_regex', 'category': 'advice', 'title': 'Plex regular expression matched no items', 'description': 'A Plex regular-expression search returned no matches.', 'solution': 'Confirm the pattern and target field; an empty result may be expected.', 'captures': ('Plex Error: ', 'No matches found with regex pattern')},
    {'id': 'plex_library', 'category': 'critical', 'title': 'Plex library was not found', 'description': 'A configured Plex library name was not found.', 'solution': 'Verify spelling, case, and the configured Plex library.', 'captures': ('Plex Error: Plex Library', 'not found')},
    {'id': 'plex_url', 'category': 'critical', 'title': 'Plex URL is invalid', 'description': 'The configured Plex URL is invalid.', 'solution': 'Verify the scheme, hostname, port, and container networking.', 'captures': ('Plex Error: Plex url is invalid',)},
    {'id': 'rating_rounding', 'category': 'warning', 'title': 'Plex user-rating rounding issue detected', 'description': 'The detected Plex version can round user ratings written through the API.', 'solution': 'Downgrade Plex to 1.40.0.7998 or upgrade to 1.40.3.8555 or later before applying mass user-rating operations.', 'details': 'Affected operations include `mass_user_rating_update` and `mass_episode_user_ratings_update`.\n\nMore information: https://forums.plex.tv/t/plex-rounding-down-user-ratings-when-set-via-api/875806/8', 'detector': 'RATING_ROUNDING'},
    {'id': 'yaml', 'category': 'schema', 'title': 'YAML parsing failed', 'description': 'Kometa encountered a YAML parsing error.', 'solution': 'Correct YAML indentation, quoting, spacing, or structure.', 'captures': ('ruamel.yaml.',)},
    {'id': 'run_order', 'category': 'schema', 'title': 'Recommended run order is not configured', 'description': "The configured run order does not follow Kometa's recommended processing sequence.", 'solution': 'Place operations before metadata and overlays unless your workflow requires otherwise.', 'detector': 'RUN_ORDER'},
    {'id': 'plex_security', 'category': 'critical', 'title': 'Vulnerable Plex Media Server version detected', 'description': 'A Plex Media Server version in a known vulnerable range was detected.', 'solution': 'Upgrade Plex Media Server to a secure release immediately.', 'detector': 'PMS_VULNERABLE'},
    {'id': 'traceback', 'category': 'error', 'title': 'Unhandled Kometa exception detected', 'description': 'Kometa raised an unhandled exception.', 'solution': 'Review the exception and its preceding context, then retry.', 'captures': ('Traceback (most recent call last):',)},
    {'id': 'tautulli_key', 'category': 'error', 'title': 'Tautulli API key is invalid', 'description': 'Tautulli rejected the configured API key.', 'solution': 'Replace the Tautulli API key.', 'captures': ('Tautulli Error: Invalid apikey',)},
    {'id': 'tautulli_url', 'category': 'error', 'title': 'Tautulli URL is invalid', 'description': 'The configured Tautulli URL is invalid.', 'solution': 'Verify the Tautulli URL and networking.', 'captures': ('Tautulli Error: Invalid URL',)},
    {'id': 'tmdb_key', 'category': 'critical', 'title': 'TMDb API key is invalid', 'description': 'TMDb rejected the configured API key.', 'solution': 'Replace the TMDb API key.', 'captures': ('TMDb Error: Invalid API key',)},
    {'id': 'timeout', 'category': 'error', 'title': 'Service connection timed out', 'description': 'A service request exceeded its configured timeout; Plex is a common source of this error.', 'solution': 'Verify network and container connectivity, then consider increasing the Plex `timeout` in config.yml (for example, `timeout: 360`).', 'details': 'A larger timeout only waits longer; it cannot repair an unreachable service. Hosted or Appbox users may need to contact their provider. In a Kometa Discord support thread, `!timeout` provides more guidance.\n\nMore information: https://kometa.wiki/en/latest/kometa/install/overview/', 'captures': ('timed out.',)},
    {'id': 'tmdb_connection', 'category': 'critical', 'title': 'TMDb connection failed', 'description': 'Kometa could not establish a connection to TMDb.', 'solution': 'Check DNS, outbound access, firewall rules, and networking.', 'captures': ('Failed to Connect to https://api.themoviedb.org/3',)},
    {'id': 'service_config', 'category': 'schema', 'title': 'Required service is not configured', 'description': 'A required service has not been configured.', 'solution': 'Add the required configuration for the affected service.', 'captures': ('Error: ', ' requires ', ' to be configured')},
    {'id': 'trakt_connection', 'category': 'warning', 'title': 'Trakt connection failed', 'description': 'Kometa could not connect to Trakt.', 'solution': 'Check authorization, credentials, network access, and service availability.', 'captures': ('Trakt Connection Failed',)},
    {'id': 'wsl_memory', 'category': 'advice', 'title': 'WSL memory allocation', 'description': 'Kometa is running under WSL, whose virtual machine memory limit may be lower than the host system memory.', 'solution': 'Review the WSL 2 memory limit and increase it in `%UserProfile%\\.wslconfig` when the Kometa workload needs more RAM, then run `wsl --shutdown` to apply it.', 'details': 'Example `.wslconfig` setting: `[wsl2]` followed by `memory=8GB`. Choose a value appropriate for the host instead of assuming all host RAM is available.\n\nMore information: https://learn.microsoft.com/windows/wsl/wsl-config', 'captures': ('Platform:', '-WSL')},
    {'id': 'db_cache_exceeds_memory', 'category': 'error', 'title': 'Plex database cache exceeds available memory', 'description': 'The configured Plex database cache is at least as large as detected system memory.', 'solution': 'Reduce db_cache to a value safely below the available system memory.', 'captures': ('Plex DB cache setting:', 'Memory:')},
    {'id': 'db_cache_undersized', 'category': 'advice', 'title': 'Plex database cache may be undersized', 'description': 'The configured Plex database cache is below one gigabyte.', 'solution': 'Consider setting db_cache: 1024 (1 GB) in the Plex configuration, provided it remains safely below available memory and suits the workload.', 'captures': ('Plex DB cache setting:',)},
    {'id': 'memory_unavailable', 'category': 'advice', 'title': 'Memory information unavailable', 'description': 'The log does not include system-memory information.', 'solution': 'Upload a complete log that includes system-memory information.', 'captures': ()},
    {'id': 'memory_overlay_insufficient', 'category': 'warning', 'title': 'Insufficient memory for overlays', 'description': 'Detected memory is below the recommended minimum for an overlay workload.', 'solution': 'Increase available memory to at least 8 GB for overlay workloads.', 'captures': ('Memory:', 'overlay_path:', 'overlay_files:')},
    {'id': 'memory_low', 'category': 'warning', 'title': 'Low memory available', 'description': 'Detected memory is below the recommended minimum for a reliable Kometa run.', 'solution': 'Increase available memory to at least 4 GB for reliable operation.', 'captures': ('Memory:',)},
    {'id': 'memory_overlay_low', 'category': 'warning', 'title': 'Memory below the overlay recommendation', 'description': 'Detected memory is below the recommended level for an overlay workload.', 'solution': 'Increase available memory to at least 8 GB for overlay workloads.', 'captures': ('Memory:', 'overlay_path:', 'overlay_files:')},
    {'id': 'schedule_unavailable', 'category': 'advice', 'title': 'Kometa schedule information unavailable', 'description': 'The log does not include the configured Kometa schedule.', 'solution': 'Upload a log that includes the configured Kometa schedule.', 'captures': ()},
    {'id': 'schedule_over_24_hours', 'category': 'warning', 'title': 'Kometa run exceeds 24 hours', 'description': 'The recorded Kometa run duration exceeds 24 hours.', 'solution': 'Split the workload into shorter scheduled runs.', 'detector': 'SCHEDULE_ANALYSIS'},
    {'id': 'schedule_overlap', 'category': 'warning', 'title': 'Kometa run overlaps the next Plex maintenance window', 'description': 'The recorded run duration overlaps the next Plex maintenance window.', 'solution': 'Move the Kometa schedule, adjust maintenance, or divide the workload.', 'detector': 'SCHEDULE_ANALYSIS'},
    {'id': 'schedule_conflict', 'category': 'warning', 'title': 'Kometa schedule conflicts with Plex maintenance', 'description': 'The configured Kometa start time falls inside the Plex maintenance window.', 'solution': 'Schedule Kometa outside the Plex maintenance window.', 'detector': 'SCHEDULE_ANALYSIS'},
    {'id': 'schedule_maintenance_buffer', 'category': 'warning', 'title': 'Kometa may still be running when Plex maintenance begins', 'description': 'The recorded run duration may extend into Plex maintenance.', 'solution': 'Increase the gap between the Kometa schedule and maintenance.', 'detector': 'SCHEDULE_ANALYSIS'},
)

LEGACY_DETAILS = {
    "anidb_connection": "Kometa uses AniDB ID 69 as a connectivity test. Failure means AniDB could not be reached. More information: https://kometa.wiki/en/latest/config/anidb/",
    "anidb_auth": "Verify every AniDB value in config.yml, not only the password. More information: https://kometa.wiki/en/latest/config/anidb/",
    "api_key_missing": "Identify the service named on the evidence line and supply its API key. More information: https://kometa.wiki/en/latest/config/",
    "plex_version": "Plex 1.32.7.x is known to break endpoints used by Kometa. Move to a release outside that series. More information: https://forums.plex.tv/t/refresh-endpoint-put-post-requests-started-throwing-404s-in-version-1-32-7-7484/853588",
    "cache_disabled": "The cache reduces repeat processing and API use. More information: https://kometa.wiki/en/latest/config/settings/#cache",
    "checkfiles": "`checkFiles=1` is a diagnostic support mode; retain it only while investigating the associated support issue.",
    "legacy_other_award": "Remove `other_award`; the awards now have individual default files. More information: https://kometa.wiki/en/latest/kometa/faqs/",
    "kometa_critical": "A critical entry usually means all or part of the run ended early. Inspect every referenced line and its preceding context. More information: https://kometa.wiki/en/latest/kometa/logs/#critical",
    "kometa_error": "Some errors can be harmless, but requested work may be incomplete. Inspect every referenced line and its preceding context. More information: https://kometa.wiki/en/latest/kometa/logs/#error",
    "kometa_warning": "Many warnings are informational and can be ignored after review. More information: https://kometa.wiki/en/latest/kometa/logs/#warning",
    "id_conversion": "The source provider record lacks a cross-reference to the requested provider ID. Confirm the title and contribute the missing external ID at the relevant metadata site when appropriate.",
    "image_unreadable": "Inspect the referenced image with an image editor and replace it if corrupt or encoded in an unsupported format. More information: https://kometa.wiki/en/latest/kometa/logs/#error",
    "legacy_delete_unmanaged": "Migrate the removed collection-deletion setting to current collection operations. More information: https://kometa.wiki/en/latest/config/operations/#delete-collections",
    "flixpatrol_parse": "The response could not be parsed; repeated failures can also indicate a FlixPatrol-side block. FlixPatrol builders are no longer supported in current Kometa releases.",
    "image_size": "Use the evidence and nearby traceback lines to identify the artwork, then reduce its dimensions or encoded size before retrying.",
    "incomplete_log": "A partial log can hide configuration, Plex connection, and completion information. Upload the complete run log from header through footer.",
    "internal_server": "This is an upstream service failure rather than a YAML correction. Retry later and check the provider status before changing configuration.",
    "linuxserver": "The LinuxServer image is community-maintained rather than the official Kometa image, so container-specific behavior may need LinuxServer support guidance.",
    "mal_connection": "Reauthorize MyAnimeList and verify client credentials and outbound connectivity before retrying.",
    "mass_update": "The mass operation depends on an earlier successful operation named in the same log line. Fix that prerequisite first.",
    "mdblist_api_key": "Generate or copy a valid MDBList key and update config.yml. More information: https://kometa.wiki/en/latest/config/mdblist/",
    "metadata_load": "Review the lines immediately before this message for the actual YAML, path, template, or network failure that prevented loading.",
    "overlay_load": "Review the lines immediately before this message for the actual YAML, path, template, or asset failure that prevented loading.",
    "playlist_load": "Review the lines immediately before this message for the actual YAML, path, template, or library failure that prevented loading.",
    "plexapi_update": "Update the Python module to the version named in the log. Container users normally update the image rather than installing into a running container.",
    "plex_no_items": "Plex filters are case-sensitive in relevant contexts; for example, `1080P` and `1080p` may not be equivalent. An empty result can also be intentional.",
    "omdb_api_key": "Replace the rejected key and verify the OMDb section in config.yml. More information: https://kometa.wiki/en/latest/config/omdb/",
    "overlay_font": "Verify the font path, filename, capitalization, and container mount. More information: https://kometa.wiki/en/latest/files/overlays/",
    "overlay_reset": "Do not enable reapply/reset routinely. It can create extra Plex artwork and database bloat; use it only for a deliberate rebuild. More information: https://kometa.wiki/en/latest/kometa/scripts/imagemaid/",
    "overlay_existing": "For seasons, Plex may inherit show art; for movies, shows, and episodes, an already-overlaid asset may have been selected. Choose clean artwork in Plex or replace the asset-pipeline source. More information: https://kometa.wiki/en/latest/kometa/guides/assets/",
    "overlay_image": "Check the full path and exact capitalization; `4K.png` and `4k.png` are different on case-sensitive systems. More information: https://kometa.wiki/en/latest/files/overlays/",
    "legacy_overlay_level": "Replace `overlay_level:` with `builder_level:`. More information: https://kometa.wiki/en/latest/files/settings/#builder-level",
    "playlist_library": "The default playlist file expects libraries named `Movies` and `TV Shows`; use template variables when your Plex library names differ. More information: https://kometa.wiki/en/latest/defaults/playlist/",
    "plex_regex": "Zero matches are often expected and can usually be ignored. If results were expected, verify both the target field and regular expression.",
    "plex_library": "Library names are case-sensitive. Enable `show_options: true` to review detected Plex options. More information: https://kometa.wiki/en/latest/config/settings/#show-options",
    "plex_url": "Verify protocol, host, port, and container reachability. More information: https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-plex-url-and-token",
    "yaml": "Search the evidence area for the detailed ruamel parser message; indentation and spacing are significant. More information: https://kometa.wiki/en/latest/kometa/yaml/",
    "run_order": "In almost every workflow, `- operations` should appear before metadata and overlays. More information: https://kometa.wiki/en/latest/config/settings/#run-order",
    "plex_security": "Affected Plex servers may have remote access restricted until upgraded. Upgrade immediately. More information: https://forums.plex.tv/t/plex-media-server-security-update/928341",
    "traceback": "The run likely ended early or skipped work such as overlays. Review the traceback from its first line together with the preceding log context.",
    "tautulli_key": "Replace the rejected API key in the Tautulli configuration. More information: https://kometa.wiki/en/latest/config/tautulli/",
    "tautulli_url": "Verify the complete Tautulli URL and container networking. More information: https://kometa.wiki/en/latest/config/tautulli/#tautulli-attributes",
    "tmdb_key": "Replace the rejected TMDb API key; TMDb-backed functionality cannot run without it. More information: https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-tmdb-api-key",
    "tmdb_connection": "The host or container could not reach TMDb. Check DNS, routing, firewall, and outbound HTTPS access before changing builders.",
    "service_config": "The evidence line names a builder whose required external service has not been configured. Add that service section before rerunning.",
    "trakt_connection": "Reauthorize Trakt, verify credentials, and check service availability. More information: https://kometa.wiki/en/latest/config/trakt/#trakt-attributes",
    "db_cache_exceeds_memory": "The Plex DB cache must remain below total available memory. Its ideal size varies with library size, files, operations, and overlays. More information: https://kometa.wiki/en/latest/config/plex/#plex-attributes",
    "db_cache_undersized": "`db_cache: 1024` represents 1 GB. Choose a value appropriate for the workload and still safely below total memory. More information: https://kometa.wiki/en/latest/config/plex/#plex-attributes",
    "memory_unavailable": "Memory recommendations cannot be calculated without the system-memory line, which normally appears in a complete Kometa header.",
    "memory_overlay_insufficient": "The recommendation is an estimate and varies with library size and workload. Overlay processing is materially more memory-intensive.",
    "memory_low": "The recommendation is an estimate and varies with library size, file count, operations, and other workload characteristics.",
    "memory_overlay_low": "The recommendation is an estimate and varies with library size and workload; 8 GB is the original cog's overlay target.",
    "schedule_unavailable": "Schedule comparison requires the Kometa start schedule from a complete log header.",
    "schedule_over_24_hours": "A run longer than a day will reach the next Plex maintenance period. Split work into smaller runs on different days. More information: https://support.plex.tv/articles/202197488-scheduled-server-maintenance/",
    "schedule_overlap": "Use the recorded duration to move Kometa after maintenance or move maintenance later. More information: https://support.plex.tv/articles/202197488-scheduled-server-maintenance/",
    "schedule_conflict": "Move Kometa to the end of the Plex maintenance window, or make maintenance finish before Kometa starts. More information: https://support.plex.tv/articles/202197488-scheduled-server-maintenance/",
    "schedule_maintenance_buffer": "The recorded duration is longer than the safe interval between maintenance windows. Split the workload or adjust both schedules. More information: https://support.plex.tv/articles/202197488-scheduled-server-maintenance/",
}

RULES = {
    spec["title"]: RecommendationRule(**({"details": LEGACY_DETAILS.get(spec["id"], "")} | spec))
    for spec in RULE_SPECS
}

def legacy_title(message: str) -> str:
    first_line = message.splitlines()[0] if message else ""
    first_line = re.sub(r"^[^\w]+", "", first_line)
    first_line = re.sub(r"[*`]+", "", first_line)
    return re.sub(r"\]+$", "", first_line).strip()

def rule_for_legacy_message(message: str) -> RecommendationRule | None:
    return RULES.get(legacy_title(message))
