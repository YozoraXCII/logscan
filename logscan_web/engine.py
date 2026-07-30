"""Standalone Kometa log recommendation engine used by the website.

This module contains no Discord or Red Bot integration.
"""

import logging
import re
from datetime import datetime, timedelta

mylogger = logging.getLogger("logscan.web")
global_divider = "="


def _parse_pms_version_tuple(ver: str):
    ver = ver.split("-", 1)[0].strip()
    parts = ver.split(".")
    nums = []
    for index in range(4):
        try:
            nums.append(int(parts[index]))
        except Exception:
            nums.append(0)
    return tuple(nums[:4])


def _version_in_inclusive_range(ver: str, low: tuple, high: tuple) -> bool:
    value = _parse_pms_version_tuple(ver)
    return low <= value <= high


_PMS_VULN_LOW = (1, 41, 7, 0)
_PMS_VULN_HIGH = (1, 42, 0, 99999)


class StandaloneLogScanner:
    def __init__(self):
        self.current_plexapi_version = None
        self.current_kometa_version = None
        self.kometa_newest_version = None
        self.version_master = None
        self.version_develop = None
        self.version_nightly = None
        self.run_time = None
        self.plex_timeout = None
        self.checkfiles_flg = None
        self.server_versions = []

    async def parse_attachment_content(self, content_bytes):
            try:
                content = content_bytes.decode('utf-8')
            except Exception as e:
                mylogger.error(f"Error decoding attachment content: {str(e)}")
                content = content_bytes.decode("utf-8", errors="replace")

            # Keep raw content for config extraction logic
            self._raw_content = content

            # Detect divider on raw content (so global_divider is correct)
            self.set_global_divider(content)

            # You can still return cleaned content for the rest of your features
            cleaned_content = self.cleanup_content(content)
            return cleaned_content

    def set_global_divider(self, content):
            """
            Search for the divider string in the content and set the global divider.
            """
            global global_divider  # Reference the global divider variable

            # Define the patterns to search for
            patterns = [
                r'--divider \(KOMETA_DIVIDER\): ?["\']?([^"\']{1})["\']?',  # KOMETA_DIVIDER pattern
                r'--divider \(PMM_DIVIDER\): ?["\']?([^"\']{1})["\']?'  # PMM_DIVIDER pattern
            ]

            # Try each pattern and set global_divider if a match is found
            for pattern in patterns:
                divider_match = re.search(pattern, content)
                if divider_match:
                    divider = divider_match.group(1)
                    global_divider = divider
                    mylogger.info(f"Divider found and set to: {divider}")
                    return  # Exit the function once a divider is found

            # If no match is found for any pattern, use default divider
            global_divider = "="
            mylogger.info(f"Divider not found, using default divider: {global_divider}")

    def extract_memory_value(self, content):
            """
            Extract the memory value from the given content.
            """
            # Regular expression to match the memory value
            memory_match = re.search(r'Memory:\s*([\d.]+)\s*(\w+)', content)

            if memory_match:
                value = float(memory_match.group(1))
                unit = memory_match.group(2).lower()

                # Convert value to gigabytes (GB)
                if unit == 'gb':
                    return value
                elif unit == 'mb':
                    return value / 1024  # Convert MB to GB
                elif unit == 'tb':
                    return value * 1024  # Convert TB to GB

            return None

    def extract_db_cache_value(self, content):
            """
            Extract the db_cache value from the given content.
            """
            # Regular expression to match the memory value
            memory_match = re.search(r'Plex DB cache setting:\s*([\d.]+)\s*(\w+)', content)

            if memory_match:
                value = float(memory_match.group(1))
                unit = memory_match.group(2).lower()

                # Convert value to gigabytes (GB)
                if unit == 'gb':
                    return value
                elif unit == 'mb':
                    return value / 1024  # Convert MB to GB
                elif unit == 'tb':
                    return value * 1024  # Convert TB to GB

            return None

    def extract_scheduled_run_time(self, content):
            """
            Extract the scheduled run time from the content.
            """
            # Define the patterns to search for
            patterns = [
                r'--times? \((KOMETA_TIMES?)\): ?["\']?(\d{1,2}:\d{2})["\']?',  # KOMETA_TIMES pattern
                r'--times? \((PMM_TIMES?)\): ?["\']?(\d{1,2}:\d{2})["\']?'  # PMM_TIMES pattern
            ]

            # Try each pattern and return the first match found
            for pattern in patterns:
                scheduled_run_time_match = re.search(pattern, content)
                if scheduled_run_time_match:
                    scheduled_run_time = scheduled_run_time_match.group(2)
                    mylogger.info(f"Scheduled run time found: {scheduled_run_time}")
                    return scheduled_run_time

            # If no match is found
            mylogger.info("Scheduled run time not found in content.")
            return None

    def extract_maintenance_times(self, content):
            """
            Extract the start and end times of the maintenance from the content.
            """
            maintenance_times_match = re.search(r'Scheduled maintenance running between (\d+:\d+) and (\d+:\d+)', content)

            if maintenance_times_match:
                start_time = maintenance_times_match.group(1)
                end_time = maintenance_times_match.group(2)
                mylogger.info(f"Scheduled maintenance times found: Start time: {start_time}, End time: {end_time}")
                return start_time, end_time
            else:
                mylogger.info("Scheduled maintenance times not found in content.")
                return None, None

    def contains_overlay_path(self, content):
            # Regular expression to search for overlay_path
            return bool(re.search(r'\boverlay_path:\s*', content, re.IGNORECASE))

    def contains_overlay_files(self, content):
            # Regular expression to search for overlay_files
            return bool(re.search(r'\boverlay_files:\s*', content, re.IGNORECASE))

    def detect_wsl_and_recommendation(self, content):
            # Regular expression to check if the content contains information about WSL platform
            wsl_pattern = r"Platform: .*-WSL"

            if re.search(wsl_pattern, content):
                recommendation = (
                    "**WSL memory allocation**\n"
                    "Kometa is running in WSL. WSL may restrict the memory available to Kometa, which can affect larger runs. "
                    "Review your WSL memory configuration and increase the allocation if necessary, then restart WSL for the change to take effect.\n"
                    "Set an appropriate limit with `wsl --set-memory <your_memory_limit>` (for example, `4GB`), then run `wsl --shutdown`."
                )
                return recommendation

            return None

    def make_db_cache_recommendations(self, parsed_content):
            disclaimer = "**NOTE**:The number you choose can vary wildly based on a number of factors " \
                         "(such as the size and number of libraries, and the amount of files/operations/overlays that are being utilized)."
            url_info = "https://kometa.wiki/en/latest/config/plex#plex-attributes"

            # Extract db_cache value and total memory value
            db_cache_value = self.extract_db_cache_value(parsed_content)
            total_memory_value = self.extract_memory_value(parsed_content)

            if db_cache_value is None or total_memory_value is None:
                return None  # Unable to determine recommendations due to missing data

            if db_cache_value >= total_memory_value:
                # db_cache should not be greater than or equal to total memory
                return f"**Plex database cache exceeds available memory**\n" \
                       f"The configured Plex database cache ({db_cache_value:.2f} GB) is greater than or equal to detected system memory " \
                       f"({total_memory_value:.2f} GB). Reduce `db_cache` to a value safely below available memory.\n" \
                       f"For more info on this setting: {url_info}\n" \
                       f"{disclaimer}"

            elif db_cache_value < 1:
                # db_cache is less than 1 GB, recommend updating based on total memory
                return f"**Plex database cache may be undersized**\n" \
                       f"The configured cache is {db_cache_value:.2f} GB on a system with {total_memory_value:.2f} GB of memory. Consider increasing `db_cache` above 1 GB where available memory and workload justify it.\n" \
                       f"For more info on this setting: {url_info}\n" \
                       f"{disclaimer}"

            return None

    def calculate_memory_recommendation(self, content):
            disclaimer = "These numbers are purely estimates and can vary wildly based on a number of factors " \
                         "(such as the size and number of libraries, and the amount of files/operations/overlays that are being utilized)."

            # Extract memory value from the content
            memory_value = self.extract_memory_value(content)
            overlay_value = self.contains_overlay_path(content)

            # Check if overlay_value is still empty before updating it the second time
            if not overlay_value:
                overlay_value = self.contains_overlay_files(content)

            if memory_value is None:
                return "**Memory information unavailable**\nThe log does not contain the system memory information required for this check. Upload a complete log if you want memory-specific recommendations."

            if memory_value < 4:
                if overlay_value:
                    return f"**Insufficient memory for overlays**\n" \
                           f"Kometa detected {memory_value:.2f} GB of memory and an overlay workload. At least 8 GB is recommended to reduce the risk of slow or failed runs.\n\n" \
                           f"{disclaimer}"
                else:
                    return f"**Low memory available**\n" \
                           f"Kometa detected {memory_value:.2f} GB of memory without overlays. At least 4 GB is recommended for reliable operation.\n\n" \
                           f"{disclaimer}"

            elif memory_value < 8:
                if overlay_value:
                    return f"**Memory below the overlay recommendation**\n" \
                           f"Kometa detected {memory_value:.2f} GB of memory and an overlay workload. Increase available memory to at least 8 GB for more reliable processing.\n\n" \
                           f"{disclaimer}"
                else:
                    return None  # No specific recommendation for memory < 8GB without overlays

            return None

    def calculate_recommendation(self, kometa_scheduled_time, maintenance_start_time=None, maintenance_end_time=None):
            if not kometa_scheduled_time:
                return "**Kometa schedule information unavailable**\nThe log does not contain the scheduled start time required for maintenance-conflict analysis. Confirm that the log is complete and includes the startup configuration."

            kometa_scheduled_time = datetime.strptime(kometa_scheduled_time, '%H:%M').time()

            # Check if maintenance times are provided
            if maintenance_start_time is None or maintenance_end_time is None:
                return None  # Cannot provide recommendations without maintenance times

            maintenance_start_time = datetime.strptime(maintenance_start_time, '%H:%M').time()
            maintenance_end_time = datetime.strptime(maintenance_end_time, '%H:%M').time()

            plex_scheduled_datetime = datetime.combine(datetime.today(), kometa_scheduled_time)
            maintenance_start_datetime = datetime.combine(datetime.today(), maintenance_start_time)
            maintenance_end_datetime = datetime.combine(datetime.today(), maintenance_end_time)

            if maintenance_start_datetime > plex_scheduled_datetime:
                # Plex maintenance period starts on the next day
                time_before_plex_maintenance = (
                        (maintenance_start_datetime - plex_scheduled_datetime).seconds // 60
                )
            else:
                # Plex maintenance period starts on the same day
                time_before_plex_maintenance = (
                        (maintenance_start_datetime - plex_scheduled_datetime).seconds // 60
                )
            # Calculate the buffer until the next plex maintenance in minutes
            buffer_until_next_plex_maintenance = (
                                                         (24 + maintenance_start_time.hour - maintenance_end_time.hour) * 60
                                                 ) % 1440  # 1440 minutes in a day

            run_time_in_minutes = self.run_time.total_seconds() / 60
            time_buffer = timedelta(minutes=buffer_until_next_plex_maintenance)
            mylogger.info(f"time_before_plex_maintenance: {time_before_plex_maintenance}")
            mylogger.info(f"buffer_until_next_plex_maintenance: {buffer_until_next_plex_maintenance}")
            mylogger.info(f"time_buffer until next Plex maintenance: {time_buffer}")
            mylogger.info(f"run_time_in_minutes: {run_time_in_minutes}")
            plex_maint_url = "https://support.plex.tv/articles/202197488-scheduled-server-maintenance/"

            if run_time_in_minutes > 1440:
                return f"**Kometa run exceeds 24 hours**\nThe detected run duration is `{self.run_time}`. Split the workload into smaller scheduled runs to reduce overlap with Plex maintenance and improve recovery from failures.\nTime between Kometa scheduled time and Plex Maintenance start: `{time_buffer}`\nKometa scheduled start time: `{kometa_scheduled_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance end time: `{maintenance_end_time.strftime('%-H:%M')}`\nFor more information on Plex Maintenance, see {plex_maint_url}"

            if run_time_in_minutes > buffer_until_next_plex_maintenance:
                return f"**Kometa run overlaps the next Plex maintenance window**\nThe run duration (`{self.run_time}`) exceeds the available interval before maintenance. Move the Kometa start time, adjust Plex maintenance, or divide the workload into shorter runs.\nTime between Kometa scheduled time and Plex Maintenance start: `{time_buffer}`\nKometa scheduled start time: `{kometa_scheduled_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance end time: `{maintenance_end_time.strftime('%-H:%M')}`\nFor more information on Plex Maintenance, see {plex_maint_url}"

            if maintenance_start_datetime <= plex_scheduled_datetime < maintenance_end_datetime:
                # Provide a message for the case when kometa_scheduled_time is between maintenance start and end times
                return f"**Kometa schedule conflicts with Plex maintenance**\nThe configured Kometa start time (`{kometa_scheduled_time.strftime('%-H:%M')}`) falls within the Plex maintenance window (`{maintenance_start_time.strftime('%-H:%M')}`–`{maintenance_end_time.strftime('%-H:%M')}`). Schedule Kometa outside this interval or adjust the maintenance window.\nThis Run took: `{self.run_time}`\nFor more information on Plex Maintenance, see {plex_maint_url}"

            if run_time_in_minutes > time_before_plex_maintenance:
                return f"**Kometa may still be running when Plex maintenance begins**\nThe detected run duration (`{self.run_time}`) exceeds the time available before maintenance. Start Kometa after maintenance, move the maintenance window, or reduce the run workload.\nTime between Kometa scheduled time and Plex Maintenance start: `{time_buffer}`\nKometa scheduled start time: `{kometa_scheduled_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance start time: `{maintenance_start_time.strftime('%-H:%M')}`\nPlex Scheduled Maintenance end time: `{maintenance_end_time.strftime('%-H:%M')}`\nFor more information on Plex Maintenance, see {plex_maint_url}"

            return None

    def cleanup_content(self, content):
            """
            Clean up the content by removing unnecessary lines and trailing characters.
            """
            cleanup_regex = r"\[(202[0-9])-\d+-\d+ \d+:\d+:\d+,\d+\] \[.*\.py:\d+\] +\[[INFODEBUGWARCTL]*\] +\||^[ ]{65}\|"
            cleaned_content = re.sub(cleanup_regex, "", content)

            # mylogger.info(f"content:\n{content}")
            # mylogger.info(f"cleaned_content:\n{cleaned_content}")

            # Second pass to remove trailing '|'
            lines = cleaned_content.splitlines()
            cleaned_lines = [line.rstrip('|') if line.rstrip().endswith('|') else line for line in lines]
            cleaned_content = "\n".join(cleaned_lines)

            # Third pass to remove trailing spaces
            cleaned_lines = [line.rstrip() for line in cleaned_content.splitlines()]
            cleaned_content = "\n".join(cleaned_lines)
            # mylogger.info(f"cleaned_content3rdpass:\n{cleaned_content}")

            return cleaned_content

    def parse_run_time_value(self, run_time_str):
            cleaned_run_time = run_time_str.strip().strip("|").strip()
            run_time_match = re.fullmatch(
                r"(?:(?P<days>\d+)\s+day(?:s)?,?\s+)?(?P<hours>\d+):(?P<minutes>\d{1,2}):(?P<seconds>\d{1,2})",
                cleaned_run_time,
            )
            if not run_time_match:
                mylogger.warning("Unable to parse run_time_str: %s", run_time_str)
                return None

            return timedelta(
                days=int(run_time_match.group("days") or 0),
                hours=int(run_time_match.group("hours")),
                minutes=int(run_time_match.group("minutes")),
                seconds=int(run_time_match.group("seconds")),
            )

    def extract_last_lines(self, content):
            lines = content.splitlines()

            # Find the index of the last line containing "Finished: "
            finished_run_index = next(
                (i for i, line in enumerate(reversed(lines)) if "Finished: " in line and "Run Time: " in line), None)

            if finished_run_index is not None:
                # Calculate the starting index of the finished run lines
                start_index = len(lines) - finished_run_index - 5  # Go back by 5 lines
                extracted_lines = [line.lstrip() for line in lines[start_index:]]
                # Extract run time from the line that contains "Run Time: "
                run_time_line = next((line for line in extracted_lines if "Run Time: " in line), None)

                if run_time_line:
                    # Extract the run time value
                    run_time_str = run_time_line.split("Run Time: ")[1].strip()
                    mylogger.info(f"run_time_str: {run_time_str}")
                    self.run_time = self.parse_run_time_value(run_time_str)
                    if self.run_time is not None:
                        mylogger.info(f"self.run_time: {self.run_time}")
                    return "\n".join(extracted_lines)
                else:
                    # If "Run Time: " is not found, return None for run time
                    return "\n".join(extracted_lines)
            else:
                return None

    def format_contiguous_lines(self, line_numbers):
            formatted_ranges = []
            start_range = line_numbers[0]
            end_range = line_numbers[0]

            for i in range(1, len(line_numbers)):
                if line_numbers[i] == line_numbers[i - 1] + 1:
                    end_range = line_numbers[i]
                else:
                    if start_range == end_range:
                        formatted_ranges.append(str(start_range))
                    else:
                        formatted_ranges.append(f"{start_range}-{end_range}")
                    start_range = end_range = line_numbers[i]

            if start_range == end_range:
                formatted_ranges.append(str(start_range))
            else:
                formatted_ranges.append(f"{start_range}-{end_range}")

            return ", ".join(formatted_ranges)

    def make_recommendations(self, content, incomplete_message):
            self.checkfiles_flg = None
            lines = content.splitlines()
            special_check_lines = []
            anidb69_errors = []
            anidb_auth_errors = []
            api_blank_errors = []
            bad_version_found_errors = []
            cache_false = []
            checkFiles = []
            current_year = []
            other_award = []
            convert_errors = []
            corrupt_image_errors = []
            critical_errors = []
            error_errors = []
            warning_errors = []
            delete_unmanaged_collections_errors = []
            flixpatrol_errors = []
            flixpatrol_paywall = []
            git_kometa_errors = []
            pmm_legacy_errors = []
            image_size = []
            incomplete_errors = []
            internal_server_errors = []
            lsio_errors = []
            mal_connection_errors = []
            mass_update_errors = []
            mdblist_attr_errors = []
            mdblist_errors = []
            mdblist_api_limit_errors = []
            metadata_attribute_errors = []
            metadata_load_errors = []
            missing_path_errors = []
            new_version_found_errors = []
            new_plexapi_version_found_errors = []
            no_items_found_errors = []
            omdb_errors = []
            omdb_api_limit_errors = []
            overlays_bloat = []
            overlay_font_missing = []
            overlay_apply_errors = []
            overlay_image_missing = []
            overlay_level_errors = []
            overlay_load_errors = []
            playlist_load_errors = []
            playlist_errors = []
            plex_lib_errors = []
            plex_regex_errors = []
            plex_url_errors = []
            rounding_errors = []
            ruamel_errors = []
            run_order_errors = []
            security_vuln_hits = []
            traceback_errors = []
            tautulli_url_errors = []
            tautulli_apikey_errors = []
            timeout_errors = []
            to_be_configured_errors = []
            tmdb_api_errors = []
            tmdb_fail_errors = []
            trakt_connection_errors = []

            for idx, line in enumerate(lines, start=1):
                if "run_order:" in line:
                    next_line = lines[idx] if idx < len(lines) else None
                    if next_line and "- operations" not in next_line:
                        run_order_errors.append(idx)
                if "No Anime Found for AniDB ID: 69" in line:
                    anidb69_errors.append(idx)
                if re.search(r'\bcache: false\b', line):
                    cache_false.append(idx)
                if self.server_versions and (
                        "mass_user_rating_update" in line or "mass_episode_user_ratings_update" in line):

                    # Set to keep track of unique (server_name, server_version, idx) combinations
                    unique_entries = set()

                    # Iterate through each (server_name, server_version) tuple in self.server_versions
                    for server_name, server_version in self.server_versions:

                        # Create a unique identifier for the tuple
                        identifier = (server_name, server_version, idx)

                        # Check if the identifier is not in unique_entries (i.e., it's a new entry)
                        if identifier not in unique_entries:
                            # Append server info to rounding_errors
                            rounding_errors.append((server_name, server_version, idx))
                            # Add the identifier to unique_entries set to mark it as processed
                            unique_entries.add(identifier)

                # Detect PMS versions in "Connected to server ..." lines and flag the vulnerable range
                m = re.search(
                    r"Connected to server\s+(.+?)\s+(?:\(?\s*(?:version|Version:)\s+)(\d+\.\d+\.\d+\.\d+(?:-[A-Za-z0-9]+)?)",
                    line
                )
                if m:
                    sn = m.group(1).strip()
                    ver = m.group(2).strip()
                    if _version_in_inclusive_range(ver, _PMS_VULN_LOW, _PMS_VULN_HIGH):
                        security_vuln_hits.append((sn, ver, idx))

                if "Config Error: anidb sub-attribute" in line or "AniDB Error: Login failed" in line:
                    anidb_auth_errors.append(idx)
                elif "apikey is blank" in line:
                    api_blank_errors.append(idx)
                elif "1.32.7" in line and "Connected to server " in line:
                    bad_version_found_errors.append(idx)
                elif "Convert Warning: No " in line and "ID Found for" in line:
                    convert_errors.append(idx)
                elif "PIL.UnidentifiedImageError: cannot" in line:
                    corrupt_image_errors.append(idx)
                elif "checkFiles=1" in line:
                    checkFiles.append(idx)
                elif "current_year" in line:
                    current_year.append(idx)
                elif "other_award" in line:
                    other_award.append(idx)
                elif "delete_unmanaged_collections" in line:
                    delete_unmanaged_collections_errors.append(idx)
                elif "internal_server_error" in line:
                    internal_server_errors.append(idx)
                elif "FlixPatrol Error: " in line and "failed to parse" in line:
                    flixpatrol_errors.append(idx)
                elif "flixpatrol" in line and "- pmm:" in line:
                    flixpatrol_paywall.append(idx)
                elif "- git: PMM" in line:
                    git_kometa_errors.append(idx)
                elif "- pmm: " in line:
                    pmm_legacy_errors.append(idx)
                elif ", in _upload_image" in line:
                    image_size.append(idx)
                elif "(Linuxserver" in line and "Version:" in line:
                    lsio_errors.append(idx)
                elif "My Anime List Connection Failed" in line:
                    mal_connection_errors.append(idx)
                elif "Config Error: Operation mass_" in line and "without a successful" in line:
                    mass_update_errors.append(idx)
                elif "mdblist_list attribute not allowed with Collection Level: Season" in line:
                    mdblist_attr_errors.append(idx)
                elif "MdbList Error: Invalid API key" in line:
                    mdblist_errors.append(idx)
                elif "MDBList Error: API Limit Reached" in line or "MDBList Error: API Rate Limit Reached" in line:
                    mdblist_api_limit_errors.append(idx)
                elif "metadata attribute is required" in line:
                    metadata_attribute_errors.append(idx)
                elif "Metadata File Failed To Load" in line:
                    metadata_load_errors.append(idx)
                elif "Overlay File Failed To Load" in line:
                    overlay_load_errors.append(idx)
                elif "Playlist File Failed To Load" in line:
                    playlist_load_errors.append(idx)
                elif "missing_path" in line or "save_missing" in line:
                    missing_path_errors.append(idx)
                elif "Newest Version: " in line:
                    new_version_found_errors.append(idx)
                elif "requires an update to:" in line:
                    new_plexapi_version_found_errors.append(idx)
                elif "OMDb Error: Invalid API key" in line:
                    omdb_errors.append(idx)
                elif "OMDb Error: Request limit reached" in line:
                    omdb_api_limit_errors.append(idx)
                elif "Overlay Error: Poster already has an Overlay" in line:
                    overlay_apply_errors.append(idx)
                elif "| Overlay Error: Overlay Image not found" in line:
                    overlay_image_missing.append(idx)
                elif "overlay_level:" in line:
                    overlay_level_errors.append(idx)
                elif "Plex Error: No Items found in Plex" in line:
                    no_items_found_errors.append(idx)
                elif "Overlay Error: font:" in line:
                    overlay_font_missing.append(idx)
                elif "Reapply Overlays: True" in line or "Reset Overlays: [" in line:
                    overlays_bloat.append(idx)
                elif "Playlist Error: Library: " in line and "not defined" in line:
                    playlist_errors.append(idx)
                elif "Plex Error: Plex Library " in line and "not found" in line:
                    plex_lib_errors.append(idx)
                elif "Plex Error: " in line and "No matches found with regex pattern" in line:
                    plex_regex_errors.append(idx)
                elif "Plex Error: Plex url is invalid" in line:
                    plex_url_errors.append(idx)
                elif "ruamel.yaml." in line:
                    ruamel_errors.append(idx)
                elif "TMDb Error: Invalid API key" in line:
                    tmdb_api_errors.append(idx)
                elif "Traceback (most recent call last):" in line:
                    traceback_errors.append(idx)
                elif "Tautulli Error: Invalid apikey" in line:
                    tautulli_apikey_errors.append(idx)
                elif "Tautulli Error: Invalid URL" in line:
                    tautulli_url_errors.append(idx)
                elif "timed out." in line:
                    timeout_errors.append(idx)
                elif "Failed to Connect to https://api.themoviedb.org/3" in line:
                    tmdb_fail_errors.append(idx)
                elif "Error: " in line and " requires " in line and " to be configured" in line:
                    to_be_configured_errors.append(idx)
                elif "Trakt Connection Failed" in line:
                    trakt_connection_errors.append(idx)
                elif "[CRITICAL]" in line:
                    critical_errors.append(idx)
                elif "[ERROR]" in line:
                    error_errors.append(idx)
                elif "[WARNING]" in line:
                    warning_errors.append(idx)

            if anidb69_errors:
                url_line = "[https://kometa.wiki/en/latest/config/anidb]"
                formatted_errors = self.format_contiguous_lines(anidb69_errors)
                anidb69_error_message = (
                    "**AniDB connection test failed**\n"
                    "Kometa could not complete its AniDB connectivity test using AniDB ID 69. Verify network access and the AniDB configuration, then retry the run.\n"
                    f"For more information on configuring AniDB, {url_line}\n"
                    f"{len(anidb69_errors)} line(s) with ANIDB69 errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(anidb69_error_message)

            if anidb_auth_errors:
                url_line = "[https://kometa.wiki/en/latest/config/anidb]"
                formatted_errors = self.format_contiguous_lines(anidb_auth_errors)
                anidb_auth_errors_message = (
                    "**AniDB authentication failed**\n"
                    "Kometa could not authenticate with AniDB. Review the AniDB credentials in `config.yml`, correct any invalid values, and retry the run.\n"
                    f"For more information on configuring AniDB, {url_line}\n"
                    f"{len(anidb_auth_errors)} line(s) with ANIDB AUTH errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(anidb_auth_errors_message)

            if api_blank_errors:
                url_line = "[https://kometa.wiki/en/latest/config/trakt/?q=api]"
                formatted_errors = self.format_contiguous_lines(api_blank_errors)
                api_blank_error_message = (
                    "**Required API key is missing**\n"
                    "A configured service requires an API key, but the value is empty. Identify the service on the referenced log lines and add a valid API key to `config.yml`.\n"
                    f"For more information on configuring API keys, {url_line}\n"
                    f"{len(api_blank_errors)} line(s) with BLANK API KEY errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(api_blank_error_message)

            if bad_version_found_errors:
                url_line = "[https://forums.plex.tv/t/refresh-endpoint-put-post-requests-started-throwing-404s-in-version-1-32-7-7484/853588]"
                formatted_errors = self.format_contiguous_lines(bad_version_found_errors)
                bad_version_found_errors_message = (
                    "**Incompatible Plex version detected**\n"
                    "Plex version `1.32.7.*` has known compatibility issues with Kometa. Upgrade or downgrade Plex to a supported release before running Kometa again.\n"
                    f"For more information on this issue, {url_line}\n"
                    f"{len(bad_version_found_errors)} line(s) with Plex Version 1.32.7.*. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(bad_version_found_errors_message)

            if cache_false:
                url_line = "[https://kometa.wiki/en/latest/config/settings#cache]"
                formatted_errors = self.format_contiguous_lines(cache_false)
                cache_false_message = (
                    "**Kometa cache is disabled**\n"
                    "The configuration contains `cache: false`. Enable the cache unless you have a specific reason not to, as caching generally improves run performance.\n"
                    f"For more information on handling this, {url_line}\n"
                    f"{len(cache_false)} line(s) with `cache: false`. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(cache_false_message)

            if checkFiles:
                formatted_errors = self.format_contiguous_lines(checkFiles)
                checkFiles_message = (
                    "**Diagnostic file check enabled**\n"
                    "The log contains `checkFiles=1`, indicating that diagnostic file checking is enabled. Include the referenced lines when requesting support from the Kometa team.\n"
                    f"{len(checkFiles)} line(s) with `checkFiles=1` messages. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(checkFiles_message)

            # if current_year:
            #     url_line = "[https://kometa.wiki/en/latest/files/dynamic_types/?h=latest#imdb-awards]"
            #     formatted_errors = self.format_contiguous_lines(current_year)
            #     current_year_message = (
            #             "**Legacy schema detected**\n"
            #             "As of 1.20 `current_year` is no longer used and should be replaced with `latest`.\n"
            #             f"For more information on handling these, {url_line}\n"
            #             f"{len(current_year)} line(s) with `current_year` issues. Line number(s): {formatted_errors}"
            #     )
            #     special_check_lines.append(current_year_message)

            if other_award:
                url_line = "[https://kometa.wiki/en/latest/kometa/faqs/?h=other_award#pmm-120-release-changes]"
                formatted_errors = self.format_contiguous_lines(other_award)
                other_award_message = (
                    "**Legacy `other_award` setting detected**\n"
                    "The `other_award` setting is no longer supported. Remove it and configure the relevant award files individually.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(other_award)} line(s) with `other_award` issues. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(other_award_message)

            if critical_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Bcritical%5D#critical]"
                formatted_errors = self.format_contiguous_lines(critical_errors)
                critical_error_message = (
                    "**Critical Kometa messages detected**\n"
                    "The log contains critical messages that may have stopped all or part of the run. Review the referenced lines first and resolve their underlying causes before retrying.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(critical_errors)} line(s) with [CRITICAL] messages. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(critical_error_message)

            if error_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
                formatted_errors = self.format_contiguous_lines(error_errors)
                error_error_message = (
                    "**Kometa errors detected**\n"
                    "The log contains error messages, and some requested work may not have completed. Review each referenced error in context and address unresolved errors before the next run.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(error_errors)} line(s) with [ERROR] messages. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(error_error_message)

            if warning_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Bwarning%5D#warning]"
                formatted_errors = self.format_contiguous_lines(warning_errors)
                warning_error_message = (
                    "**Kometa warnings detected**\n"
                    "The log contains warning messages. Review the referenced lines to confirm that they are expected for your configuration.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(warning_errors)} line(s) with [WARNING] messages. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(warning_error_message)

            if convert_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/#warning]"
                formatted_errors = self.format_contiguous_lines(convert_errors)
                convert_error_message = (
                    "**Metadata ID conversion failed**\n"
                    "Kometa could not cross-reference an item because a required external ID was unavailable. Verify the item on the source services and correct the missing ID where possible.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(convert_errors)} line(s) with Convert Warnings. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(convert_error_message)

            if corrupt_image_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/#error]"
                formatted_errors = self.format_contiguous_lines(corrupt_image_errors)
                corrupt_image_message = (
                    "**Unreadable image file detected**\n"
                    "Kometa could not identify an image file. Confirm that it is not corrupt, uses a supported format, and can be opened normally.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(corrupt_image_errors)} line(s) with `PIL.UnidentifiedImageError` reported. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(corrupt_image_message)

            if delete_unmanaged_collections_errors:
                url_line = "[https://kometa.wiki/en/latest/config/operations/#delete-collections]"
                formatted_errors = self.format_contiguous_lines(delete_unmanaged_collections_errors)
                delete_unmanaged_collections_errors_message = (
                    "**Legacy collection deletion setting detected**\n"
                    "`delete_unmanaged_collections` is no longer supported. Replace it with the current collection deletion setting.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(delete_unmanaged_collections_errors)} line(s) with `delete_unmanaged_collections` errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(delete_unmanaged_collections_errors_message)

            if flixpatrol_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/faqs/?h=flixpatrol#flixpatrol]"
                formatted_errors = self.format_contiguous_lines(flixpatrol_errors)
                flixpatrol_error_message = (
                    "**FlixPatrol data could not be parsed**\n"
                    "Kometa received an unexpected response from FlixPatrol. Confirm that the source remains available and review current Kometa guidance.\n"
                    f"For more information on handling FlixPatrol errors, {url_line}\n"
                    f"{len(flixpatrol_errors)} line(s) with FlixPatrol errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(flixpatrol_error_message)

            if flixpatrol_paywall:
                url_line = "[https://flixpatrol.com/about/premium/]"
                url_line2 = "[https://discord.com/channels/822460010649878528/1099773891733377065/1214929432754651176]"
                formatted_errors = self.format_contiguous_lines(flixpatrol_paywall)
                flixpatrol_paywall_message = (
                    "**FlixPatrol source requires a subscription**\n"
                    "The configured FlixPatrol list is unavailable with the current account access. Use an accessible list or provide the required subscription.\n"
                    f"For more information on the FlixPatrol paywall, {url_line}\n"
                    f"{len(flixpatrol_paywall)} line(s) with `- pmm: flixpatrol` detected. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(flixpatrol_paywall_message)

            if git_kometa_errors:
                url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
                formatted_errors = self.format_contiguous_lines(git_kometa_errors)
                git_kometa_error_message = (
                    "**Legacy Kometa repository reference detected**\n"
                    "The configuration still references `git: PMM`. Update it to the current Kometa repository reference.\n"
                    f"For more information on handling this, {url_line}\n"
                    f"{len(git_kometa_errors)} line(s) with OLD Kometa YAML. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(git_kometa_error_message)

            if pmm_legacy_errors:
                url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
                formatted_errors = self.format_contiguous_lines(pmm_legacy_errors)
                pmm_legacy_error_message = (
                    "**Legacy PMM configuration detected**\n"
                    "The configuration contains the former `pmm:` schema. Migrate it to the current Kometa schema.\n"
                    f"For more information on handling this, {url_line}\n"
                    f"{len(pmm_legacy_errors)} line(s) with PRE Kometa YAML. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(pmm_legacy_error_message)

            if image_size:
                url_line = "[https://www.google.com]"
                formatted_errors = self.format_contiguous_lines(image_size)
                image_size_message = (
                    "**Image exceeds the permitted size**\n"
                    "A configured image exceeds the destination service's size limit. Resize or optimize the image and retry the run.\n"
                    f"This usually means that you have internal server errors (500) as well in this log. Change the image to one that is less than 10MB. For more information on handling this, {url_line}\n"
                    f"{len(image_size)} line(s) with IMAGE SIZE errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(image_size_message)

            if incomplete_message:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/#providing-log-files-on-discord]"
                incomplete_errors_message = (
                    "**Log appears incomplete**\n"
                    "The uploaded file does not contain a complete Kometa run. Upload the full log, including the end-of-run summary, for reliable diagnostics.\n"
                    f"For more information on providing logs, {url_line}\n"
                )
                special_check_lines.append(incomplete_errors_message)

            if internal_server_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/faqs/?h=errors+issues#errors-issues]"
                formatted_errors = self.format_contiguous_lines(internal_server_errors)
                internal_server_error_message = (
                    "**Remote service returned an internal error**\n"
                    "A service used by Kometa returned a server-side error. Retry later; if it persists, review the service and its status.\n"
                    f"For more information on handling internal server errors, {url_line}\n"
                    f"{len(internal_server_errors)} line(s) with INTERNAL SERVER errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(internal_server_error_message)

            if lsio_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/install/images/?h=linuxserver#linuxserver]"
                formatted_errors = self.format_contiguous_lines(lsio_errors)
                lsio_error_message = (
                    "**LinuxServer container image detected**\n"
                    "This installation uses the LinuxServer image. Consider migrating to the official image for current updates and support.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(lsio_errors)} line(s) with LINUXSERVER IMAGE issues. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(lsio_error_message)

            if mal_connection_errors:
                url_line = "[https://kometa.wiki/en/latest/config/myanimelist]"
                formatted_errors = self.format_contiguous_lines(mal_connection_errors)
                mal_connection_error_message = (
                    "**MyAnimeList connection failed**\n"
                    "Verify the configured credentials, network access, and service availability before retrying.\n"
                    f"For more information on configuring the My Anime List (MAL) service, {url_line}\n"
                    f"{len(mal_connection_errors)} line(s) with MY ANIME LIST CONNECTION errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(mal_connection_error_message)

            if mass_update_errors:
                url_line = "[https://kometa.wiki/en/latest/config/operations]"
                formatted_errors = self.format_contiguous_lines(mass_update_errors)
                mass_update_errors_message = (
                    "**Mass update prerequisite failed**\n"
                    "A mass update was skipped because a required preceding operation did not complete. Resolve the earlier error, then rerun Kometa.\n"
                    f"For more information on `mass_*_update` operations, {url_line}\n"
                    f"{len(mass_update_errors)} line(s) with `mass_*_update` config errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(mass_update_errors_message)

            if mdblist_attr_errors:
                url_line = "[https://kometa.wiki/en/latest/files/builders/mdblist/?h=mdblist+builders]"
                formatted_errors = self.format_contiguous_lines(mdblist_attr_errors)
                mdblist_attr_error_message = (
                    "**MDBList attribute is invalid at this collection level**\n"
                    "`mdblist_list` cannot be used for a season-level collection. Remove it or use a supported collection level.\n"
                    f"For more information on MDBList configuration, {url_line}\n"
                    f"{len(mdblist_attr_errors)} line(s) with MDBList attribute errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(mdblist_attr_error_message)

            if mdblist_errors:
                url_line = "[https://kometa.wiki/en/latest/config/mdblist/?h=mdblist+attributes#mdblist-attributes]"
                formatted_errors = self.format_contiguous_lines(mdblist_errors)
                mdblist_error_message = (
                    "**MDBList API key is invalid**\n"
                    "Replace the configured key with a valid MDBList API key and retry the run.\n"
                    f"For more information on configuring MdbList, {url_line}\n"
                    f"{len(mdblist_errors)} line(s) with MDBLIST errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(mdblist_error_message)

            if mdblist_api_limit_errors:
                url_line = "[https://kometa.wiki/en/latest/config/mdblist/?h=mdblist+attributes#mdblist-attributes]"
                formatted_errors = self.format_contiguous_lines(mdblist_api_limit_errors)
                mdblist_api_limit_error_message = (
                    "**MDBList API limit reached**\n"
                    "Wait for the limit to reset or review the account's API allowance before retrying.\n"
                    f"For more information on configuring MdbList, {url_line}\n"
                    f"{len(mdblist_api_limit_errors)} line(s) with MDBLIST API Limit errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(mdblist_api_limit_error_message)

            if metadata_attribute_errors:
                url_line = "[https://kometa.wiki/en/latest/config/files/#example]"
                formatted_errors = self.format_contiguous_lines(metadata_attribute_errors)
                metadata_attribute_errors_message = (
                    "**Required metadata attribute is missing**\n"
                    "Review the referenced file and add the required value using the documented schema.\n"
                    f"Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(metadata_attribute_errors)} line(s) with METADATA ATTRIBUTE errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(metadata_attribute_errors_message)

            if metadata_load_errors:
                url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
                formatted_errors = self.format_contiguous_lines(metadata_load_errors)
                metadata_load_errors_message = (
                    "**Metadata file failed to load**\n"
                    "Review the error for an invalid path, inaccessible URL, or YAML/schema problem, then correct the file definition.\n"
                    f"Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(metadata_load_errors)} line(s) with METADATA LOAD errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(metadata_load_errors_message)

            if overlay_load_errors:
                url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
                formatted_errors = self.format_contiguous_lines(overlay_load_errors)
                overlay_load_errors_message = (
                    "**Overlay file failed to load**\n"
                    "Review the error for an invalid path, inaccessible URL, or YAML/schema problem, then correct the file definition.\n"
                    "Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(overlay_load_errors)} line(s) with OVERLAY LOAD errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(overlay_load_errors_message)

            if playlist_load_errors:
                url_line = "[https://kometa.wiki/en/latest/config/overview/?h=configuration]"
                formatted_errors = self.format_contiguous_lines(playlist_load_errors)
                playlist_load_errors_message = (
                    "**Playlist file failed to load**\n"
                    "Review the error for an invalid path, inaccessible URL, or YAML/schema problem, then correct the file definition.\n"
                    "Within the attached log file, go to the indicated line(s) for more details on the exact issue and take actions to fix.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(playlist_load_errors)} line(s) with PLAYLIST LOAD errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(playlist_load_errors_message)

            if missing_path_errors:
                url_line = "[https://kometa.wiki/en/latest/config/libraries/?h=report_path#attributes]"
                formatted_errors = self.format_contiguous_lines(missing_path_errors)
                missing_path_errors_message = (
                    "**Legacy missing-item setting detected**\n"
                    "Replace `missing_path` or `save_missing` with the current missing-item reporting configuration.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(missing_path_errors)} line(s) with `missing_path` or `save_missing` errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(missing_path_errors_message)

            if new_plexapi_version_found_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/#checking-kometa-version]"
                formatted_errors = self.format_contiguous_lines(new_plexapi_version_found_errors)
                note = f"**(as of {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})**"
                new_plexapi_version_found_errors_message = (
                    "**Python dependency update required**\n"
                    "Update the package identified on the referenced line, then restart Kometa.\n"
                    f"For more information on updating, {url_line}\n"
                    f"{len(new_plexapi_version_found_errors)} line(s) with New Python Module Updates. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(new_plexapi_version_found_errors_message)

            if new_version_found_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/#checking-kometa-version]"
                formatted_errors = self.format_contiguous_lines(new_version_found_errors)
                note = f"**(as of {datetime.now().strftime('%Y-%m-%d %H:%M:%S')})**"
                new_version_found_errors_message = (
                    "**Kometa update available**\n"
                    "Review the release notes and update when convenient to receive current fixes and features.\n"
                    f"Current version: {self.current_kometa_version}\n"
                    f"Newest version at the time of this log: {self.kometa_newest_version}\n"
                    f"Latest versions {note}: master {self.version_master}; develop {self.version_develop}; nightly {self.version_nightly}.\n"
                    f"For more information on updating, {url_line}\n"
                    f"{len(new_version_found_errors)} line(s) with New Version errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(new_version_found_errors_message)

            if no_items_found_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
                formatted_errors = self.format_contiguous_lines(no_items_found_errors)
                no_items_error_message = (
                    "**No matching Plex items found**\n"
                    "Verify the library, filters, source IDs, and item availability in Plex.\n"
                    f"For more information on this error, {url_line}\n"
                    f"{len(no_items_found_errors)} line(s) with 'No Items found in Plex' errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(no_items_error_message)

            if omdb_errors:
                url_line = "[https://kometa.wiki/en/latest/config/omdb/#omdb-attributes]"
                formatted_errors = self.format_contiguous_lines(omdb_errors)
                omdb_error_message = (
                    "**OMDb API key is invalid**\n"
                    "Replace the configured key with a valid OMDb API key and retry the run.\n"
                    f"For more information on configuring OMDb, {url_line}\n"
                    f"{len(omdb_errors)} line(s) with OMDb errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(omdb_error_message)

            if omdb_api_limit_errors:
                url_line = "[https://kometa.wiki/en/latest/config/omdb/?h=omdb#omdb-attributes]"
                formatted_errors = self.format_contiguous_lines(omdb_api_limit_errors)
                omdb_api_limit_error_message = (
                    "**OMDb request limit reached**\n"
                    "Wait for the limit to reset or review the account's API allowance.\n"
                    f"For more information on configuring OMDB, {url_line}\n"
                    f"{len(omdb_api_limit_errors)} line(s) with OMDB API Limit errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(omdb_api_limit_error_message)

            if overlay_font_missing:
                url_line = "[https://kometa.wiki/en/latest/showcase/overlays/?h=font#example-2]"
                formatted_errors = self.format_contiguous_lines(overlay_font_missing)
                overlay_font_missing_message = (
                    "**Overlay font file is missing**\n"
                    "Verify the configured path, filename, letter case, and container accessibility.\n"
                    f"{len(overlay_font_missing)} line(s) with `Overlay Error: font:` errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(overlay_font_missing_message)

            if overlays_bloat:
                url_line = "[https://kometa.wiki/en/latest/kometa/scripts/imagemaid]"
                formatted_errors = self.format_contiguous_lines(overlays_bloat)
                overlays_bloat_message = (
                    "**Overlay reapplication or reset detected**\n"
                    "This can significantly increase processing time and storage activity. Use it only when a full rebuild is required.\n"
                    f"{len(overlays_bloat)} line(s) with reapply_overlays or reset_overlays. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(overlays_bloat_message)

            if overlay_apply_errors:
                url_line = "[https://kometa.wiki/en/latest/defaults/overlays]"
                url_line2 = "[https://kometa.wiki/en/latest/kometa/guides/assets]"
                formatted_errors = self.format_contiguous_lines(overlay_apply_errors)
                overlay_apply_errors_message = (
                    "**Poster already contains an overlay**\n"
                    "Restore the original artwork or use the documented overlay reset process before reapplying overlays.\n"
                    f"For more information on overlays, {url_line}\n"
                    f"For more information on the asset pipeline, {url_line2}\n"
                    f"{len(overlay_apply_errors)} line(s) with OVERLAY APPLY errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(overlay_apply_errors_message)

            if overlay_image_missing:
                url_line = "[https://kometa.wiki/en/latest/defaults/overlays]"
                formatted_errors = self.format_contiguous_lines(overlay_image_missing)
                overlay_image_missing_message = (
                    "**Overlay image file is missing**\n"
                    "Verify the configured path, filename, letter case, and container accessibility.\n"
                    f"For more information on overlays, {url_line}\n"
                    f"{len(overlay_image_missing)} line(s) with OVERLAY IMAGE MISSING errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(overlay_image_missing_message)

            if overlay_level_errors:
                url_line = "[https://kometa.wiki/en/latest/files/settings/?h=builder_level]"
                formatted_errors = self.format_contiguous_lines(overlay_level_errors)
                overlay_level_errors_message = (
                    "**Legacy `overlay_level` setting detected**\n"
                    "Replace `overlay_level` with `builder_level` using the current overlay schema.\n"
                    f"For more information on handling these, {url_line}\n"
                    f"{len(overlay_level_errors)} line(s) with `overlay_level` errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(overlay_level_errors_message)

            if playlist_errors:
                url_line = "[https://kometa.wiki/en/latest/defaults/playlist/?h=playlist]"
                formatted_errors = self.format_contiguous_lines(playlist_errors)
                playlist_error_message = (
                    "**Playlist references an unknown Plex library**\n"
                    "Correct the library name or provide the appropriate template variable for your environment.\n"
                    f"For more information: {url_line}\n"
                    f"{len(playlist_errors)} line(s) with playlist errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(playlist_error_message)

            # Extract scheduled run time
            if self.run_time is None or not isinstance(self.run_time, timedelta):
                self.run_time = timedelta(hours=0, minutes=0, seconds=0)
            kometa_scheduled_time = self.extract_scheduled_run_time(content)
            maintenance_start_time, maintenance_end_time = self.extract_maintenance_times(content)
            kometa_time_recommendation = self.calculate_recommendation(kometa_scheduled_time, maintenance_start_time,
                                                                       maintenance_end_time)
            if kometa_time_recommendation:
                special_check_lines.append(kometa_time_recommendation)

            # Extract Memory value:
            kometa_mem_recommendation = self.calculate_memory_recommendation(content)
            if kometa_mem_recommendation:
                special_check_lines.append(kometa_mem_recommendation)

            # Extract DB Cache value:
            kometa_db_cache_recommendation = self.make_db_cache_recommendations(content)
            if kometa_db_cache_recommendation:
                special_check_lines.append(kometa_db_cache_recommendation)

            # Extract WSL information
            wsl_recommendation = self.detect_wsl_and_recommendation(content)
            if wsl_recommendation:
                special_check_lines.append(wsl_recommendation)

            if plex_regex_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
                formatted_errors = self.format_contiguous_lines(plex_regex_errors)
                plex_regex_error_message = (
                    "**Plex regular expression matched no items**\n"
                    "Confirm that the pattern and target field are correct; no action is needed if an empty result is expected.\n"
                    f"For more information on handling regex issues, {url_line}\n"
                    f"{len(plex_regex_errors)} line(s) with Plex regex errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(plex_regex_error_message)

            if plex_lib_errors:
                url_line = "[https://kometa.wiki/en/latest/config/settings/?h=show_options#show-options]"
                formatted_errors = self.format_contiguous_lines(plex_lib_errors)
                plex_lib_error_message = (
                    "**Plex library was not found**\n"
                    "Verify spelling and letter case, and enable `show_options: true` to review available names.\n"
                    f"For more information on configuring the show_options, {url_line}\n"
                    f"{len(plex_lib_errors)} line(s) with PLEX LIBRARY errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(plex_lib_error_message)

            if plex_url_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-plex-url-and-token]"
                formatted_errors = self.format_contiguous_lines(plex_url_errors)
                plex_url_error_message = (
                    "**Plex URL is invalid**\n"
                    "Verify the scheme, hostname, port, and container networking, then test connectivity.\n"
                    f"For more information on configuring the Plex URL, {url_line}\n"
                    f"{len(plex_url_errors)} line(s) with PLEX URL errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(plex_url_error_message)

            if rounding_errors:
                url_line = "[https://forums.plex.tv/t/plex-rounding-down-user-ratings-when-set-via-api/875806/8]"

                # Construct the message with server names and versions
                rounding_errors_message = (
                    "**Plex user-rating rounding issue detected**\n"
                    "The detected Plex version may round ratings written through the API during mass updates. Upgrade to `1.40.3.8555` or later before applying these operations.\n"
                    f"For more information on this issue, {url_line}\n"
                    f"Detected issues on the following servers:\n"
                )
                # Append server names, versions, and line numbers to the message
                for server_name, server_version, line_num in rounding_errors:
                    rounding_errors_message += f"- Server: {server_name}, Version: {server_version}, Line: {line_num}\n"

                special_check_lines.append(rounding_errors_message)

            if ruamel_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/yaml/]"
                formatted_errors = self.format_contiguous_lines(ruamel_errors)
                ruamel_error_message = (
                    "**YAML parsing failed**\n"
                    "Review the `ruamel.yaml` error near the referenced lines and correct indentation, spacing, quoting, or structure.\n"
                    f"For more information on handling YAML issues, {url_line}\n"
                    f"{len(ruamel_errors)} line(s) with YAML errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(ruamel_error_message)

            if run_order_errors:
                url_line = "[https://kometa.wiki/en/latest/config/settings/?h=run_order#run-order]"
                formatted_errors = self.format_contiguous_lines(run_order_errors)
                run_order_error_message = (
                    "**Recommended run order is not configured**\n"
                    "Move `- operations` before metadata and overlays unless your workflow specifically requires another order.\n"
                    f"For more information on this, {url_line}\n"
                    f"{len(run_order_errors)} line(s) with RUN_ORDER warnings. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(run_order_error_message)

            if security_vuln_hits:
                seen = set()
                items = []
                for sn, ver, ln in security_vuln_hits:
                    key = (sn, ver, ln)
                    if key not in seen:
                        seen.add(key)
                        items.append((sn, ver, ln))

                vuln_low_str = ".".join(map(str, _PMS_VULN_LOW))
                vuln_high_str = ".".join(map(str, _PMS_VULN_HIGH))
                url_line = "[https://forums.plex.tv/t/plex-media-server-security-update/928341]"

                msg = (
                    "**Vulnerable Plex Media Server version detected**\n"
                    "A server is running a Plex release within the identified vulnerable range. Upgrade Plex Media Server to a secure release immediately and verify the version after restart.\n"
                    f"**Affected range:** `{vuln_low_str}` **through** `{vuln_high_str}`\n"
                    f"For more information on this see url: {url_line}\n"
                    f"{len(security_vuln_hits)} line(s) with these errors."
                    "Detected on:\n"
                )
                for sn, ver, ln in items:
                    msg += f"- Server: {sn}, Version: `{ver}`, Line: {ln}\n"

                special_check_lines.append(msg)

            if traceback_errors:
                url_line = "[https://kometa.wiki/en/latest/config/tautulli]"
                formatted_errors = self.format_contiguous_lines(traceback_errors)
                traceback_errors_message = (
                    "**Unhandled Kometa exception detected**\n"
                    "Review the first exception and its preceding context, resolve the cause, and retry.\n"
                    f"{len(traceback_errors)} line(s) with Traceback errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(traceback_errors_message)

            if tautulli_apikey_errors:
                url_line = "[https://kometa.wiki/en/latest/config/tautulli]"
                formatted_errors = self.format_contiguous_lines(tautulli_apikey_errors)
                tautulli_apikey_errors_message = (
                    "**Tautulli API key is invalid**\n"
                    "Replace the configured key with a valid Tautulli API key and retry the run.\n"
                    f"For more information on configuring Tautulli, {url_line}\n"
                    f"{len(tautulli_apikey_errors)} line(s) with Tautulli errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(tautulli_apikey_errors_message)

            if tautulli_url_errors:
                url_line = "[https://kometa.wiki/en/latest/config/tautulli#tautulli-attributes]"
                formatted_errors = self.format_contiguous_lines(tautulli_url_errors)
                tautulli_url_error_message = (
                    "**Tautulli URL is invalid**\n"
                    "Verify the scheme, hostname, port, and container networking, then test connectivity.\n"
                    f"For more information on configuring the Tautulli URL, {url_line}\n"
                    f"{len(tautulli_url_errors)} line(s) with TAUTULLI URL errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(tautulli_url_error_message)

            if tmdb_api_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/#getting-a-tmdb-api-key]"
                formatted_errors = self.format_contiguous_lines(tmdb_api_errors)
                tmdb_api_errors_message = (
                    "**TMDb API key is invalid**\n"
                    "Replace the configured key with a valid TMDb API key and retry the run.\n"
                    f"For more information on configuring TMDb, {url_line}\n"
                    f"{len(tmdb_api_errors)} line(s) with TMDb errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(tmdb_api_errors_message)

            if timeout_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/install/overview/]"
                formatted_errors = self.format_contiguous_lines(timeout_errors)
                timeout_error_message = (
                    "**Service connection timed out**\n"
                    "Confirm that the affected service is reachable. If it is healthy but slow, increase the relevant timeout in `config.yml` and retry.\n"
                    f"Configured Plex timeout: `{self.plex_timeout}` seconds.\n"
                    f"For more information on network configuration, {url_line}\n"
                    f"{len(timeout_errors)} line(s) with timeout errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(timeout_error_message)

            if tmdb_fail_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/install/wt/wt-01-basic-config/]"
                formatted_errors = self.format_contiguous_lines(tmdb_fail_errors)
                tmdb_fail_error_message = (
                    "**TMDb connection failed**\n"
                    "Verify DNS, outbound internet access, firewall rules, and container networking.\n"
                    f"For more information on network configuration, {url_line}\n"
                    f"{len(tmdb_fail_errors)} line(s) with TMDB errors. Line number location. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(tmdb_fail_error_message)

            if to_be_configured_errors:
                url_line = "[https://kometa.wiki/en/latest/kometa/logs/?h=%5Berror%5D#error]"
                formatted_errors = self.format_contiguous_lines(to_be_configured_errors)
                to_be_configured_errors_message = (
                    "**Required service is not configured**\n"
                    "Identify the service on the referenced lines and add its required settings before retrying.\n"
                    f"For more information on configuring services, {url_line}\n"
                    f"{len(to_be_configured_errors)} line(s) with `to be configured` errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(to_be_configured_errors_message)

            if trakt_connection_errors:
                url_line = "[https://kometa.wiki/en/latest/config/trakt/#trakt-attributes]"
                formatted_errors = self.format_contiguous_lines(trakt_connection_errors)
                trakt_connection_error_message = (
                    "**Trakt connection failed**\n"
                    "Verify authorization, credentials, network access, and service availability before retrying.\n"
                    f"For more information on configuring the Trakt service, {url_line}\n"
                    f"{len(trakt_connection_errors)} line(s) with TRAKT CONNECTION errors. Line number(s): {formatted_errors}"
                )
                special_check_lines.append(trakt_connection_error_message)

            if checkFiles:
                self.checkfiles_flg = 1

            # Initialize a list to store both the first line and full recommendation message
            recommendation_messages = []

            for idx, message in enumerate(special_check_lines, start=1):
                # Split the message into lines and log the first line with a label
                lines = message.split('\n')
                first_line = lines[0] if lines else ""
                mylogger.info(f"Kometa Recommendation {idx}: {first_line}")

                # Append both the first line and the full recommendation message to the list
                recommendation_messages.append({"first_line": first_line, "message": message})

            return recommendation_messages

    def reorder_recommendations(self, recommendations):
            # Severity ordering is applied after normalization in scanner.py.
            return recommendations

    def extract_header_lines(self, content):
            start_marker_current = "Version: "
            start_marker_newest = "Newest Version: "
            end_marker = "Run Command: "

            lines = content.splitlines()
            header_lines = []

            for i, line in enumerate(lines):
                if start_marker_current in line:
                    version_value = line.split(start_marker_current)[1].strip()  # Extract version value
                    self.current_kometa_version = version_value  # Store the version as a class variable
                    while line and end_marker not in line:
                        header_lines.append(line.strip())  # Trim leading and trailing spaces
                        i += 1
                        line = lines[i] if i < len(lines) else ""
                        if start_marker_newest in line:
                            newest_version_value = line.split(start_marker_newest)[
                                1].strip()  # Extract newest version value
                            self.kometa_newest_version = newest_version_value  # Store the newest version as a class variable
                    header_lines.append(line.strip())  # Append the "Run Command" line
                    # mylogger.info(f"header_lines bef replacement: {header_lines}")
                    break  # Stop after the first occurrence

            # Perform the replacement after all lines have been added to header_lines
            header_lines = [line.replace("(redacted)", "") for line in header_lines]
            header_lines = [line.replace("(redacted)", "") for line in header_lines]
            # mylogger.info(f"header_lines aft replacement: {header_lines}")

            return "\n".join(header_lines)
