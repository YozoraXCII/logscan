"""Kometa, Plex, image, overlay, and generic log-level rules."""

from .base import TextRule
from ..recommendations import RULES


def _rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, any_of=needles)


def _same_line_rule(rule_id: str, *needles: str) -> TextRule:
    definition = next(rule for rule in RULES.values() if rule.id == rule_id)
    return TextRule(definition, all_on_same_line=needles)


RULES = (
    _rule("api_key_missing", "apikey is blank"),
    TextRule(
        next(rule for rule in RULES.values() if rule.id == "plex_version"),
        all_on_same_line=("1.32.7", "Connected to server"),
    ),
    _rule("kometa_critical", "[CRITICAL]"),
    _rule("kometa_error", "[ERROR]"),
    _rule("kometa_warning", "[WARNING]"),
    _same_line_rule("id_conversion", "Convert Warning: No ", "ID Found for"),
    _rule("image_unreadable", "PIL.UnidentifiedImageError: cannot"),
    _same_line_rule("flixpatrol_parse", "FlixPatrol Error:", "failed to parse"),
    _rule("image_size", "in _upload_image"),
    _rule("internal_server", "internal_server_error"),
    _same_line_rule("mass_update", "Config Error: Operation mass_", "without a successful"),
    _rule("metadata_load", "Metadata File Failed To Load"),
    _rule("overlay_load", "Overlay File Failed To Load"),
    _rule("playlist_load", "Playlist File Failed To Load"),
    _rule("plex_no_items", "Plex Error: No Items found in Plex"),
    _rule("overlay_font", "Overlay Error: font:"),
    _rule("overlay_reset", "Reapply Overlays: True", "Reset Overlays: ["),
    _rule("overlay_existing", "Poster already has an Overlay"),
    _rule("overlay_image", "Overlay Image not found"),
    _same_line_rule("playlist_library", "Playlist Error: Library:", "not defined"),
    _same_line_rule("plex_regex", "Plex Error: ", "No matches found with regex pattern"),
    _same_line_rule("plex_library", "Plex Error: Plex Library", "not found"),
    _rule("plex_url", "Plex Error: Plex url is invalid"),
    _rule("rating_rounding", "mass_user_rating_update", "mass_episode_user_ratings_update"),
    _rule("plex_security", "Connected to server"),
    _rule("traceback", "Traceback (most recent call last):"),
)
