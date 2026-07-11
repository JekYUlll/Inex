"""Inex Sublime Text package bootstrap.

The editable scratch-buffer client is implemented in Phase 5. This bootstrap
only reports whether the application-global persistence settings satisfy the
strict-mode prerequisites; it never starts the sidecar or decrypts content.
"""

from typing import List

import sublime
import sublime_plugin


def insecure_preferences() -> List[str]:
    """Return persistence settings that block strict editable mode."""

    preferences = sublime.load_settings("Preferences.sublime-settings")
    issues = []
    if preferences.get("hot_exit") != "disabled":
        issues.append('"hot_exit" must be "disabled"')
    if preferences.get("hot_exit_projects", True) is not False:
        issues.append('"hot_exit_projects" must be false')
    if preferences.get("update_system_recent_files", True) is not False:
        issues.append('"update_system_recent_files" must be false')
    return issues


class InexShowSecurityStatusCommand(sublime_plugin.ApplicationCommand):
    """Show the strict-mode gate without opening or decrypting a vault."""

    def run(self) -> None:
        issues = insecure_preferences()
        if issues:
            sublime.message_dialog(
                "Inex editable mode is blocked:\n\n- " + "\n- ".join(issues)
            )
            return

        sublime.message_dialog(
            "Inex persistence prerequisites are configured. "
            "The client remains pre-alpha until residue tests pass."
        )
