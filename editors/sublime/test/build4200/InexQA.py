"""Build 4200 black-box helper injected only into an isolated XDG profile.

The helper never writes managed text to its report.  It records only fixed
scenario names, booleans, byte counts, and SHA-256 digests.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import sublime
import sublime_plugin


_TOKEN_RE = re.compile(r"^EDIT_TOKEN: (INEXQA_EDIT_[0-9a-f]{32})$", re.MULTILINE)
_INITIAL_TOKEN_RE = re.compile(
    r"^INITIAL_TOKEN: (INEXQA_INITIAL_[0-9a-f]{32})$", re.MULTILINE
)
_started = False
_error_probe_installed = False
_opened_fingerprint: Optional[Tuple[int, str]] = None
_HOST_MARKER = "inex.managed_plaintext"
_LOCKED_TEXT = "[Inex locked — unlock the vault to reopen this document]\n"
_CRUD_DIRECTORY = "qa-crud"
_CRUD_CREATED = "qa-crud/new.md"
_CRUD_RENAMED = "qa-crud/renamed.md"


def _settings() -> sublime.Settings:
    return sublime.load_settings("InexQA.sublime-settings")


def _report(event: str, **fields: Any) -> None:
    path = _settings().get("report_path", "")
    if not isinstance(path, str) or not os.path.isabs(path):
        return
    record: Dict[str, Any] = {"event": event, "time": time.monotonic()}
    for key, value in fields.items():
        if isinstance(value, (bool, int, float, str)) or value is None:
            record[key] = value
    encoded = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def _state_path() -> Optional[str]:
    path = _settings().get("state_path", "")
    if not isinstance(path, str) or not os.path.isabs(path):
        return None
    return path


def _read_state() -> Dict[str, Any]:
    path = _state_path()
    if path is None:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, UnicodeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _write_state(value: Dict[str, Any]) -> bool:
    path = _state_path()
    if path is None:
        return False
    temporary = path + ".tmp"
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, encoded)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        return True
    except OSError:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        return False


def _inex_module() -> Optional[Any]:
    for name, module in list(sys.modules.items()):
        if (
            (name == "Inex" or name.endswith(".Inex"))
            and module is not None
            and hasattr(module, "_registry")
            and hasattr(module, "_runtime_snapshot")
        ):
            return module
    return None


def _managed() -> Optional[Tuple[Any, sublime.View, Any]]:
    module = _inex_module()
    if module is None:
        return None
    documents = module._registry.values()
    if len(documents) != 1:
        return None
    document = documents[0]
    for window in sublime.windows():
        for view in window.views(include_transient=True):
            if view.id() == document.view_id:
                return module, view, document
    return None


def _tree_contains(kind: str, logical_path: str) -> bool:
    module = _inex_module()
    if module is None:
        return False
    client, _vault, _generation = module._runtime_snapshot()
    if client is None or not client.has_session:
        return False
    entries = client.list_tree()
    return any(
        entry.get("kind") == kind and entry.get("logicalPath") == logical_path
        for entry in entries
    )


def _wait_for(
    label: str,
    predicate: Callable[[], bool],
    done: Callable[[], None],
    timeout_ms: int = 20000,
) -> None:
    deadline = time.monotonic() + timeout_ms / 1000.0

    def poll() -> None:
        try:
            if predicate():
                done()
                return
        except Exception:
            pass
        if time.monotonic() >= deadline:
            _report("fatal", step=label)
            return
        sublime.set_timeout(poll, 100)

    poll()


class InexQaAppendEditTokenCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit) -> None:
        text = self.view.substr(sublime.Region(0, self.view.size()))
        match = _TOKEN_RE.search(text)
        if match is None:
            raise RuntimeError("QA edit token is missing")
        self.view.insert(edit, self.view.size(), "\n" + match.group(1) + "\n")


def _begin() -> None:
    global _error_probe_installed
    window = sublime.active_window()
    if window is None:
        _report("fatal", step="no_window")
        return
    module = _inex_module()
    if module is None:
        _report("fatal", step="inex_not_loaded")
        return
    if not _error_probe_installed:
        original_show_error = module._show_error

        def report_then_show(error: Exception) -> None:
            _report(
                "inex_error",
                error_type=type(error).__name__,
                safe_message=module._safe_error(error),
            )
            original_show_error(error)

        module._show_error = report_then_show
        _error_probe_installed = True
    issues = module.insecure_preferences()
    _report(
        "loaded",
        build=sublime.version(),
        gate_ok=not issues,
        issue_count=len(issues),
    )
    if issues:
        return
    window.run_command("inex_unlock")
    sublime.set_timeout(
        lambda: _report(
            "unlock_dispatched",
            plugin_active=getattr(module, "_plugin_active", False) is True,
            in_progress=getattr(module, "_unlock_in_progress", False) is True,
        ),
        500,
    )

    def unlocked() -> bool:
        current = _inex_module()
        if current is None:
            return False
        client, _vault, _generation = current._runtime_snapshot()
        return client is not None and client.has_session

    def select_tree() -> None:
        _report("ui", action="select_tree")
        _wait_for("managed_open", lambda: _managed() is not None, _opened)

    _wait_for("unlock", unlocked, select_tree)


def _opened() -> None:
    global _opened_fingerprint
    current = _managed()
    if current is None:
        _report("fatal", step="managed_missing_after_open")
        return
    _module, view, document = current
    text = view.substr(sublime.Region(0, view.size()))
    initial_ok = "INEXQA_INITIAL_" in text and _TOKEN_RE.search(text) is not None
    _report(
        "opened",
        scratch=view.is_scratch(),
        unnamed=view.file_name() is None,
        initial_ok=initial_ok,
        initial_clean=not document.dirty,
        byte_count=len(text.encode("utf-8")),
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )
    if not (
        view.is_scratch()
        and view.file_name() is None
        and initial_ok
        and not document.dirty
    ):
        _report("fatal", step="open_invariants")
        return
    encoded = text.encode("utf-8")
    _opened_fingerprint = (len(encoded), hashlib.sha256(encoded).hexdigest())
    view.run_command("inex_qa_append_edit_token")

    def dirty() -> bool:
        managed = _managed()
        return managed is not None and managed[2].dirty

    def save() -> None:
        view.run_command("inex_save")

        def saved() -> bool:
            managed = _managed()
            return managed is not None and not managed[2].dirty

        _wait_for("save", saved, _saved)

    _wait_for("edit_dirty", dirty, save)


def _saved() -> None:
    current = _managed()
    if current is None:
        _report("fatal", step="managed_missing_after_save")
        return
    _module, view, _document = current
    text = view.substr(sublime.Region(0, view.size()))
    match = _TOKEN_RE.search(text)
    persisted_shape = match is not None and text.count(match.group(1)) == 2
    _report(
        "saved",
        persisted_shape=persisted_shape,
        scratch=view.is_scratch(),
        unnamed=view.file_name() is None,
        byte_count=len(text.encode("utf-8")),
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
    )
    if not persisted_shape:
        _report("fatal", step="save_shape")
        return
    if _settings().get("full_application_kill_restart", False) is True:
        _full_application_restart_ready()
        return
    if _settings().get("plugin_host_crash", False) is True:
        _plugin_host_crash_ready()
        return
    window = view.window()
    if window is None:
        _report("fatal", step="close_window_missing")
        return
    window.run_command("inex_close_active")

    def closed() -> bool:
        visible_ids = {
            candidate.id()
            for candidate_window in sublime.windows()
            for candidate in candidate_window.views(include_transient=True)
        }
        return _managed() is None and view.id() not in visible_ids

    def start_crud() -> None:
        _start_crud_folder(window)

    _wait_for("close", closed, start_crud)


def _start_crud_folder(window: sublime.Window) -> None:
    window.run_command("inex_new_folder")
    _report("ui", action="crud_new_folder")

    def create_markdown() -> None:
        _report("crud_folder_created", exists=True)
        window.run_command("inex_new_encrypted_markdown")
        _report("ui", action="crud_new_markdown")
        _wait_for("crud_markdown_open", _created_document_is_open, _crud_created)

    _wait_for(
        "crud_folder_create",
        lambda: _tree_contains("directory", _CRUD_DIRECTORY),
        create_markdown,
    )


def _created_document_is_open() -> bool:
    current = _managed()
    if current is None:
        return False
    _module, view, document = current
    return (
        document.logical_path == _CRUD_CREATED
        and not document.dirty
        and not document.read_only
        and view.is_scratch()
        and view.file_name() is None
        and view.size() == 0
        and _tree_contains("file", _CRUD_CREATED)
    )


def _crud_created() -> None:
    current = _managed()
    if current is None:
        _report("fatal", step="crud_created_document_missing")
        return
    _module, view, document = current
    window = view.window()
    if window is None:
        _report("fatal", step="crud_created_window_missing")
        return
    _report(
        "crud_markdown_created",
        clean=not document.dirty,
        scratch=view.is_scratch(),
        unnamed=view.file_name() is None,
        empty=view.size() == 0,
    )
    window.run_command("inex_rename_active")
    _report("ui", action="crud_rename")
    _wait_for("crud_rename", _renamed_document_is_current, _crud_renamed)


def _renamed_document_is_current() -> bool:
    current = _managed()
    if current is None:
        return False
    _module, _view, document = current
    return (
        document.logical_path == _CRUD_RENAMED
        and not document.dirty
        and _tree_contains("file", _CRUD_RENAMED)
        and not _tree_contains("file", _CRUD_CREATED)
    )


def _crud_renamed() -> None:
    current = _managed()
    if current is None:
        _report("fatal", step="crud_renamed_document_missing")
        return
    _module, view, document = current
    window = view.window()
    if window is None:
        _report("fatal", step="crud_renamed_window_missing")
        return
    _report("crud_markdown_renamed", clean=not document.dirty)
    window.run_command("inex_delete_active")
    _report("ui", action="crud_delete_confirm")
    _wait_for("crud_delete", _crud_delete_finished, _crud_complete)


def _crud_delete_finished() -> bool:
    return (
        _managed() is None
        and _tree_contains("directory", _CRUD_DIRECTORY)
        and not _tree_contains("file", _CRUD_CREATED)
        and not _tree_contains("file", _CRUD_RENAMED)
        and _tree_contains("file", "qa.md")
    )


def _crud_complete() -> None:
    _report("crud_markdown_deleted", absent=True)
    _report("minimal_complete", managed_count=0, crud_complete=True)
    _report("complete", managed_count=0, crud_complete=True)


def _plugin_host_crash_ready() -> None:
    current = _managed()
    if current is None:
        _report("fatal", step="plugin_host_managed_missing")
        return
    _module, view, _document = current
    window = view.window()
    if window is None:
        _report("fatal", step="plugin_host_window_missing")
        return
    window.focus_view(view)
    text = view.substr(sublime.Region(0, view.size()))
    encoded = text.encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()
    marker = view.settings().get(_HOST_MARKER) is True
    if not marker:
        _report("fatal", step="plugin_host_product_marker_missing")
        return
    state = {
        "phase": "await_plugin_host_restart",
        "view_id": view.id(),
        "byte_count": len(encoded),
        "content_sha256": digest,
    }
    if not _write_state(state):
        _report("fatal", step="plugin_host_state_write")
        return
    _report(
        "plugin_host_crash_ready",
        view_id=view.id(),
        byte_count=len(encoded),
        content_sha256=digest,
        marker=marker,
    )


def _full_application_restart_ready() -> None:
    current = _managed()
    if current is None:
        _report("fatal", step="full_restart_managed_missing")
        return
    _module, view, document = current
    text = view.substr(sublime.Region(0, view.size()))
    encoded = text.encode("utf-8")
    marker = view.settings().get(_HOST_MARKER) is True
    initial_match = _INITIAL_TOKEN_RE.search(text)
    edit_match = _TOKEN_RE.search(text)
    if (
        not marker
        or _opened_fingerprint is None
        or initial_match is None
        or edit_match is None
        or document.logical_path != "qa.md"
    ):
        _report("fatal", step="full_restart_ready_invariants")
        return
    token_fingerprints: List[Dict[str, Any]] = []
    for token in (initial_match.group(1), edit_match.group(1)):
        token_bytes = token.encode("utf-8")
        token_fingerprints.append(
            {
                "byte_count": len(token_bytes),
                "content_sha256": hashlib.sha256(token_bytes).hexdigest(),
            }
        )
    saved_fingerprint = (len(encoded), hashlib.sha256(encoded).hexdigest())
    state = {
        "phase": "await_full_application_restart",
        "logical_path": "qa.md",
        "opened_byte_count": _opened_fingerprint[0],
        "opened_content_sha256": _opened_fingerprint[1],
        "saved_byte_count": saved_fingerprint[0],
        "saved_content_sha256": saved_fingerprint[1],
        "token_fingerprints": token_fingerprints,
    }
    if not _write_state(state):
        _report("fatal", step="full_restart_state_write")
        return
    _report(
        "full_application_restart_ready",
        view_id=view.id(),
        logical_path="qa.md",
        byte_count=saved_fingerprint[0],
        content_sha256=saved_fingerprint[1],
        marker=marker,
        state_written=True,
        token_fingerprint_count=len(token_fingerprints),
    )


def _valid_state_fingerprint(
    state: Dict[str, Any], byte_field: str, digest_field: str
) -> Optional[Tuple[int, str]]:
    byte_count = state.get(byte_field)
    digest = state.get(digest_field)
    if (
        not isinstance(byte_count, int)
        or isinstance(byte_count, bool)
        or byte_count <= 0
        or not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
    ):
        return None
    return byte_count, digest


def _restart_state() -> Optional[Dict[str, Any]]:
    state = _read_state()
    if set(state) != {
        "phase",
        "logical_path",
        "opened_byte_count",
        "opened_content_sha256",
        "saved_byte_count",
        "saved_content_sha256",
        "token_fingerprints",
    }:
        return None
    if (
        state.get("phase") != "await_full_application_restart"
        or state.get("logical_path") != "qa.md"
        or _valid_state_fingerprint(
            state, "opened_byte_count", "opened_content_sha256"
        )
        is None
        or _valid_state_fingerprint(state, "saved_byte_count", "saved_content_sha256")
        is None
    ):
        return None
    tokens = state.get("token_fingerprints")
    if not isinstance(tokens, list) or len(tokens) != 2:
        return None
    for token in tokens:
        if (
            not isinstance(token, dict)
            or set(token) != {"byte_count", "content_sha256"}
            or _valid_state_fingerprint(
                {
                    "byte_count": token.get("byte_count"),
                    "content_sha256": token.get("content_sha256"),
                },
                "byte_count",
                "content_sha256",
            )
            is None
        ):
            return None
    return state


def _contains_hashed_window(encoded: bytes, byte_count: int, digest: str) -> bool:
    if byte_count > len(encoded):
        return False
    return any(
        hashlib.sha256(encoded[offset : offset + byte_count]).hexdigest() == digest
        for offset in range(len(encoded) - byte_count + 1)
    )


def _preunlock_observation(state: Dict[str, Any]) -> Dict[str, Any]:
    module = _inex_module()
    managed_count = len(module._registry.values()) if module is not None else -1
    session_active = False
    if module is not None:
        client, _vault, _generation = module._runtime_snapshot()
        session_active = client is not None and client.has_session
    known_fingerprints = {
        _valid_state_fingerprint(state, "opened_byte_count", "opened_content_sha256"),
        _valid_state_fingerprint(state, "saved_byte_count", "saved_content_sha256"),
    }
    token_fingerprints = [
        (token["byte_count"], token["content_sha256"])
        for token in state["token_fingerprints"]
    ]
    view_count = 0
    marker_count = 0
    known_fingerprint_count = 0
    token_window_match_count = 0
    for window in sublime.windows():
        for view in window.views(include_transient=True):
            view_count += 1
            encoded = view.substr(sublime.Region(0, view.size())).encode("utf-8")
            if view.settings().get(_HOST_MARKER) is True:
                marker_count += 1
            if (len(encoded), hashlib.sha256(encoded).hexdigest()) in known_fingerprints:
                known_fingerprint_count += 1
            token_window_match_count += sum(
                1
                for byte_count, digest in token_fingerprints
                if _contains_hashed_window(encoded, byte_count, digest)
            )
    clean = (
        managed_count == 0
        and not session_active
        and marker_count == 0
        and known_fingerprint_count == 0
        and token_window_match_count == 0
    )
    return {
        "view_count": view_count,
        "managed_count": managed_count,
        "session_active": session_active,
        "marker_count": marker_count,
        "known_fingerprint_count": known_fingerprint_count,
        "token_window_match_count": token_window_match_count,
        "clean": clean,
    }


def _begin_full_application_restart() -> None:
    state = _restart_state()
    module = _inex_module()
    if state is None or module is None:
        _report("fatal", step="full_restart_state_or_module")
        return
    issues = module.insecure_preferences()
    _report(
        "restart_loaded",
        build=sublime.version(),
        gate_ok=not issues,
        issue_count=len(issues),
    )
    if issues:
        return
    stable_since: Optional[float] = None
    deadline = time.monotonic() + 20000 / 1000.0

    def poll() -> None:
        nonlocal stable_since
        observation = _preunlock_observation(state)
        now = time.monotonic()
        if observation["clean"] is True:
            if stable_since is None:
                stable_since = now
            if now - stable_since >= 2.0:
                _report(
                    "restart_preunlock_checked",
                    stable_duration_ms=2000,
                    **observation,
                )
                window = sublime.active_window()
                if window is None:
                    _report("fatal", step="full_restart_window_missing")
                    return
                window.run_command("inex_unlock")
                sublime.set_timeout(
                    lambda: _report(
                        "restart_unlock_dispatched",
                        plugin_active=getattr(module, "_plugin_active", False) is True,
                        in_progress=getattr(module, "_unlock_in_progress", False) is True,
                    ),
                    500,
                )

                def unlocked() -> bool:
                    current = _inex_module()
                    if current is None:
                        return False
                    client, _vault, _generation = current._runtime_snapshot()
                    return client is not None and client.has_session

                def select_tree() -> None:
                    _report("ui", action="select_tree_after_restart")
                    _wait_for(
                        "managed_reopen", lambda: _managed() is not None, _restart_reopened
                    )

                _wait_for("restart_unlock", unlocked, select_tree)
                return
        else:
            stable_since = None
        if now >= deadline:
            _report("fatal", step="full_restart_preunlock_stability")
            return
        sublime.set_timeout(poll, 100)

    poll()


def _restart_reopened() -> None:
    state = _restart_state()
    current = _managed()
    if state is None or current is None:
        _report("fatal", step="full_restart_reopen_missing")
        return
    module, view, document = current
    text = view.substr(sublime.Region(0, view.size()))
    encoded = text.encode("utf-8")
    fingerprint_matches = (
        len(encoded) == state["saved_byte_count"]
        and hashlib.sha256(encoded).hexdigest() == state["saved_content_sha256"]
    )
    client, _vault, _generation = module._runtime_snapshot()
    session_active = client is not None and client.has_session
    marker = view.settings().get(_HOST_MARKER) is True
    logical_path_matches = document.logical_path == state["logical_path"]
    _report(
        "restart_reopened",
        scratch=view.is_scratch(),
        unnamed=view.file_name() is None,
        clean=not document.dirty,
        marker=marker,
        session_active=session_active,
        logical_path_matches=logical_path_matches,
        fingerprint_matches=fingerprint_matches,
        byte_count=len(encoded),
        content_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    if not all(
        (
            view.is_scratch(),
            view.file_name() is None,
            not document.dirty,
            marker,
            session_active,
            logical_path_matches,
            fingerprint_matches,
        )
    ):
        _report("fatal", step="full_restart_reopen_invariants")
        return
    window = view.window()
    if window is None:
        _report("fatal", step="full_restart_close_window_missing")
        return
    window.run_command("inex_close_active")

    def closed() -> bool:
        visible_ids = {
            candidate.id()
            for candidate_window in sublime.windows()
            for candidate in candidate_window.views(include_transient=True)
        }
        return _managed() is None and view.id() not in visible_ids

    def finish() -> None:
        _report(
            "restart_closed", managed_count=0, view_absent=True, normal_close=True
        )
        _report("complete", restarted=True, managed_count=0)

    _wait_for("restart_close", closed, finish)


def _check_plugin_host_restart() -> None:
    state = _read_state()
    window = sublime.active_window()
    view = window.active_view() if window is not None else None
    expected_id = state.get("view_id")
    expected_bytes = state.get("byte_count")
    expected_digest = state.get("content_sha256")
    if view is None:
        byte_count = 0
        digest = hashlib.sha256(b"").hexdigest()
        marker = False
        identifier_matches = False
        locked_text = False
        read_only = False
    else:
        text = view.substr(sublime.Region(0, view.size()))
        encoded = text.encode("utf-8")
        byte_count = len(encoded)
        digest = hashlib.sha256(encoded).hexdigest()
        marker = view.settings().get(_HOST_MARKER) is True
        identifier_matches = view.id() == expected_id
        locked_text = text == _LOCKED_TEXT
        read_only = view.is_read_only()
    same_length = (
        isinstance(expected_bytes, int)
        and not isinstance(expected_bytes, bool)
        and byte_count == expected_bytes
    )
    same_hash = isinstance(expected_digest, str) and digest == expected_digest
    plaintext_survived = (
        view is not None
        and identifier_matches
        and same_length
        and same_hash
    )
    orphan_scrubbed = (
        view is not None
        and identifier_matches
        and not marker
        and locked_text
        and read_only
    )
    _report(
        "plugin_host_restart_checked",
        active_view=view is not None,
        active_view_id_matches=identifier_matches,
        byte_count=byte_count,
        content_sha256=digest,
        marker=marker,
        same_length=same_length,
        same_hash=same_hash,
        plaintext_survived=plaintext_survived,
        orphan_scrubbed=orphan_scrubbed,
        locked_text=locked_text,
        read_only=read_only,
    )
    _report("complete", plugin_host_safe=orphan_scrubbed)


def plugin_loaded() -> None:
    global _started
    if _started:
        return
    _started = True

    phase = _read_state().get("phase")
    if phase == "await_plugin_host_restart":
        sublime.set_timeout(_check_plugin_host_restart, 1000)
        return
    if phase == "await_full_application_restart":
        _wait_for(
            "restart_inex_plugin_active",
            lambda: _inex_module() is not None
            and getattr(_inex_module(), "_plugin_active", False) is True,
            _begin_full_application_restart,
        )
        return

    def wait_for_inex() -> None:
        _wait_for(
            "inex_plugin_active",
            lambda: _inex_module() is not None
            and getattr(_inex_module(), "_plugin_active", False) is True,
            _begin,
        )

    sublime.set_timeout(wait_for_inex, 250)
