"""Inex experimental strict client for Sublime Text Build 4200.

The editor buffer is always scratch and unnamed at the filesystem layer.  All
authoritative state lives in this plugin process and all persistence is EDRY
ciphertext produced by the local inexd sidecar.
"""

from __future__ import annotations

import os
import builtins
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import sublime
import sublime_plugin

try:
    from .inex_core import (
        DocumentRegistry,
        DraftStorageError,
        IdleDeadline,
        ManagedDocument,
        ModelError,
        PendingPlaintextRegistry,
        PlaintextHandoffRegistry,
        atomic_write_ciphertext,
        check_security_preferences,
        classify_text_command,
        classify_window_command,
        draft_filename,
        macro_fingerprint,
        read_encrypted_draft,
        remove_encrypted_draft,
        safe_error_message,
        scrub_then_remove,
        session_epoch_is_current,
        session_owner_is_current,
        validate_logical_path,
    )
    from .inex_password import PasswordPromptError, prompt_password
    from .inex_annotation import AnnotationPickerError, AnnotationPickerState
    from .inex_markdown import markdown_headings, markdown_links
    from .inex_rpc import (
        InexRpcClient,
        RpcLifecycleError,
        RpcProtocolError,
        RpcRemoteError,
        resolve_sidecar,
        wipe,
    )
except ImportError:  # Direct package development outside Sublime's loader.
    from inex_core import (
        DocumentRegistry,
        DraftStorageError,
        IdleDeadline,
        ManagedDocument,
        ModelError,
        PendingPlaintextRegistry,
        PlaintextHandoffRegistry,
        atomic_write_ciphertext,
        check_security_preferences,
        classify_text_command,
        classify_window_command,
        draft_filename,
        macro_fingerprint,
        read_encrypted_draft,
        remove_encrypted_draft,
        safe_error_message,
        scrub_then_remove,
        session_epoch_is_current,
        session_owner_is_current,
        validate_logical_path,
    )
    from inex_password import PasswordPromptError, prompt_password
    from inex_annotation import AnnotationPickerError, AnnotationPickerState
    from inex_markdown import markdown_headings, markdown_links
    from inex_rpc import (
        InexRpcClient,
        RpcLifecycleError,
        RpcProtocolError,
        RpcRemoteError,
        resolve_sidecar,
        wipe,
    )


PACKAGE_VERSION = "0.1.0"
TESTED_SUBLIME_BUILD = "4200"
STATUS_KEY = "inex.document"
VIEW_PLAINTEXT_MARKER = "inex.managed_plaintext"
PREFERENCES_CHANGE_TAG = "inex-strict-security-gate"
LOCKED_TEXT = "[Inex locked — unlock the vault to reopen this document]\n"
BLOCKED_TEXT = "[Inex blocked an unsafe plaintext save]\n"

_registry = DocumentRegistry()
_annotation_pickers: List[AnnotationPickerState] = []
_runtime_lock = threading.Lock()
_client: Optional[InexRpcClient] = None
_vault_id: Optional[str] = None
_vault_path: Optional[str] = None
_generation = 0
_unlock_in_progress = False
_umbra_generation = 0
_plugin_active = False
_orphan_scrub_blocked = False
_scrubbing_views = set()  # type: ignore
_fixed_scrub_acks: Dict[int, str] = {}
_last_activity_ping = 0.0
_activity_ping_inflight = False
_idle_deadline: Optional[IdleDeadline] = None
_idle_timer_serial = 0
_handoffs = PlaintextHandoffRegistry()
_pending_plaintext = PendingPlaintextRegistry()
_macro_baseline: Optional[str] = None
_macro_sanitize_bypass = False
_MACRO_TAINT_ATTRIBUTE = "_inex_sublime_macro_tainted"


def _settings() -> sublime.Settings:
    return sublime.load_settings("Inex.sublime-settings")


def _preference_values() -> Dict[str, Any]:
    preferences = sublime.load_settings("Preferences.sublime-settings")
    return {
        "hot_exit": preferences.get("hot_exit"),
        "hot_exit_projects": preferences.get("hot_exit_projects"),
        "remember_open_files": preferences.get("remember_open_files"),
        "update_system_recent_files": preferences.get("update_system_recent_files"),
    }


def insecure_preferences() -> List[str]:
    """Return every strict-mode blocker without starting or decrypting."""

    issues = check_security_preferences(_preference_values())
    if sublime.version() != TESTED_SUBLIME_BUILD:
        issues.append(
            "Sublime Text build must be exactly %s (found %s)"
            % (TESTED_SUBLIME_BUILD, sublime.version())
        )
    if _macro_is_tainted():
        issues.append("Sublime macro state captured managed input; restart Sublime Text")
    if _orphan_scrub_blocked:
        issues.append("An orphaned marked view could not be safely scrubbed")
    return issues


def _show_security_block(window: Optional[sublime.Window] = None) -> None:
    issues = insecure_preferences()
    if not issues:
        return
    sublime.message_dialog("Inex editable mode is blocked:\n\n- " + "\n- ".join(issues))


def _safe_error(error: Exception) -> str:
    if isinstance(error, PasswordPromptError):
        return str(error)
    return safe_error_message(error)


def _show_error(error: Exception) -> None:
    sublime.message_dialog(_safe_error(error))


def _macro_is_tainted() -> bool:
    return getattr(builtins, _MACRO_TAINT_ATTRIBUTE, False) is True


def _set_macro_tainted() -> None:
    setattr(builtins, _MACRO_TAINT_ATTRIBUTE, True)


def _start_macro_monitoring() -> None:
    global _macro_baseline
    _macro_baseline = macro_fingerprint(sublime.get_macro())


def _verify_empty_macro() -> bool:
    try:
        macro = sublime.get_macro()
    except Exception:
        return False
    return isinstance(macro, list) and macro == []


def _detect_active_macro_recording(window: Optional[sublime.Window]) -> None:
    global _macro_baseline, _macro_sanitize_bypass
    if (
        _macro_sanitize_bypass
        or not _registry.values()
        or _macro_baseline is None
    ):
        return
    try:
        current = macro_fingerprint(sublime.get_macro())
    except Exception:
        _set_macro_tainted()
        _perform_lock("Inex could not validate Sublime macro state")
        return
    if current == _macro_baseline:
        return
    _macro_baseline = current
    _set_macro_tainted()
    sanitized = False
    if window is not None:
        _macro_sanitize_bypass = True
        try:
            # A changing current macro while a managed view exists proves that
            # recording is active. Build 4200 does not clear the old macro when
            # an empty recording is started/stopped. Its probed clearing path
            # is: stop old, start fresh, run one no-op TextCommand, stop, then
            # require the public API to report an exact empty macro.
            window.run_command("toggle_record_macro")
            window.run_command("toggle_record_macro")
            window.run_command("inex_macro_sanitizer")
            window.run_command("toggle_record_macro")
            sanitized = _verify_empty_macro()
        except Exception:
            sanitized = False
        finally:
            _macro_sanitize_bypass = False
    _perform_lock("Inex detected macro recording and locked all plaintext buffers")
    if sanitized:
        sublime.message_dialog(
            "Inex detected active macro recording. Managed buffers were locked "
            "and Build 4200 reported an empty replacement macro. Unlock and all "
            "macro features remain disabled until Sublime Text restarts."
        )
    else:
        sublime.message_dialog(
            "Inex detected active macro recording and locked managed buffers, "
            "but Build 4200 did not confirm macro sanitization. Quit and restart "
            "Sublime Text before further use."
        )


def _all_windows() -> List[sublime.Window]:
    return list(sublime.windows())


def _view_by_id(view_id: int) -> Optional[sublime.View]:
    for window in _all_windows():
        for view in window.views(include_transient=True):
            if view.id() == view_id:
                return view
    return None


def _window_managed_documents(window: sublime.Window) -> List[ManagedDocument]:
    view_ids = {view.id() for view in window.views(include_transient=True)}
    return [document for document in _registry.values() if document.view_id in view_ids]


def _runtime_snapshot() -> Tuple[Optional[InexRpcClient], Optional[str], int]:
    with _runtime_lock:
        return _client, _vault_id, _generation


def _current_client(expected_generation: Optional[int] = None) -> InexRpcClient:
    with _runtime_lock:
        if expected_generation is not None and expected_generation != _generation:
            raise RpcLifecycleError("Inex session changed during the operation")
        if _client is None or not _client.has_session:
            raise RpcLifecycleError("Inex vault is locked")
        return _client


def _draft_directory() -> str:
    # This package-owned directory contains EDRY bytes only. It is deliberately
    # not configurable, which prevents accidental placement in the vault or a
    # plaintext-oriented workspace.
    return os.path.abspath(
        os.path.join(sublime.packages_path(), "User", "InexEncryptedDrafts")
    )


def _update_document_ui(document: ManagedDocument) -> None:
    view = _view_by_id(document.view_id)
    if view is None or not view.is_valid():
        return
    if (
        view.file_name() is not None
        or not view.is_scratch()
        or view.settings().get(VIEW_PLAINTEXT_MARKER) is not True
    ):
        _emergency_scrub_view(view, "Managed buffer acquired unsafe file state")
        return
    prefix = "● " if document.dirty else ""
    suffix = " [read-only]" if document.read_only else ""
    view.set_name(prefix + document.logical_path + " — Inex" + suffix)
    if document.read_only:
        status = "Inex: read-only"
    elif document.requires_overwrite_confirmation:
        status = "Inex: stale recovery; overwrite confirmation required"
    elif document.dirty:
        status = "Inex: encrypted draft pending" if document.draft_version < document.version else "Inex: encrypted draft saved"
    else:
        status = "Inex: ciphertext saved"
    view.set_status(STATUS_KEY, status)


def _replace_view_with_fixed_text(view: sublime.View, text: str, status: str) -> None:
    if not view.is_valid():
        return
    if text == LOCKED_TEXT:
        scrub_command = "inex_scrub_locked_buffer"
    elif text == BLOCKED_TEXT:
        scrub_command = "inex_scrub_blocked_buffer"
    else:
        raise ModelError("Inex scrub text is not a fixed constant")
    # The globally registered TextCommand refuses ordinary views. Internal
    # emergency callers install the same fixed Boolean marker before invoking
    # it, including an empty view that failed before its first insertion.
    view.settings().set(VIEW_PLAINTEXT_MARKER, True)
    view.set_scratch(True)
    view.set_read_only(False)
    _scrubbing_views.add(view.id())
    _fixed_scrub_acks.pop(view.id(), None)
    scrubbed = False
    try:
        # This dedicated command accepts no text/token argument and deliberately
        # works for named or non-scratch views reached by an emergency path.
        view.run_command(scrub_command)
        if _fixed_scrub_acks.pop(view.id(), None) != scrub_command:
            raise ModelError("Inex fixed scrub command did not acknowledge replace")
        view.run_command("clear_undo_stack")
        view.settings().erase(VIEW_PLAINTEXT_MARKER)
        scrubbed = True
    finally:
        _fixed_scrub_acks.pop(view.id(), None)
        _scrubbing_views.discard(view.id())
        if not scrubbed and view.is_valid():
            view.set_read_only(True)
    view.set_read_only(True)
    view.set_name("Inex — locked")
    view.set_status(STATUS_KEY, status)


def _replace_buffer_from_bytes(view: sublime.View, value: bytearray) -> None:
    token = _handoffs.put(value)
    try:
        view.run_command("inex_replace_entire_buffer", {"token": token})
    finally:
        _handoffs.discard(token)


def _emergency_scrub_view(view: sublime.View, reason: str) -> None:
    scrub_then_remove(
        _registry,
        view.id(),
        lambda: _replace_view_with_fixed_text(
            view, BLOCKED_TEXT, "Inex: unsafe operation blocked"
        ),
    )
    sublime.status_message("Inex locked a managed buffer: " + reason)


def _cleanup_pending_owner(owner: Any) -> None:
    owner.wipe()
    if isinstance(owner.context, InexRpcClient) and owner.handle:
        sublime.set_timeout_async(
            lambda: _close_handle_best_effort(owner.context, owner.handle), 0
        )


def _clear_pending_plaintext() -> None:
    for owner in _pending_plaintext.drain():
        try:
            _cleanup_pending_owner(owner)
        except Exception:
            # `_cleanup_pending_owner` wipes before scheduling handle close;
            # continue draining so one failed Sublime callback cannot strand
            # other pending plaintext owners in memory.
            try:
                owner.wipe()
            except Exception:
                pass


def _lock_views_and_drop_models(reason: str) -> Tuple[Optional[InexRpcClient], List[str]]:
    global _client, _vault_id, _vault_path, _generation, _unlock_in_progress
    global _last_activity_ping, _activity_ping_inflight
    global _idle_deadline, _idle_timer_serial
    global _macro_baseline, _orphan_scrub_blocked, _umbra_generation
    with _runtime_lock:
        client = _client
        _client = None
        _vault_id = None
        _vault_path = None
        _generation += 1
        _unlock_in_progress = False
        _last_activity_ping = 0.0
        _activity_ping_inflight = False
        _idle_deadline = None
        _idle_timer_serial += 1
        _umbra_generation += 1
    _clear_annotation_pickers()
    scrub_failed = False
    try:
        _handoffs.clear()
    except Exception:
        scrub_failed = True
    try:
        _clear_pending_plaintext()
    except Exception:
        scrub_failed = True
    _macro_baseline = None
    try:
        windows = _all_windows()
    except Exception:
        windows = []
        scrub_failed = True
    for window in windows:
        try:
            window.run_command("hide_overlay")
        except Exception:
            scrub_failed = True
    handles = []
    try:
        documents = _registry.values()
    except Exception:
        documents = []
        scrub_failed = True
    for document in documents:
        view = None
        try:
            view = _view_by_id(document.view_id)
            if view is not None:
                handle = scrub_then_remove(
                    _registry,
                    document.view_id,
                    lambda view=view: _replace_view_with_fixed_text(
                        view, LOCKED_TEXT, "Inex: locked"
                    ),
                )
            else:
                handle = scrub_then_remove(
                    _registry, document.view_id, lambda: None
                )
            if handle:
                handles.append(handle)
        except Exception:
            scrub_failed = True
            try:
                document.lock()
            except Exception:
                pass
            if view is not None:
                try:
                    if view.is_valid():
                        view.set_read_only(True)
                except Exception:
                    pass
    if scrub_failed:
        _orphan_scrub_blocked = True
        message = "Inex locked the sidecar, but one or more marked views require restart"
    else:
        message = reason
    try:
        sublime.status_message(message)
    except Exception:
        pass
    return client, handles


def _shutdown_client(client: Optional[InexRpcClient], handles: List[str]) -> None:
    if client is None:
        return
    for handle in handles:
        if not handle:
            continue
        try:
            client.close_document(handle)
        except Exception:
            pass
    try:
        if client.has_session:
            client.lock()
    except Exception:
        pass
    try:
        client.shutdown()
    finally:
        client.dispose()


def _perform_lock(reason: str) -> None:
    client, handles = _lock_views_and_drop_models(reason)
    try:
        sublime.set_timeout_async(lambda: _shutdown_client(client, handles), 0)
    except Exception:
        _shutdown_client(client, handles)


def _session_lost(expected_client: Optional[InexRpcClient], _error: Exception) -> None:
    # The exception is intentionally not logged or echoed. It may originate in
    # child-process lifecycle code; only a fixed UI message is used.
    def lock_after_loss() -> None:
        current, _vault, _epoch = _runtime_snapshot()
        if not session_owner_is_current(expected_client, current):
            return
        client, handles = _lock_views_and_drop_models(
            "Inex sidecar/session was lost; buffers were locked"
        )
        sublime.set_timeout_async(lambda: _shutdown_client(client, handles), 0)

    sublime.set_timeout(lock_after_loss, 0)


def _security_gate_changed() -> None:
    if insecure_preferences():
        client, _vault, _unused = _runtime_snapshot()
        if client is not None or _registry.values():
            _perform_lock("Inex strict security preferences changed; buffers were locked")


def _scrub_orphaned_marked_views() -> bool:
    safe = True
    for window in _all_windows():
        for view in window.views(include_transient=True):
            try:
                if (
                    view.is_valid()
                    and view.settings().get(VIEW_PLAINTEXT_MARKER) is True
                ):
                    _replace_view_with_fixed_text(
                        view, LOCKED_TEXT, "Inex: orphaned plaintext locked"
                    )
            except Exception:
                safe = False
                try:
                    view.set_read_only(True)
                except Exception:
                    pass
    return safe


def plugin_loaded() -> None:
    global _plugin_active, _orphan_scrub_blocked
    if not _scrub_orphaned_marked_views():
        _plugin_active = False
        _orphan_scrub_blocked = True
        sublime.message_dialog(
            "Inex editing remains disabled because an orphaned marked view "
            "could not be scrubbed. Close the view and restart Sublime Text."
        )
        return
    _orphan_scrub_blocked = False
    _plugin_active = True
    preferences = sublime.load_settings("Preferences.sublime-settings")
    preferences.clear_on_change(PREFERENCES_CHANGE_TAG)
    preferences.add_on_change(PREFERENCES_CHANGE_TAG, _security_gate_changed)


def plugin_unloaded() -> None:
    global _plugin_active, _unlock_in_progress
    _plugin_active = False
    _unlock_in_progress = False
    preferences = sublime.load_settings("Preferences.sublime-settings")
    preferences.clear_on_change(PREFERENCES_CHANGE_TAG)
    client, handles = _lock_views_and_drop_models("Inex plugin unloaded")
    _shutdown_client(client, handles)


def _note_user_activity() -> None:
    global _last_activity_ping, _activity_ping_inflight
    client, _vault, _generation_value = _runtime_snapshot()
    now = time.monotonic()
    if (
        client is None
        or _activity_ping_inflight
        or now - _last_activity_ping < 30.0
    ):
        return
    _last_activity_ping = now
    _activity_ping_inflight = True

    def worker() -> None:
        try:
            client.ping()
        except Exception as error:
            sublime.set_timeout(
                lambda error=error: _session_lost(client, error), 0
            )
        finally:
            sublime.set_timeout(finished, 0)

    def finished() -> None:
        global _activity_ping_inflight
        _activity_ping_inflight = False

    sublime.set_timeout_async(worker, 0)


def _session_activity(expected_client: Optional[InexRpcClient]) -> None:
    authenticated_at = time.monotonic()
    sublime.set_timeout(
        lambda: _renew_idle_deadline(expected_client, authenticated_at), 0
    )


def _renew_idle_deadline(
    expected_client: Optional[InexRpcClient], authenticated_at: float
) -> None:
    global _idle_timer_serial
    current, _vault, epoch = _runtime_snapshot()
    if current is not expected_client or _idle_deadline is None:
        return
    _idle_deadline.renew(authenticated_at)
    _idle_timer_serial += 1
    if _idle_deadline.state(time.monotonic()) == "expired":
        _perform_lock("Inex vault locked after delayed idle-deadline processing")
        return
    _arm_idle_timers(current, epoch, _idle_timer_serial, _idle_deadline.revision)


def _arm_idle_timers(
    client: InexRpcClient, epoch: int, serial: int, revision: int
) -> None:
    deadline = _idle_deadline
    if deadline is None:
        return
    now = time.monotonic()
    warning_delay = deadline.delay_to_warning_ms(now)
    expiry_delay = deadline.delay_to_expiry_ms(now)
    sublime.set_timeout(
        lambda: _idle_warning(client, epoch, serial, revision), warning_delay
    )
    sublime.set_timeout(
        lambda: _idle_expired(client, epoch, serial, revision), expiry_delay + 1
    )


def _idle_callback_current(
    client: InexRpcClient, epoch: int, serial: int, revision: int
) -> bool:
    current, _vault, current_epoch = _runtime_snapshot()
    return (
        current is client
        and current_epoch == epoch
        and _idle_deadline is not None
        and _idle_timer_serial == serial
        and _idle_deadline.revision == revision
    )


def _idle_warning(
    client: InexRpcClient, epoch: int, serial: int, revision: int
) -> None:
    if not _idle_callback_current(client, epoch, serial, revision):
        return
    state = _idle_deadline.state(time.monotonic()) if _idle_deadline else "expired"
    if state == "active":
        delay = max(1, _idle_deadline.delay_to_warning_ms(time.monotonic()))
        sublime.set_timeout(
            lambda: _idle_warning(client, epoch, serial, revision), delay
        )
        return
    if state == "warning":
        sublime.status_message("Inex vault will lock soon because the session is idle")


def _idle_expired(
    client: InexRpcClient, epoch: int, serial: int, revision: int
) -> None:
    if not _idle_callback_current(client, epoch, serial, revision):
        return
    if _idle_deadline is not None and _idle_deadline.state(time.monotonic()) != "expired":
        delay = _idle_deadline.delay_to_expiry_ms(time.monotonic())
        sublime.set_timeout(
            lambda: _idle_expired(client, epoch, serial, revision), delay + 1
        )
        return
    _perform_lock("Inex vault locked after the authenticated idle deadline")


def _finish_unlock(
    window: sublime.Window,
    client: InexRpcClient,
    vault_path: str,
    result: Dict[str, Any],
    expected_generation: int,
    authenticated_at: float,
) -> None:
    global _client, _vault_id, _vault_path, _generation, _unlock_in_progress
    global _last_activity_ping, _activity_ping_inflight
    global _idle_deadline, _idle_timer_serial
    if (
        not session_epoch_is_current(
            expected_generation, _runtime_snapshot()[2], _plugin_active
        )
        or not _unlock_in_progress
    ):
        client.dispose()
        return
    _unlock_in_progress = False
    if insecure_preferences():
        client.dispose()
        _show_security_block(window)
        return
    with _runtime_lock:
        if _generation != expected_generation or _client is not None:
            client.dispose()
            _show_error(RpcLifecycleError("Another Inex vault is already unlocked"))
            return
        _client = client
        _vault_id = result["vaultId"]
        _vault_path = vault_path
        _generation += 1
        _last_activity_ping = 0.0
        _activity_ping_inflight = False
        _idle_deadline = IdleDeadline(result["idleTimeoutMs"], authenticated_at)
        _idle_timer_serial += 1
        installed_epoch = _generation
        installed_serial = _idle_timer_serial
        installed_revision = _idle_deadline.revision
    window.status_message("Inex vault unlocked")
    if _idle_deadline.state(time.monotonic()) == "expired":
        _perform_lock("Inex vault locked because unlock delivery exceeded its idle allowance")
        return
    _arm_idle_timers(
        client, installed_epoch, installed_serial, installed_revision
    )
    _show_tree(window, "")


def _unlock_failed(error: Exception, expected_generation: int) -> None:
    global _unlock_in_progress
    if not session_epoch_is_current(
        expected_generation, _runtime_snapshot()[2], _plugin_active
    ):
        return
    _unlock_in_progress = False
    _show_error(error)


def _begin_unlock(window: sublime.Window) -> None:
    global _unlock_in_progress
    if insecure_preferences():
        _show_security_block(window)
        return
    existing, _vault, start_generation = _runtime_snapshot()
    if existing is not None and existing.has_session:
        _show_tree(window, "")
        return
    if _unlock_in_progress:
        window.status_message("Inex unlock is already in progress")
        return
    settings = _settings()
    vault_path = settings.get("vault_path", "")
    if not isinstance(vault_path, str) or not os.path.isabs(vault_path):
        _show_error(RpcLifecycleError("Configure an absolute vault_path first"))
        return
    try:
        executable = resolve_sidecar(
            settings.get("sidecar_path", ""), os.path.dirname(__file__), sublime.platform()
        )
    except Exception as error:
        _show_error(error)
        return
    zenity_path = settings.get("zenity_path", "")
    if not isinstance(zenity_path, str):
        _show_error(PasswordPromptError("zenity_path must be a string"))
        return
    _unlock_in_progress = True

    def worker() -> None:
        client = None
        try:
            password = prompt_password(sublime.platform(), zenity_path)
            if password is None:
                sublime.set_timeout(
                    lambda: _unlock_failed(
                        PasswordPromptError("Unlock canceled"), start_generation
                    ),
                    0,
                )
                return
            client = InexRpcClient(
                executable,
                on_session_lost=lambda error: _session_lost(client, error),
                on_session_activity=lambda: _session_activity(client),
            )
            client.start(PACKAGE_VERSION)
            try:
                result = client.unlock(vault_path, password)
                authenticated_at = time.monotonic()
            finally:
                # Python strings are immutable and cannot be deterministically
                # zeroized. No reference is retained by this plugin.
                password = ""
            sublime.set_timeout(
                lambda: _finish_unlock(
                    window,
                    client,
                    vault_path,
                    result,
                    start_generation,
                    authenticated_at,
                ),
                0,
            )
        except Exception as error:
            if client is not None:
                client.dispose()
            sublime.set_timeout(
                lambda error=error: _unlock_failed(error, start_generation), 0
            )

    sublime.set_timeout_async(worker, 0)


def _immediate_tree_items(
    entries: List[Dict[str, str]], prefix: str
) -> List[Tuple[str, str]]:
    prefix_with_slash = prefix + "/" if prefix else ""
    items: Dict[Tuple[str, str], None] = {}
    for entry in entries:
        path = entry["logicalPath"]
        validate_logical_path(path, allow_directory=entry["kind"] == "directory")
        if prefix_with_slash and not path.startswith(prefix_with_slash):
            continue
        remainder = path[len(prefix_with_slash) :]
        first, separator, _tail = remainder.partition("/")
        if separator:
            logical = prefix_with_slash + first
            items[("directory", logical)] = None
        elif first:
            items[(entry["kind"], path)] = None
    return sorted(items, key=lambda item: (item[0] != "directory", item[1].casefold(), item[1]))


def _show_tree(window: sublime.Window, prefix: str) -> None:
    try:
        validate_logical_path(prefix, allow_directory=True)
        client, _vault, generation = _runtime_snapshot()
        if client is None:
            raise RpcLifecycleError("Inex vault is locked")
    except Exception as error:
        _show_error(error)
        return

    def worker() -> None:
        try:
            entries = client.list_tree(prefix)
            items = _immediate_tree_items(entries, prefix)
            sublime.set_timeout(lambda: present(items), 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: _show_error(error), 0)

    def present(items: List[Tuple[str, str]]) -> None:
        try:
            _current_client(generation)
        except Exception:
            return
        choices: List[List[str]] = []
        actions: List[Tuple[str, str]] = []
        if prefix:
            parent = prefix.rpartition("/")[0]
            choices.append(["../", "Parent directory"])
            actions.append(("directory", parent))
        for kind, path in items:
            label = path.rpartition("/")[2] + ("/" if kind == "directory" else "")
            choices.append([label, path])
            actions.append((kind, path))
        if not choices:
            window.status_message("Inex: this vault directory is empty")
            return

        def selected(index: int) -> None:
            if index < 0 or index >= len(actions):
                return
            try:
                if _current_client(generation) is not client:
                    return
            except Exception:
                return
            kind, path = actions[index]
            if kind == "directory":
                _show_tree(window, path)
            else:
                _open_document(window, path, None)

        window.show_quick_panel(choices, selected, placeholder="Inex vault: /" + prefix)

    sublime.set_timeout_async(worker, 0)


def _open_document(
    window: sublime.Window,
    logical_path: str,
    location: Optional[Tuple[int, int]],
    heading_slug_value: Optional[str] = None,
) -> None:
    try:
        validate_logical_path(logical_path)
        if insecure_preferences():
            raise RpcLifecycleError("Inex strict security gate is not satisfied")
        for document in _registry.values():
            if document.logical_path == logical_path:
                view = _view_by_id(document.view_id)
                if view is not None:
                    window.focus_view(view)
                    if location is not None:
                        _select_location(view, location)
                    elif heading_slug_value:
                        _select_heading(view, document, heading_slug_value)
                    return
        client, _vault, generation = _runtime_snapshot()
        if client is None:
            raise RpcLifecycleError("Inex vault is locked")
    except Exception as error:
        _show_error(error)
        return

    def worker() -> None:
        handle = ""
        content = bytearray()
        recovered_content = bytearray()
        envelope = bytearray()
        owner_token: Optional[str] = None
        try:
            handle, content, etag = client.open_document(logical_path)
            owner_token = _pending_plaintext.add(handle, client, content)
            content = bytearray()
            client_now, vault_id, epoch_now = _runtime_snapshot()
            if client_now is not client or epoch_now != generation or vault_id is None:
                raise RpcLifecycleError("Inex session changed during document open")
            filename = draft_filename(vault_id, logical_path)
            loaded = read_encrypted_draft(_draft_directory(), filename)
            if loaded is not None:
                envelope = loaded
                recovered_content, base_etag = client.decrypt_draft(
                    logical_path, envelope
                )
                if not _pending_plaintext.add_buffer(owner_token, recovered_content):
                    recovered_content = bytearray()
                    raise RpcLifecycleError("Inex pending document was canceled")
                recovered_content = bytearray()
                client_now, _vault_now, epoch_now = _runtime_snapshot()
                if client_now is not client or epoch_now != generation:
                    raise RpcLifecycleError("Inex session changed during draft recovery")
                sublime.set_timeout(
                    lambda owner_token=owner_token, etag=etag,
                    base_etag=base_etag, filename=filename: offer_recovery(
                        owner_token,
                        etag,
                        base_etag,
                        filename,
                    ),
                    0,
                )
            else:
                sublime.set_timeout(
                    lambda owner_token=owner_token, etag=etag: finish_pending_open(
                        owner_token, etag, False, False, etag
                    ),
                    0,
                )
            # Ownership remains in the explicit pending registry until the UI
            # callback atomically claims it or lock drains it.
            owner_token = None
        except Exception as error:
            wipe(content)
            wipe(recovered_content)
            if owner_token is not None:
                owner = _pending_plaintext.take(owner_token)
                if owner is not None:
                    _cleanup_pending_owner(owner)
            elif handle:
                try:
                    client.close_document(handle)
                except Exception:
                    pass
            sublime.set_timeout(lambda error=error: _show_error(error), 0)
        finally:
            wipe(envelope)

    def finish_pending_open(
        owner_token: str,
        etag: str,
        recovered: bool,
        stale_recovery: bool,
        recovery_base_etag: Optional[str],
    ) -> None:
        owner = _pending_plaintext.take(owner_token)
        if owner is None:
            return
        if owner.context is not client or len(owner.buffers) != 1:
            _cleanup_pending_owner(owner)
            return
        content = owner.buffers[0]
        owner.buffers = []
        finish_open(
            owner.handle,
            content,
            etag,
            recovered,
            stale_recovery,
            recovery_base_etag,
        )

    def finish_open(
        handle: str,
        content: bytearray,
        etag: str,
        recovered: bool,
        stale_recovery: bool,
        recovery_base_etag: Optional[str],
    ) -> None:
        view = None
        document = None
        try:
            if _current_client(generation) is not client:
                raise RpcLifecycleError("Inex session changed during document open")
            if insecure_preferences():
                raise RpcLifecycleError("Inex strict security gate changed during open")
            view = window.new_file(syntax="Packages/Markdown/Markdown.sublime-syntax")
            # Ordering is a security boundary: scratch must be true before the
            # first plaintext character enters Sublime.
            view.set_scratch(True)
            if view.file_name() is not None:
                raise RpcLifecycleError("Sublime created an unsafe named buffer")
            # The fixed Boolean marker intentionally survives plugin-host loss.
            # It must exist before the first plaintext insertion command.
            view.settings().set(VIEW_PLAINTEXT_MARKER, True)
            view.set_name(logical_path + " — Inex")
            document = ManagedDocument(
                view.id(),
                logical_path,
                handle,
                etag,
                content,
                recovered=recovered,
                stale_recovery=stale_recovery,
                recovery_base_etag=recovery_base_etag,
            )
            _registry.add(document)
            # Establish the current-macro fingerprint while the view is empty
            # and already managed.  If recording was armed in an ordinary
            # buffer, the first plaintext insertion changes the fingerprint;
            # its post-command hook then stops recording and scrubs the view.
            _start_macro_monitoring()
            _scrubbing_views.add(view.id())
            try:
                _replace_buffer_from_bytes(view, bytearray(content))
            finally:
                _scrubbing_views.discard(view.id())
            if _registry.get(view.id()) is not document or _macro_is_tainted():
                raise RpcLifecycleError(
                    "Inex stopped active macro recording before opening the document"
                )
            view.run_command("clear_undo_stack")
            _update_document_ui(document)
            if location is not None:
                _select_location(view, location)
            elif heading_slug_value:
                _select_heading(view, document, heading_slug_value)
        except Exception as error:
            wipe(content)
            scrub_failed = False
            if document is not None and _registry.get(document.view_id) is document:
                try:
                    scrub_then_remove(
                        _registry,
                        document.view_id,
                        lambda: _replace_view_with_fixed_text(
                            view, LOCKED_TEXT, "Inex: document open failed"
                        ),
                    )
                except Exception:
                    scrub_failed = True
                    document.lock()
                    if view is not None and view.is_valid():
                        view.set_read_only(True)
            elif view is not None and view.is_valid():
                try:
                    _replace_view_with_fixed_text(
                        view, LOCKED_TEXT, "Inex: document open failed"
                    )
                except Exception:
                    scrub_failed = True
                    view.set_read_only(True)
            if scrub_failed:
                _perform_lock("Inex failed closed after a document-open scrub error")
            else:
                sublime.set_timeout_async(
                    lambda: _close_handle_best_effort(client, handle), 0
                )
            _show_error(error)

    def offer_recovery(
        owner_token: str,
        etag: str,
        base_etag: Optional[str],
        filename: str,
    ) -> None:
        try:
            if _current_client(generation) is not client or insecure_preferences():
                raise RpcLifecycleError("Inex session changed during draft recovery")
        except Exception:
            owner = _pending_plaintext.take(owner_token)
            if owner is not None:
                _cleanup_pending_owner(owner)
            return
        stale = base_etag != etag
        if stale:
            detail = (
                "The authenticated draft is based on older ciphertext. "
                "Saving it will require a second overwrite confirmation and a current-etag check."
            )
        else:
            detail = "The authenticated draft matches the current ciphertext etag."
        choices = [
            ["Restore encrypted draft as dirty", detail],
            ["Discard encrypted draft", "Delete ciphertext draft and open the saved document"],
            ["Cancel", "Leave the encrypted draft untouched and open nothing"],
        ]

        def selected(index: int) -> None:
            owner = _pending_plaintext.take(owner_token)
            if owner is None:
                return
            try:
                current = _current_client(generation)
            except Exception:
                current = None
            if current is not client or owner.context is not client or len(owner.buffers) != 2:
                _cleanup_pending_owner(owner)
                return
            content, recovered_content = owner.buffers
            owner.buffers = []
            if index == 0:
                wipe(content)
                finish_open(
                    owner.handle,
                    recovered_content,
                    etag,
                    True,
                    stale,
                    base_etag,
                )
                return
            if index == 1:
                try:
                    remove_encrypted_draft(_draft_directory(), filename)
                except Exception as error:
                    _release_unopened_document(
                        client, owner.handle, [content, recovered_content]
                    )
                    _show_error(error)
                    return
                wipe(recovered_content)
                finish_open(owner.handle, content, etag, False, False, etag)
                return
            _release_unopened_document(
                client, owner.handle, [content, recovered_content]
            )

        window.show_quick_panel(
            choices, selected, placeholder="Authenticated Inex recovery draft found"
        )

    sublime.set_timeout_async(worker, 0)


def _select_location(view: sublime.View, location: Tuple[int, int]) -> None:
    row, utf16_column = location
    point = view.text_point_utf16(row, utf16_column, clamp_column=True)
    selection = view.sel()
    selection.clear()
    selection.add(sublime.Region(point, point))
    view.show(point)


def _select_heading(
    view: sublime.View, document: ManagedDocument, slug: str
) -> None:
    snapshot = bytearray(document.content)
    try:
        text = snapshot.decode("utf-8", "strict")
    finally:
        wipe(snapshot)
    for heading in markdown_headings(text):
        if heading["slug"] == slug:
            point = view.text_point(
                int(heading["line"]), int(heading["column"]), clamp_column=True
            )
            selection = view.sel()
            selection.clear()
            selection.add(sublime.Region(point, point))
            view.show(point)
            return
    sublime.status_message("Inex: target heading was not found")


def _navigation_snapshot(
    window: sublime.Window,
) -> Tuple[ManagedDocument, InexRpcClient, int, str]:
    view = window.active_view()
    document = _registry.get(view.id()) if view is not None else None
    client, _vault, generation = _runtime_snapshot()
    if document is None or client is None:
        raise ModelError("An active Inex document is required")
    snapshot = bytearray(document.content)
    try:
        text = snapshot.decode("utf-8", "strict")
    finally:
        wipe(snapshot)
    return document, client, generation, text


def _capture_view(document: ManagedDocument) -> Tuple[int, bytearray]:
    view = _view_by_id(document.view_id)
    if view is None or not view.is_valid():
        raise ModelError("Managed view is unavailable")
    if (
        view.file_name() is not None
        or not view.is_scratch()
        or view.settings().get(VIEW_PLAINTEXT_MARKER) is not True
    ):
        raise ModelError("Managed view entered unsafe file state")
    text = view.substr(sublime.Region(0, view.size()))
    content = bytearray(text.encode("utf-8"))
    if content != document.content:
        document.replace(content)
    else:
        wipe(content)
    return document.snapshot()


def _write_draft_snapshot(
    client: InexRpcClient,
    vault_id: str,
    document: ManagedDocument,
    logical_path: str,
    version: int,
    draft_epoch: int,
    snapshot: bytearray,
    base_etag: Optional[str],
) -> bool:
    envelope = bytearray()
    try:
        with document.draft_lock:
            if (
                not document.draft_snapshot_is_current(version, draft_epoch)
                or document.logical_path != logical_path
            ):
                return False
            envelope = client.encrypt_draft(
                logical_path, snapshot, base_etag
            )
            atomic_write_ciphertext(
                _draft_directory(),
                draft_filename(vault_id, logical_path),
                envelope,
            )
        return True
    finally:
        wipe(snapshot)
        wipe(envelope)


def _schedule_draft(document: ManagedDocument, debounce_generation: int) -> None:
    delay = _settings().get("draft_debounce_ms", 250)
    if isinstance(delay, bool) or not isinstance(delay, int) or delay < 100 or delay > 5000:
        delay = 250

    def begin() -> None:
        current = _registry.get(document.view_id)
        if (
            current is not document
            or document.closed
            or document.debounce_generation != debounce_generation
        ):
            return
        try:
            version, snapshot = document.snapshot()
            draft_epoch = document.draft_epoch
            logical_path = document.logical_path
            base_etag = document.draft_base_etag
            client, vault_id, generation = _runtime_snapshot()
            if client is None or vault_id is None:
                raise RpcLifecycleError("Inex vault is locked")
        except Exception as error:
            _draft_failed(document, error)
            return

        def worker() -> None:
            try:
                wrote = _write_draft_snapshot(
                    client,
                    vault_id,
                    document,
                    logical_path,
                    version,
                    draft_epoch,
                    snapshot,
                    base_etag,
                )
                if wrote:
                    sublime.set_timeout(
                        lambda: drafted(
                            version,
                            draft_epoch,
                            logical_path,
                            generation,
                            base_etag,
                        ),
                        0,
                    )
            except Exception as error:
                sublime.set_timeout(
                    lambda error=error: _draft_failed(document, error), 0
                )

        def drafted(
            version: int,
            expected_draft_epoch: int,
            expected_path: str,
            expected_generation: int,
            base_etag: str,
        ) -> None:
            current_document = _registry.get(document.view_id)
            try:
                _current_client(expected_generation)
            except Exception:
                return
            if current_document is document:
                if (
                    document.draft_epoch != expected_draft_epoch
                    or document.logical_path != expected_path
                    or document.draft_base_etag != base_etag
                    or not document.dirty
                ):
                    try:
                        remove_encrypted_draft(
                            _draft_directory(),
                            draft_filename(vault_id, expected_path),
                        )
                    except Exception as error:
                        _draft_failed(document, error)
                        return
                else:
                    document.mark_drafted(version)
                _update_document_ui(document)

        sublime.set_timeout_async(worker, 0)

    sublime.set_timeout(begin, delay)


def _draft_failed(document: ManagedDocument, error: Exception) -> None:
    if _registry.get(document.view_id) is not document:
        return
    document.lock()
    view = _view_by_id(document.view_id)
    if view is not None:
        view.set_read_only(True)
    _update_document_ui(document)
    sublime.message_dialog(
        "Inex encrypted draft failed; this buffer is now read-only.\n\n"
        + _safe_error(error)
    )


def _save_one(
    document: ManagedDocument,
    on_done: Optional[Callable[[bool], None]] = None,
    recovery_overwrite_confirmed: bool = False,
) -> None:
    if document.requires_overwrite_confirmation and not recovery_overwrite_confirmed:
        view = _view_by_id(document.view_id)
        window = view.window() if view is not None else None
        if window is None:
            if on_done is not None:
                on_done(False)
            return
        client_before, _vault_before, generation_before = _runtime_snapshot()
        choices = [
            [
                "Overwrite current ciphertext with recovery draft",
                "The write still aborts if the current etag changed",
            ],
            ["Cancel", "Keep the stale recovery draft dirty"],
        ]

        def confirmed(index: int) -> None:
            current, _vault_now, generation_now = _runtime_snapshot()
            if (
                index == 0
                and current is client_before
                and generation_now == generation_before
                and _registry.get(document.view_id) is document
            ):
                _save_one(document, on_done, True)
            elif on_done is not None:
                on_done(False)

        window.show_quick_panel(
            choices,
            confirmed,
            placeholder="Confirm stale Inex recovery overwrite",
        )
        return
    try:
        client, vault_id, generation = _runtime_snapshot()
        if client is None or vault_id is None:
            raise RpcLifecycleError("Inex vault is locked")
        version, snapshot = _capture_view(document)
        write_etag = document.etag
    except Exception as error:
        _show_error(error)
        if on_done is not None:
            on_done(False)
        return

    def worker() -> None:
        try:
            new_etag, durability = client.write_document(
                document.logical_path, snapshot, write_etag
            )
            sublime.set_timeout(lambda: saved(new_etag, durability), 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: failed(error), 0)
        finally:
            wipe(snapshot)

    def saved(new_etag: str, durability: str) -> None:
        success = False
        if _registry.get(document.view_id) is document:
            try:
                _current_client(generation)
                document.mark_saved(version, new_etag)
                document.mark_drafted(version)
                if not document.dirty:
                    try:
                        remove_encrypted_draft(
                            _draft_directory(),
                            draft_filename(vault_id, document.logical_path),
                        )
                    except Exception as error:
                        sublime.message_dialog(
                            "Inex saved ciphertext, but could not remove the old encrypted draft.\n\n"
                            + _safe_error(error)
                        )
                else:
                    _schedule_draft(document, document.debounce_generation)
                _update_document_ui(document)
                _warn_if_not_synced("save", (durability,))
                success = True
            except Exception:
                pass
        if on_done is not None:
            on_done(success)

    def failed(error: Exception) -> None:
        _show_error(error)
        if on_done is not None:
            on_done(False)

    sublime.set_timeout_async(worker, 0)


def _save_many(
    window: sublime.Window,
    documents: List[ManagedDocument],
    on_done: Optional[Callable[[bool], None]] = None,
    save_regular: bool = False,
) -> None:
    remaining = list(documents)
    all_ok = True

    def next_document(ok: bool = True) -> None:
        nonlocal all_ok
        all_ok = all_ok and ok
        if remaining:
            _save_one(remaining.pop(0), next_document)
            return
        if save_regular:
            for view in window.views(include_transient=True):
                if _registry.get(view.id()) is None and view.is_dirty():
                    view.run_command("save")
        if on_done is not None:
            on_done(all_ok)

    next_document(True)


def _flush_final_draft(document: ManagedDocument) -> bool:
    if not document.dirty or document.draft_version >= document.version:
        return True
    snapshot = bytearray()
    try:
        client, vault_id, _generation_value = _runtime_snapshot()
        if client is None or vault_id is None:
            raise RpcLifecycleError("Inex vault is locked")
        version, snapshot = _capture_view(document)
        draft_epoch = document.draft_epoch
        logical_path = document.logical_path
        base_etag = document.draft_base_etag
        wrote = _write_draft_snapshot(
            client,
            vault_id,
            document,
            logical_path,
            version,
            draft_epoch,
            snapshot,
            base_etag,
        )
        if not wrote:
            raise DraftStorageError("Encrypted draft was superseded before close")
        document.mark_drafted(version)
        return True
    except Exception as error:
        wipe(snapshot)
        sublime.message_dialog(
            "Inex could not finish the encrypted draft before close. "
            "Sublime's pre-close API cannot veto closing.\n\n" + _safe_error(error)
        )
        return False


def _prepare_close(view: sublime.View) -> None:
    document = _registry.get(view.id())
    if document is None:
        return
    _flush_final_draft(document)
    client, _vault, _unused = _runtime_snapshot()
    handle = scrub_then_remove(
        _registry,
        view.id(),
        lambda: _replace_view_with_fixed_text(view, LOCKED_TEXT, "Inex: closing"),
    )
    if client is not None and handle:
        sublime.set_timeout_async(
            lambda: _close_handle_best_effort(client, handle), 0
        )


def _close_handle_best_effort(client: InexRpcClient, handle: str) -> None:
    try:
        client.close_document(handle)
    except Exception:
        pass


def _release_unopened_document(
    client: InexRpcClient, handle: str, buffers: List[bytearray]
) -> None:
    for buffer in buffers:
        wipe(buffer)
    if handle:
        sublime.set_timeout_async(
            lambda: _close_handle_best_effort(client, handle), 0
        )


def _close_managed_active(window: sublime.Window) -> None:
    view = window.active_view()
    if view is None or _registry.get(view.id()) is None:
        return
    _prepare_close(view)
    _registry.grant_bypass(window.id(), "close_file")
    window.run_command("close_file")


def _close_many(window: sublime.Window, original_command: str, args: Dict[str, Any]) -> None:
    for document in _window_managed_documents(window):
        view = _view_by_id(document.view_id)
        if view is not None:
            _prepare_close(view)
    _registry.grant_bypass(window.id(), original_command)
    window.run_command(original_command, args)


def _flush_then_close_filtered(
    window: sublime.Window, original_command: str, args: Dict[str, Any]
) -> None:
    # Indexed/selected close commands may leave some Inex views open. Flush all
    # candidates but let on_pre_close remove only the views Sublime actually
    # closes, keeping the survivors managed.
    for document in _window_managed_documents(window):
        _flush_final_draft(document)
    _registry.grant_bypass(window.id(), original_command)
    window.run_command(original_command, args)


def _prompt_lock(window: sublime.Window) -> None:
    documents = _registry.values()
    dirty = [document for document in documents if document.dirty]
    if not dirty:
        _perform_lock("Inex vault locked")
        return

    choices = [
        ["Save encrypted changes and lock", "Writes with etag checks before locking"],
        ["Discard unsaved changes and lock", "Encrypted drafts already written remain ciphertext"],
        ["Cancel", "Keep the vault unlocked"],
    ]

    def selected(index: int) -> None:
        if index == 0:
            views = []
            for document in dirty:
                view = _view_by_id(document.view_id)
                if view is not None:
                    view.set_read_only(True)
                    views.append(view)

            def finished(ok: bool) -> None:
                if ok:
                    _perform_lock("Inex vault locked after encrypted save")
                else:
                    for view in views:
                        if view.is_valid():
                            view.set_read_only(False)

            _save_many(window, dirty, finished)
        elif index == 1:
            _perform_lock("Inex vault locked; unsaved in-memory changes discarded")

    window.show_quick_panel(choices, selected, placeholder="Lock Inex vault")


def _begin_umbra_unlock(window: sublime.Window) -> None:
    """Unlock only K_umbra; Outer session and ordinary buffers stay intact."""
    if insecure_preferences():
        _show_security_block(window)
        return
    client, _vault, generation = _runtime_snapshot()
    if client is None or not client.has_session:
        _show_error(RpcLifecycleError("Unlock the Outer Inex vault first"))
        return
    settings = _settings()
    zenity_path = settings.get("zenity_path", "")
    if not isinstance(zenity_path, str):
        _show_error(PasswordPromptError("zenity_path must be a string"))
        return

    def request_password(initialize: bool) -> None:
        def worker() -> None:
            password = ""
            try:
                password = prompt_password(sublime.platform(), zenity_path) or ""
                if not password:
                    raise PasswordPromptError("Umbra unlock canceled")
                current, _vault_now, current_generation = _runtime_snapshot()
                if current is not client or current_generation != generation:
                    raise RpcLifecycleError("Inex session changed during Umbra unlock")
                status = (
                    client.initialize_umbra(password)
                    if initialize
                    else client.unlock_umbra(password)
                )
                if not status["initialized"] or not status["unlocked"]:
                    raise RpcProtocolError("Umbra did not enter an unlocked state")
                authenticated_at = time.monotonic()
                sublime.set_timeout(lambda: completed(authenticated_at), 0)
            except Exception as error:
                sublime.set_timeout(lambda error=error: _show_error(error), 0)
            finally:
                password = ""

        sublime.set_timeout_async(worker, 0)

    def completed(authenticated_at: float) -> None:
        global _umbra_generation
        current, _vault_now, current_generation = _runtime_snapshot()
        if current is not client or current_generation != generation:
            return
        _umbra_generation += 1
        _renew_idle_deadline(client, authenticated_at)
        window.status_message("Inex Umbra unlocked")

    def present(status: Dict[str, bool]) -> None:
        current, _vault_now, current_generation = _runtime_snapshot()
        if current is not client or current_generation != generation:
            return
        if status["unlocked"]:
            window.status_message("Inex Umbra is already unlocked")
            return
        if status["initialized"]:
            request_password(False)
            return
        warning = (
            "Umbra password cannot be recovered. Forgetting it permanently loses "
            "all Umbra private content."
        )
        if sublime.ok_cancel_dialog(warning, "Set Umbra Password"):
            request_password(True)

    def status_worker() -> None:
        try:
            status = client.umbra_status()
            sublime.set_timeout(lambda: present(status), 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: _show_error(error), 0)

    sublime.set_timeout_async(status_worker, 0)


def _lock_umbra(window: sublime.Window) -> None:
    try:
        client, _vault, generation = _runtime_snapshot()
        if client is None or not client.has_session:
            raise RpcLifecycleError("Inex vault is locked")
    except Exception as error:
        _show_error(error)
        return

    def worker() -> None:
        try:
            client.lock_umbra()
            sublime.set_timeout(done, 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: _show_error(error), 0)

    def done() -> None:
        global _umbra_generation
        current, _vault_now, current_generation = _runtime_snapshot()
        if current is client and current_generation == generation:
            _umbra_generation += 1
            _clear_annotation_pickers()
            try:
                window.run_command("hide_overlay")
            except Exception:
                pass
            window.status_message("Inex Umbra locked; Outer vault remains unlocked")

    sublime.set_timeout_async(worker, 0)


def _enter_active_umbra(window: sublime.Window) -> None:
    """Upgrade a clean active buffer, then replace it with daemon projection."""
    view = window.active_view()
    document = _registry.get(view.id()) if view is not None else None
    session = _command_session(window)
    if view is None or document is None or session is None:
        if document is None:
            _show_error(ModelError("An active Inex document is required"))
        return
    client, _vault_id, generation = session
    if document.is_umbra:
        window.status_message("Inex document is already in Umbra mode")
        return
    if document.dirty or document.read_only:
        _show_error(ModelError("Save a clean active document before entering Umbra"))
        return
    logical_path = document.logical_path
    expected_etag = document.etag
    view.set_read_only(True)

    def worker() -> None:
        content = bytearray()
        converted = False
        try:
            status = client.umbra_status()
            if not status["unlocked"]:
                raise RpcLifecycleError("Unlock Umbra private mode first")
            converted_etag, durability = client.convert_document_to_umbra(
                logical_path, expected_etag
            )
            converted = True
            content, projection_etag, render_map = client.open_umbra_document(logical_path)
            if projection_etag != converted_etag:
                raise RpcProtocolError("Umbra projection ETag does not match conversion")
            sublime.set_timeout(
                lambda: completed(content, projection_etag, render_map, durability), 0
            )
            content = bytearray()
        except Exception as error:
            wipe(content)
            sublime.set_timeout(
                lambda error=error, converted=converted: failed(error, converted), 0
            )

    def completed(
        content: bytearray, projection_etag: str, render_map: Dict[str, Any], durability: str
    ) -> None:
        old_handle = ""
        try:
            current, _vault_now, current_generation = _runtime_snapshot()
            if (
                current is not client
                or current_generation != generation
                or _registry.get(document.view_id) is not document
                or document.logical_path != logical_path
                or document.etag != expected_etag
                or document.dirty
                or document.is_umbra
                or not view.is_valid()
            ):
                raise RpcLifecycleError("Inex session changed during Umbra conversion")
            old_handle = document.transition_to_umbra_projection(
                content, projection_etag, render_map
            )
            content = bytearray()
            _scrubbing_views.add(view.id())
            try:
                _replace_buffer_from_bytes(view, bytearray(document.content))
            finally:
                _scrubbing_views.discard(view.id())
            view.run_command("clear_undo_stack")
            view.set_read_only(False)
            _update_document_ui(document)
            _warn_if_not_synced("save", (durability,))
            window.status_message("Inex document entered Umbra mode")
        except Exception as error:
            wipe(content)
            _perform_lock("Inex locked after an Umbra conversion state change")
            _show_error(error)
            return
        if old_handle:
            sublime.set_timeout_async(
                lambda: _close_handle_best_effort(client, old_handle), 0
            )

    def failed(error: Exception, converted: bool) -> None:
        if converted:
            _perform_lock("Inex locked because Umbra conversion could not complete")
            _show_error(error)
            return
        current, _vault_now, current_generation = _runtime_snapshot()
        if (
            current is client
            and current_generation == generation
            and _registry.get(document.view_id) is document
            and view.is_valid()
            and not document.is_umbra
        ):
            view.set_read_only(False)
        _show_error(error)

    sublime.set_timeout_async(worker, 0)


def _clear_annotation_pickers() -> None:
    global _annotation_pickers
    for state in _annotation_pickers:
        try:
            state.clear()
        except Exception:
            pass
    _annotation_pickers = []


def _show_annotation_picker(
    window: sublime.Window,
    state: AnnotationPickerState,
    on_apply: Callable[[Dict[str, Any]], None],
) -> None:
    """Show the MVP repeated Quick Panel without persisting private labels."""
    _annotation_pickers.append(state)

    def discard() -> None:
        if state in _annotation_pickers:
            _annotation_pickers.remove(state)
        state.clear()

    def submit() -> None:
        if state.outer != "cover":
            try:
                on_apply(state.spec())
            finally:
                discard()
            return

        def cover_done(cover_text: str) -> None:
            try:
                on_apply(state.spec(cover_text))
            except Exception as error:
                _show_error(error)
            finally:
                discard()

        window.show_input_panel("Public cover text", "", cover_done, None, discard)

    def present() -> None:
        if state not in _annotation_pickers:
            return
        items = state.items()
        choices = [item["label"] for item in items]

        def selected(index: int) -> None:
            if index < 0 or index >= len(items):
                discard()
                return
            try:
                action = state.select(items[index]["id"])
                if action == "cancel":
                    discard()
                elif action == "done":
                    submit()
                else:
                    present()
            except Exception as error:
                discard()
                _show_error(error)

        window.show_quick_panel(choices, selected, placeholder="Configure private annotation")

    present()


def _apply_private_annotation_from_active_view(window: sublime.Window) -> None:
    view = window.active_view()
    document = _registry.get(view.id()) if view is not None else None
    session = _command_session(window)
    if view is None or document is None or session is None:
        if document is None:
            _show_error(ModelError("An active Inex document is required"))
        return
    client, _vault_id, generation = session
    if not document.is_umbra or document.dirty or document.read_only:
        _show_error(ModelError("A clean active Umbra projection is required"))
        return
    try:
        selections = []
        for region in view.sel():
            if region.empty():
                raise ModelError("Select Markdown before applying a private annotation")
            start = len(view.substr(sublime.Region(0, region.begin())).encode("utf-8"))
            end = len(view.substr(sublime.Region(0, region.end())).encode("utf-8"))
            selections.append({"startByte": start, "endByte": end})
        if not selections or len(selections) > 64:
            raise ModelError("Private annotation selections are invalid")
        if bytearray(view.substr(sublime.Region(0, view.size())).encode("utf-8")) != document.content:
            raise ModelError("Umbra projection changed; reopen it before annotating")
    except Exception as error:
        _show_error(error)
        return
    expected_etag = document.etag
    expected_map = document.umbra_render_map
    if expected_map is None:
        _show_error(ModelError("Umbra projection is unavailable"))
        return
    umbra_generation = _umbra_generation

    def load_picker() -> None:
        try:
            if not client.umbra_status()["unlocked"]:
                raise RpcLifecycleError("Unlock Umbra private mode first")
            config = client.load_umbra_annotation_config()
            state = AnnotationPickerState(config)
            sublime.set_timeout(lambda: present(state), 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: _show_error(error), 0)

    def present(state: AnnotationPickerState) -> None:
        if (
            _runtime_snapshot()[0] is not client
            or _runtime_snapshot()[2] != generation
            or _umbra_generation != umbra_generation
            or _registry.get(document.view_id) is not document
        ):
            state.clear()
            return
        _show_annotation_picker(window, state, lambda spec: apply(spec))

    def apply(spec: Dict[str, Any]) -> None:
        def worker() -> None:
            content = bytearray()
            try:
                content, etag, render_map, durability = client.apply_private_annotation(
                    document.logical_path, bytearray(document.content), expected_etag,
                    expected_map, selections, spec,
                )
                sublime.set_timeout(lambda: completed(content, etag, render_map, durability), 0)
                content = bytearray()
            except Exception as error:
                wipe(content)
                sublime.set_timeout(lambda error=error: _show_error(error), 0)

        sublime.set_timeout_async(worker, 0)

    def completed(content: bytearray, etag: str, render_map: Dict[str, Any], durability: str) -> None:
        try:
            if (
                _runtime_snapshot()[0] is not client
                or _runtime_snapshot()[2] != generation
                or _umbra_generation != umbra_generation
                or _registry.get(document.view_id) is not document
                or document.etag != expected_etag
                or document.umbra_render_map != expected_map
                or document.dirty
            ):
                raise RpcLifecycleError("Inex session changed during private annotation")
            document.replace_umbra_projection(content, etag, render_map)
            content = bytearray()
            _scrubbing_views.add(view.id())
            try:
                _replace_buffer_from_bytes(view, bytearray(document.content))
            finally:
                _scrubbing_views.discard(view.id())
            view.run_command("clear_undo_stack")
            _update_document_ui(document)
            _warn_if_not_synced("save", (durability,))
        except Exception as error:
            wipe(content)
            _show_error(error)

    sublime.set_timeout_async(load_picker, 0)


def _search(window: sublime.Window, query: str) -> None:
    try:
        if insecure_preferences():
            raise RpcLifecycleError("Inex strict security gate is not satisfied")
        client, _vault, generation = _runtime_snapshot()
        if client is None:
            raise RpcLifecycleError("Inex vault is locked")
    except Exception as error:
        _show_error(error)
        return

    def worker() -> None:
        try:
            results = client.search(query, 100)
            for result in results:
                validate_logical_path(result["logicalPath"])
            sublime.set_timeout(lambda: present(results), 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: _show_error(error), 0)

    def present(results: List[Dict[str, Any]]) -> None:
        try:
            _current_client(generation)
        except Exception:
            return
        if not results:
            window.status_message("Inex: no search results")
            return
        choices = [
            [
                "%s:%d" % (result["logicalPath"], result["line"] + 1),
                result["snippet"].replace("\n", " "),
            ]
            for result in results
        ]

        def selected(index: int) -> None:
            if index < 0 or index >= len(results):
                return
            try:
                if _current_client(generation) is not client:
                    return
            except Exception:
                return
            result = results[index]
            _open_document(
                window,
                result["logicalPath"],
                (result["line"], result["utf16Column"]),
            )

        window.show_quick_panel(choices, selected, placeholder="Inex search results")

    sublime.set_timeout_async(worker, 0)


def _command_session(
    window: sublime.Window,
) -> Optional[Tuple[InexRpcClient, str, int]]:
    try:
        if insecure_preferences():
            raise RpcLifecycleError("Inex strict security gate is not satisfied")
        client, vault_id, generation = _runtime_snapshot()
        if client is None or vault_id is None or not client.has_session:
            raise RpcLifecycleError("Inex vault is locked")
        return client, vault_id, generation
    except Exception as error:
        _show_error(error)
        return None


def _warn_if_not_synced(operation: str, durabilities: Tuple[str, ...]) -> None:
    messages = {
        "create": (
            "Inex created encrypted Markdown, but the daemon could not confirm "
            "parent-directory durability."
        ),
        "rename": (
            "Inex renamed ciphertext, but the daemon could not confirm all "
            "source/destination directory durability."
        ),
        "delete": (
            "Inex deleted ciphertext, but the daemon could not confirm "
            "parent-directory durability."
        ),
        "save": (
            "Inex saved ciphertext, but the daemon could not confirm "
            "parent-directory durability."
        ),
    }
    message = messages.get(operation)
    if message is not None and "notSynced" in durabilities:
        sublime.message_dialog(message)


def _active_clean_context(
    window: sublime.Window, operation: str
) -> Optional[Tuple[sublime.View, ManagedDocument, InexRpcClient, str, int]]:
    session = _command_session(window)
    if session is None:
        return None
    client, vault_id, generation = session
    view = window.active_view()
    document = _registry.get(view.id()) if view is not None else None
    if view is None or document is None:
        sublime.message_dialog(
            "Inex %s requires an active managed Markdown document." % operation
        )
        return None
    if document.read_only or view.is_read_only():
        sublime.message_dialog(
            "Inex %s requires a clean writable managed document." % operation
        )
        return None
    if (
        view.file_name() is not None
        or not view.is_scratch()
        or view.settings().get(VIEW_PLAINTEXT_MARKER) is not True
    ):
        _emergency_scrub_view(view, "managed CRUD invariant failed")
        return None
    snapshot = bytearray()
    try:
        _version, snapshot = _capture_view(document)
    except Exception as error:
        _show_error(error)
        return None
    finally:
        wipe(snapshot)
    if document.dirty:
        _schedule_draft(document, document.debounce_generation)
        sublime.message_dialog(
            "Save encrypted changes before using Inex %s." % operation
        )
        return None
    return view, document, client, vault_id, generation


def _crud_document_current(
    document: ManagedDocument,
    client: InexRpcClient,
    vault_id: str,
    generation: int,
    logical_path: str,
    etag: str,
    draft_epoch: int,
) -> bool:
    current, current_vault, current_generation = _runtime_snapshot()
    return (
        current is client
        and current_vault == vault_id
        and current_generation == generation
        and _registry.get(document.view_id) is document
        and not document.closed
        and not document.dirty
        and document.logical_path == logical_path
        and document.etag == etag
        and document.draft_epoch == draft_epoch
    )


def _create_markdown(window: sublime.Window, logical_path: str) -> None:
    session = _command_session(window)
    if session is None:
        return
    client, _vault_id, generation = session
    try:
        path = validate_logical_path(logical_path)
    except Exception as error:
        _show_error(error)
        return

    def worker() -> None:
        try:
            _etag, durability = client.create_document(path)
            sublime.set_timeout(lambda: created(durability), 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: failed(error), 0)

    def created(durability: str) -> None:
        current, _vault_now, current_generation = _runtime_snapshot()
        if current is client and current_generation == generation:
            _warn_if_not_synced("create", (durability,))
            window.status_message("Inex: encrypted Markdown created")
            _open_document(window, path, None)

    def failed(error: Exception) -> None:
        current, _vault_now, current_generation = _runtime_snapshot()
        if current is client and current_generation == generation:
            _show_error(error)

    sublime.set_timeout_async(worker, 0)


def _create_folder(window: sublime.Window, logical_path: str) -> None:
    session = _command_session(window)
    if session is None:
        return
    client, _vault_id, generation = session
    try:
        path = validate_logical_path(logical_path, allow_directory=True)
        if not path:
            raise ModelError("Logical directory path is invalid")
    except Exception as error:
        _show_error(error)
        return

    def worker() -> None:
        try:
            client.create_directory(path)
            sublime.set_timeout(created, 0)
        except Exception as error:
            sublime.set_timeout(lambda error=error: failed(error), 0)

    def created() -> None:
        current, _vault_now, current_generation = _runtime_snapshot()
        if current is client and current_generation == generation:
            window.status_message("Inex: encrypted folder created")

    def failed(error: Exception) -> None:
        current, _vault_now, current_generation = _runtime_snapshot()
        if current is client and current_generation == generation:
            _show_error(error)

    sublime.set_timeout_async(worker, 0)


def _rename_active(
    window: sublime.Window,
    destination: str,
    expected_document: Optional[ManagedDocument] = None,
) -> None:
    context = _active_clean_context(window, "rename")
    if context is None:
        return
    view, document, client, vault_id, generation = context
    if expected_document is not None and document is not expected_document:
        sublime.message_dialog("Inex rename target changed; retry the command.")
        return
    source = document.logical_path
    source_etag = document.etag
    try:
        destination = validate_logical_path(destination)
        if destination == source:
            raise ModelError("Rename destination must differ from the source")
    except Exception as error:
        _show_error(error)
        return
    view.set_read_only(True)
    operation_draft_epoch = document.invalidate_drafts()

    def worker() -> None:
        try:
            cleanup_error = None
            with document.draft_lock:
                if not _crud_document_current(
                    document,
                    client,
                    vault_id,
                    generation,
                    source,
                    source_etag,
                    operation_draft_epoch,
                ):
                    raise RpcLifecycleError(
                        "Inex rename context changed before ciphertext commit"
                    )
                (
                    new_etag,
                    destination_durability,
                    source_durability,
                ) = client.rename_document(source, destination, source_etag)
                try:
                    remove_encrypted_draft(
                        _draft_directory(), draft_filename(vault_id, source)
                    )
                except Exception as error:
                    cleanup_error = error
            sublime.set_timeout(
                lambda: renamed(
                    new_etag,
                    destination_durability,
                    source_durability,
                    cleanup_error,
                ),
                0,
            )
        except Exception as error:
            sublime.set_timeout(lambda error=error: failed(error), 0)

    def renamed(
        new_etag: str,
        destination_durability: str,
        source_durability: str,
        cleanup_error: Optional[Exception],
    ) -> None:
        current, current_vault, current_generation = _runtime_snapshot()
        if (
            current is not client
            or current_vault != vault_id
            or current_generation != generation
            or _registry.get(document.view_id) is not document
            or document.logical_path != source
            or document.etag != source_etag
            or document.dirty
        ):
            return
        try:
            document.rename_clean(destination, new_etag)
            if cleanup_error is not None:
                sublime.message_dialog(
                    "Inex renamed ciphertext, but could not remove an old "
                    "encrypted draft.\n\n" + _safe_error(cleanup_error)
                )
            if view.is_valid() and not document.read_only:
                view.set_read_only(False)
            _update_document_ui(document)
            _warn_if_not_synced(
                "rename", (destination_durability, source_durability)
            )
            window.status_message("Inex: encrypted document renamed")
        except Exception as error:
            _show_error(error)

    def failed(error: Exception) -> None:
        current, _vault_now, current_generation = _runtime_snapshot()
        if (
            current is client
            and current_generation == generation
            and _registry.get(document.view_id) is document
            and view.is_valid()
            and not document.read_only
        ):
            view.set_read_only(False)
            _show_error(error)

    sublime.set_timeout_async(worker, 0)


def _delete_active(window: sublime.Window) -> None:
    context = _active_clean_context(window, "delete")
    if context is None:
        return
    view, document, client, vault_id, generation = context
    logical_path = document.logical_path
    etag = document.etag
    operation_draft_epoch: Optional[int] = None
    choices = [
        ["Delete encrypted document", "Deletion uses the current ciphertext etag"],
        ["Cancel", "Keep the encrypted document"],
    ]

    def selected(index: int) -> None:
        nonlocal operation_draft_epoch
        current, current_vault, current_generation = _runtime_snapshot()
        if (
            index != 0
            or current is not client
            or current_vault != vault_id
            or current_generation != generation
            or _registry.get(document.view_id) is not document
            or document.logical_path != logical_path
            or document.etag != etag
            or document.dirty
            or document.read_only
            or not view.is_valid()
        ):
            return
        view.set_read_only(True)
        operation_draft_epoch = document.invalidate_drafts()
        sublime.set_timeout_async(worker, 0)

    def worker() -> None:
        try:
            cleanup_error = None
            with document.draft_lock:
                if not _crud_document_current(
                    document,
                    client,
                    vault_id,
                    generation,
                    logical_path,
                    etag,
                    operation_draft_epoch
                    if operation_draft_epoch is not None
                    else -1,
                ):
                    raise RpcLifecycleError(
                        "Inex delete context changed before ciphertext commit"
                    )
                durability = client.delete_document(logical_path, etag)
                try:
                    remove_encrypted_draft(
                        _draft_directory(), draft_filename(vault_id, logical_path)
                    )
                except Exception as error:
                    cleanup_error = error
            sublime.set_timeout(
                lambda: deleted(durability, cleanup_error), 0
            )
        except Exception as error:
            sublime.set_timeout(lambda error=error: failed(error), 0)

    def deleted(
        durability: str, cleanup_error: Optional[Exception]
    ) -> None:
        current, current_vault, current_generation = _runtime_snapshot()
        if (
            current is not client
            or current_vault != vault_id
            or current_generation != generation
            or _registry.get(document.view_id) is not document
            or document.logical_path != logical_path
            or document.etag != etag
            or document.dirty
        ):
            return
        try:
            handle = scrub_then_remove(
                _registry,
                document.view_id,
                lambda: _replace_view_with_fixed_text(
                    view, LOCKED_TEXT, "Inex: deleted"
                ),
            )
            if cleanup_error is not None:
                sublime.message_dialog(
                    "Inex deleted ciphertext, but could not remove an old "
                    "encrypted draft.\n\n" + _safe_error(cleanup_error)
                )
            if handle:
                sublime.set_timeout_async(
                    lambda: _close_handle_best_effort(client, handle), 0
                )
            owner = view.window() if view.is_valid() else None
            if owner is not None:
                owner.focus_view(view)
                _registry.grant_bypass(owner.id(), "close_file")
                owner.run_command("close_file")
            _warn_if_not_synced("delete", (durability,))
            window.status_message("Inex: encrypted document deleted")
        except Exception as error:
            _show_error(error)

    def failed(error: Exception) -> None:
        current, _vault_now, current_generation = _runtime_snapshot()
        if (
            current is client
            and current_generation == generation
            and _registry.get(document.view_id) is document
            and view.is_valid()
            and not document.read_only
        ):
            view.set_read_only(False)
            _show_error(error)

    window.show_quick_panel(
        choices, selected, placeholder="Confirm encrypted document deletion"
    )


class InexReplaceEntireBufferCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit, token: str) -> None:
        if (
            not self.view.is_scratch()
            or self.view.file_name() is not None
            or self.view.settings().get(VIEW_PLAINTEXT_MARKER) is not True
        ):
            raise RuntimeError("Inex refused to insert into a non-scratch buffer")
        value = _handoffs.take(token)
        try:
            text = value.decode("utf-8", "strict")
            self.view.replace(edit, sublime.Region(0, self.view.size()), text)
        finally:
            wipe(value)


class InexScrubLockedBufferCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit) -> None:
        if self.view.settings().get(VIEW_PLAINTEXT_MARKER) is not True:
            raise RuntimeError("Inex refused to scrub an unmarked buffer")
        self.view.replace(
            edit, sublime.Region(0, self.view.size()), LOCKED_TEXT
        )
        _fixed_scrub_acks[self.view.id()] = "inex_scrub_locked_buffer"


class InexScrubBlockedBufferCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit) -> None:
        if self.view.settings().get(VIEW_PLAINTEXT_MARKER) is not True:
            raise RuntimeError("Inex refused to scrub an unmarked buffer")
        self.view.replace(
            edit, sublime.Region(0, self.view.size()), BLOCKED_TEXT
        )
        _fixed_scrub_acks[self.view.id()] = "inex_scrub_blocked_buffer"


class InexShowSecurityStatusCommand(sublime_plugin.ApplicationCommand):
    def run(self) -> None:
        issues = insecure_preferences()
        if issues:
            _show_security_block()
            return
        sublime.message_dialog(
            "Inex strict prerequisites match the Build 4200 baseline. "
            "The client remains experimental until the isolated-profile "
            "disk-residue matrix passes."
        )


class InexUnlockCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _begin_unlock(self.window)


class InexBrowseCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        client, _vault, _unused = _runtime_snapshot()
        if client is None or not client.has_session:
            _begin_unlock(self.window)
        else:
            _show_tree(self.window, "")


class InexLockCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _prompt_lock(self.window)


class InexUnlockUmbraCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _begin_umbra_unlock(self.window)


class InexLockUmbraCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _lock_umbra(self.window)


class InexEnterUmbraModeCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _enter_active_umbra(self.window)


class InexChoosePrivateAnnotationCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _apply_private_annotation_from_active_view(self.window)


class InexSearchCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        if insecure_preferences():
            _show_security_block(self.window)
            return
        client, _vault, generation = _runtime_snapshot()
        if client is None:
            _show_error(RpcLifecycleError("Inex vault is locked"))
            return

        def done(query: str) -> None:
            current, _vault_now, generation_now = _runtime_snapshot()
            if query and current is client and generation_now == generation:
                _search(self.window, query)

        # Search text is never put in settings or logs. Build 4200 has no
        # dedicated non-history search API; the exact release residue matrix
        # remains binding for this experimental feature.
        self.window.show_input_panel("Inex search", "", done, None, None)


class InexNewEncryptedMarkdownCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        session = _command_session(self.window)
        if session is None:
            return
        client, _vault_id, generation = session

        def done(logical_path: str) -> None:
            current, _vault_now, current_generation = _runtime_snapshot()
            if current is client and current_generation == generation:
                _create_markdown(self.window, logical_path)

        self.window.show_input_panel(
            "New encrypted Markdown path", "", done, None, None
        )


class InexNewFolderCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        session = _command_session(self.window)
        if session is None:
            return
        client, _vault_id, generation = session

        def done(logical_path: str) -> None:
            current, _vault_now, current_generation = _runtime_snapshot()
            if current is client and current_generation == generation:
                _create_folder(self.window, logical_path)

        self.window.show_input_panel(
            "New encrypted folder path", "", done, None, None
        )


class InexRenameActiveCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        context = _active_clean_context(self.window, "rename")
        if context is None:
            return
        _view, document, client, _vault_id, generation = context

        def done(destination: str) -> None:
            current, _vault_now, current_generation = _runtime_snapshot()
            if (
                current is client
                and current_generation == generation
                and _registry.get(document.view_id) is document
                and not document.dirty
            ):
                _rename_active(self.window, destination, document)

        self.window.show_input_panel(
            "Rename encrypted Markdown path",
            document.logical_path,
            done,
            None,
            None,
        )


class InexDeleteActiveCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _delete_active(self.window)


class InexShowHeadingsCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        try:
            document, client, generation, text = _navigation_snapshot(self.window)
            headings = markdown_headings(text)
        except Exception as error:
            _show_error(error)
            return
        if not headings:
            self.window.status_message("Inex: no Markdown headings")
            return
        choices = [
            [
                "%s %s" % ("#" * int(heading["level"]), heading["title"]),
                "Line %d" % (int(heading["line"]) + 1),
            ]
            for heading in headings
        ]

        def selected(index: int) -> None:
            current, _vault, current_generation = _runtime_snapshot()
            view = _view_by_id(document.view_id)
            if (
                index < 0
                or index >= len(headings)
                or current is not client
                or current_generation != generation
                or _registry.get(document.view_id) is not document
                or view is None
            ):
                return
            _select_heading(view, document, str(headings[index]["slug"]))

        self.window.show_quick_panel(
            choices, selected, placeholder="Inex Markdown headings"
        )


class InexFollowLinkCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        try:
            document, client, generation, text = _navigation_snapshot(self.window)
            links = markdown_links(text, document.logical_path)
        except Exception as error:
            _show_error(error)
            return
        if not links:
            self.window.status_message("Inex: no relative Markdown or wiki links")
            return
        choices = [
            [
                str(link["label"]),
                str(link["targetPath"])
                + (("#" + str(link["anchor"])) if link["anchor"] else ""),
            ]
            for link in links
        ]

        def selected(index: int) -> None:
            current, _vault, current_generation = _runtime_snapshot()
            if (
                index < 0
                or index >= len(links)
                or current is not client
                or current_generation != generation
                or _registry.get(document.view_id) is not document
            ):
                return
            link = links[index]
            _open_document(
                self.window,
                str(link["targetPath"]),
                None,
                str(link["anchor"]) if link["anchor"] else None,
            )

        self.window.show_quick_panel(
            choices, selected, placeholder="Inex relative Markdown links"
        )


class InexSaveCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit) -> None:
        document = _registry.get(self.view.id())
        if document is not None:
            _save_one(document)


class InexCloseManagedTextCommand(sublime_plugin.TextCommand):
    def run(
        self,
        edit: sublime.Edit,
        original_command: str,
        original_args: Optional[Dict[str, Any]] = None,
    ) -> None:
        window = self.view.window()
        if window is None:
            return
        _prepare_close(self.view)
        window.run_command(original_command, original_args or {})


class InexSaveActiveCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        view = self.window.active_view()
        document = _registry.get(view.id()) if view is not None else None
        if document is not None:
            _save_one(document)


class InexSaveAllCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _save_many(
            self.window,
            _window_managed_documents(self.window),
            save_regular=True,
        )


class InexBlockPlaintextSaveCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit, operation: str = "operation") -> None:
        sublime.message_dialog(
            "Inex blocked %s because a managed buffer must never acquire a plaintext filename."
            % operation
        )


class InexBlockPlaintextSaveWindowCommand(sublime_plugin.WindowCommand):
    def run(self, operation: str = "operation") -> None:
        sublime.message_dialog(
            "Inex blocked %s because a managed buffer must never acquire a plaintext filename."
            % operation
        )


class InexBlockPlaintextDisclosureCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit) -> None:
        sublime.message_dialog(
            "Inex blocked an operation that could export managed plaintext outside the encrypted vault."
        )


class InexBlockPlaintextDisclosureWindowCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        sublime.message_dialog(
            "Inex blocked an operation that could export managed plaintext outside the encrypted vault."
        )


class InexBlockMacroCommand(sublime_plugin.TextCommand):
    def run(self, edit: sublime.Edit) -> None:
        sublime.message_dialog(
            "Inex blocked macro recording, playback, or persistence while managed plaintext exists."
        )


class InexBlockMacroWindowCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        sublime.message_dialog(
            "Inex blocked macro recording, playback, or persistence while managed plaintext exists."
        )


class InexMacroSanitizerCommand(sublime_plugin.TextCommand):
    """No-op command used only to overwrite Build 4200's current macro."""

    def run(self, edit: sublime.Edit) -> None:
        pass


class InexCloseActiveCommand(sublime_plugin.WindowCommand):
    def run(self) -> None:
        _close_managed_active(self.window)


class InexCloseManyCommand(sublime_plugin.WindowCommand):
    def run(self, original_command: str, original_args: Optional[Dict[str, Any]] = None) -> None:
        _close_many(self.window, original_command, original_args or {})


class InexCloseFilteredCommand(sublime_plugin.WindowCommand):
    def run(self, original_command: str, original_args: Optional[Dict[str, Any]] = None) -> None:
        _flush_then_close_filtered(
            self.window, original_command, original_args or {}
        )


class InexStrictEventListener(sublime_plugin.EventListener):
    def on_text_command(
        self, view: sublime.View, command_name: str, args: Optional[Dict[str, Any]]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        if command_name == "toggle_record_macro" and _macro_sanitize_bypass:
            return None
        macro_commands = {
            "toggle_record_macro",
            "save_macro",
            "run_macro",
            "run_macro_file",
        }
        if _macro_is_tainted() and command_name in macro_commands:
            return ("inex_block_macro", {})
        if _registry.values() and command_name in macro_commands:
            return ("inex_block_macro", {})
        managed = _registry.get(view.id()) is not None
        if managed:
            _detect_active_macro_recording(view.window())
            managed = _registry.get(view.id()) is not None
            if _macro_is_tainted() and command_name in macro_commands:
                return ("inex_block_macro", {})
        action = classify_text_command(managed, command_name)
        if action == "save":
            return ("inex_save", {})
        if action in ("block_save_as", "block_plaintext"):
            return (
                "inex_block_plaintext_save",
                {"operation": "Save As" if action == "block_save_as" else command_name},
            )
        if action == "block_disclosure":
            return ("inex_block_plaintext_disclosure", {})
        if action == "block_macro":
            return ("inex_block_macro", {})
        if action == "close_active":
            return (
                "inex_close_managed_text",
                {"original_command": command_name, "original_args": args or {}},
            )
        return None

    def on_window_command(
        self, window: sublime.Window, command_name: str, args: Optional[Dict[str, Any]]
    ) -> Optional[Tuple[str, Dict[str, Any]]]:
        if command_name == "toggle_record_macro" and _macro_sanitize_bypass:
            return None
        macro_commands = {
            "toggle_record_macro",
            "save_macro",
            "run_macro",
            "run_macro_file",
        }
        if _macro_is_tainted() and command_name in macro_commands:
            return ("inex_block_macro_window", {})
        if _registry.values() and command_name in macro_commands:
            return ("inex_block_macro_window", {})
        if _registry.consume_bypass(window.id(), command_name):
            return None
        documents = _window_managed_documents(window)
        if documents:
            _detect_active_macro_recording(window)
            documents = _window_managed_documents(window)
            if _macro_is_tainted() and command_name in macro_commands:
                return ("inex_block_macro_window", {})
        active = window.active_view()
        active_managed = active is not None and _registry.get(active.id()) is not None
        action = classify_window_command(bool(documents), active_managed, command_name)
        if action == "save":
            return ("inex_save_active", {})
        if action == "save_all":
            return ("inex_save_all", {})
        if action in ("block_save_as", "block_plaintext"):
            return (
                "inex_block_plaintext_save_window",
                {"operation": "Save As" if action == "block_save_as" else command_name},
            )
        if action == "block_disclosure":
            return ("inex_block_plaintext_disclosure_window", {})
        if action == "block_macro":
            return ("inex_block_macro_window", {})
        if action == "close_active":
            return ("inex_close_active", {})
        if action == "close_many":
            return (
                "inex_close_many",
                {"original_command": command_name, "original_args": args or {}},
            )
        if action == "close_filtered":
            return (
                "inex_close_filtered",
                {"original_command": command_name, "original_args": args or {}},
            )
        return None

    def on_post_text_command(
        self, view: sublime.View, command_name: str, args: Optional[Dict[str, Any]]
    ) -> None:
        if _registry.get(view.id()) is not None:
            _detect_active_macro_recording(view.window())

    def on_post_window_command(
        self, window: sublime.Window, command_name: str, args: Optional[Dict[str, Any]]
    ) -> None:
        if _window_managed_documents(window):
            _detect_active_macro_recording(window)

    def on_modified(self, view: sublime.View) -> None:
        if view.id() in _scrubbing_views:
            return
        document = _registry.get(view.id())
        if document is None:
            return
        if (
            insecure_preferences()
            or view.file_name() is not None
            or not view.is_scratch()
            or view.settings().get(VIEW_PLAINTEXT_MARKER) is not True
        ):
            _emergency_scrub_view(view, "strict gate or scratch invariant failed")
            return
        try:
            text = view.substr(sublime.Region(0, view.size()))
            generation = document.replace(bytearray(text.encode("utf-8")))
            _note_user_activity()
            _update_document_ui(document)
            _schedule_draft(document, generation)
        except Exception as error:
            document.lock()
            view.set_read_only(True)
            _update_document_ui(document)
            _show_error(error)

    def on_activated(self, view: sublime.View) -> None:
        document = _registry.get(view.id())
        if document is None:
            return
        if (
            insecure_preferences()
            or view.file_name() is not None
            or not view.is_scratch()
            or view.settings().get(VIEW_PLAINTEXT_MARKER) is not True
        ):
            _emergency_scrub_view(view, "strict gate or scratch invariant failed")
            return
        _note_user_activity()

    def on_selection_modified(self, view: sublime.View) -> None:
        if _registry.get(view.id()) is not None:
            _note_user_activity()

    def on_clone(self, view: sublime.View) -> None:
        for document in _registry.values():
            original = _view_by_id(document.view_id)
            if original is not None and original.buffer_id() == view.buffer_id():
                _perform_lock("Inex blocked an unmanaged clone of a plaintext buffer")
                return

    def on_pre_save(self, view: sublime.View) -> None:
        if _registry.get(view.id()) is None:
            return
        # Notifications cannot veto. Scrub before the native saver can read the
        # buffer, after making a synchronous best-effort encrypted draft.
        document = _registry.get(view.id())
        if document is not None:
            _flush_final_draft(document)
        _emergency_scrub_view(view, "unintercepted native save")

    def on_pre_close(self, view: sublime.View) -> None:
        if _registry.get(view.id()) is not None:
            _prepare_close(view)

    def on_close(self, view: sublime.View) -> None:
        document = _registry.remove(view.id())
        if document is not None:
            document.close()
