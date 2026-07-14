"""Pure security/model helpers for the experimental Sublime client."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import threading
import unicodedata
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

try:
    from .inex_rpc import (
        MAX_DOCUMENT_BYTES,
        MAX_DRAFT_BYTES,
        RpcLifecycleError,
        RpcProtocolError,
        RpcRemoteError,
        wipe,
    )
except ImportError:  # Direct pure-Python test execution.
    from inex_rpc import (
        MAX_DOCUMENT_BYTES,
        MAX_DRAFT_BYTES,
        RpcLifecycleError,
        RpcProtocolError,
        RpcRemoteError,
        wipe,
    )


SECURITY_REQUIRED = {
    "hot_exit": "disabled",
    "hot_exit_projects": False,
    "remember_open_files": False,
    "update_system_recent_files": False,
}

SAVE_COMMANDS = frozenset(("save",))
SAVE_AS_COMMANDS = frozenset(("save_as", "prompt_save_as"))
PLAINTEXT_BROADENING_COMMANDS = frozenset(("clone_file",))
PLAINTEXT_DISCLOSURE_COMMANDS = frozenset(
    (
        "html_print",
        "print",
        "print_selection",
        "export",
        "export_html",
        "save_selection_as",
        "copy_as_html",
        "copy",
        "cut",
        "open_in_browser",
        "view_in_browser",
        "browser_preview",
        "open_context_url",
        "old_open_context_url",
    )
)
MACRO_CONTROL_COMMANDS = frozenset(
    ("toggle_record_macro", "save_macro", "run_macro", "run_macro_file")
)
SAVE_ALL_COMMANDS = frozenset(("save_all",))
CLOSE_ACTIVE_COMMANDS = frozenset(("close_file", "close"))
CLOSE_MANY_COMMANDS = frozenset(
    ("close_all", "close_all_files", "close_window", "exit")
)
CLOSE_FILTERED_COMMANDS = frozenset(
    (
        "close_by_index",
        "close_others_by_index",
        "close_selected",
        "close_unselected",
        "close_to_right_by_index",
        "close_unmodified",
        "close_unmodified_to_right_by_index",
        "close_deleted_files",
        "close_transient",
        "close_workspace",
        "close_pane",
    )
)

_ETAG_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_DRAFT_NAME_RE = re.compile(r"^[0-9a-f]{64}\.edry$")
_DOS_DEVICE_RE = re.compile(r"^(?:COM|LPT)(?:[1-9]|[\u00b9\u00b2\u00b3])$", re.IGNORECASE)


class SecurityGateError(Exception):
    pass


class ModelError(Exception):
    pass


class DraftStorageError(Exception):
    pass


class IdleDeadline:
    def __init__(self, idle_timeout_ms: int, now: float) -> None:
        if (
            isinstance(idle_timeout_ms, bool)
            or not isinstance(idle_timeout_ms, int)
            or idle_timeout_ms < 1000
            or idle_timeout_ms > 60 * 60 * 1000
        ):
            raise ModelError("Session idle timeout is invalid")
        self.idle_timeout_ms = idle_timeout_ms
        self.warning_ms = min(60000, max(250, idle_timeout_ms // 5))
        self.safety_ms = min(250, idle_timeout_ms // 4)
        self.deadline = now + (idle_timeout_ms - self.safety_ms) / 1000.0
        self.revision = 1

    def renew(self, now: float) -> int:
        self.deadline = now + (
            self.idle_timeout_ms - self.safety_ms
        ) / 1000.0
        self.revision += 1
        return self.revision

    def state(self, now: float) -> str:
        remaining_ms = (self.deadline - now) * 1000.0
        if remaining_ms <= 0:
            return "expired"
        if remaining_ms <= self.warning_ms:
            return "warning"
        return "active"

    def delay_to_warning_ms(self, now: float) -> int:
        value = (self.deadline - now) * 1000.0 - self.warning_ms
        return max(0, int(value))

    def delay_to_expiry_ms(self, now: float) -> int:
        return max(0, int((self.deadline - now) * 1000.0))


class PlaintextHandoffRegistry:
    def __init__(self) -> None:
        self._values: Dict[str, bytearray] = {}
        self._lock = threading.Lock()

    def put(self, value: bytearray) -> str:
        if not isinstance(value, bytearray) or len(value) > MAX_DOCUMENT_BYTES:
            if isinstance(value, bytearray):
                wipe(value)
            raise ModelError("Plaintext handoff is invalid")
        token = secrets.token_urlsafe(32)
        with self._lock:
            while token in self._values:
                token = secrets.token_urlsafe(32)
            self._values[token] = value
        return token

    def take(self, token: str) -> bytearray:
        with self._lock:
            value = self._values.pop(token, None)
        if value is None:
            raise ModelError("Plaintext handoff is missing or already consumed")
        return value

    def discard(self, token: str) -> None:
        with self._lock:
            value = self._values.pop(token, None)
        if value is not None:
            wipe(value)

    def clear(self) -> None:
        with self._lock:
            values = list(self._values.values())
            self._values.clear()
        for value in values:
            wipe(value)

    def __len__(self) -> int:
        with self._lock:
            return len(self._values)


class PendingPlaintextOwner:
    def __init__(
        self, token: str, handle: str, context: Any, buffers: List[bytearray]
    ) -> None:
        self.token = token
        self.handle = handle
        self.context = context
        self.buffers = buffers

    def wipe(self) -> None:
        for value in self.buffers:
            wipe(value)
        self.buffers = []


class PendingPlaintextRegistry:
    def __init__(self) -> None:
        self._owners: Dict[str, PendingPlaintextOwner] = {}
        self._lock = threading.Lock()

    def add(self, handle: str, context: Any, value: bytearray) -> str:
        if not isinstance(value, bytearray) or len(value) > MAX_DOCUMENT_BYTES:
            if isinstance(value, bytearray):
                wipe(value)
            raise ModelError("Pending plaintext is invalid")
        token = secrets.token_urlsafe(32)
        with self._lock:
            while token in self._owners:
                token = secrets.token_urlsafe(32)
            self._owners[token] = PendingPlaintextOwner(
                token, handle, context, [value]
            )
        return token

    def add_buffer(self, token: str, value: bytearray) -> bool:
        with self._lock:
            owner = self._owners.get(token)
            if owner is not None:
                owner.buffers.append(value)
                return True
        wipe(value)
        return False

    def take(self, token: str) -> Optional[PendingPlaintextOwner]:
        with self._lock:
            return self._owners.pop(token, None)

    def drain(self) -> List[PendingPlaintextOwner]:
        with self._lock:
            owners = list(self._owners.values())
            self._owners.clear()
        return owners

    def __len__(self) -> int:
        with self._lock:
            return len(self._owners)


def safe_error_message(error: Exception) -> str:
    """Return only fixed/local validation messages, never arbitrary paths/data."""

    if isinstance(
        error,
        (
            RpcProtocolError,
            RpcLifecycleError,
            RpcRemoteError,
            SecurityGateError,
            ModelError,
            DraftStorageError,
        ),
    ):
        return str(error)
    return "Inex operation failed without exposing diagnostic details"


def session_epoch_is_current(captured: int, current: int, plugin_active: bool) -> bool:
    return (
        not isinstance(captured, bool)
        and isinstance(captured, int)
        and not isinstance(current, bool)
        and isinstance(current, int)
        and plugin_active is True
        and captured == current
    )


def session_owner_is_current(expected: Any, current: Any) -> bool:
    return expected is not None and expected is current


def macro_fingerprint(value: Any) -> str:
    try:
        serialized = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise ModelError("Sublime macro state is invalid")
    return hashlib.sha256(serialized).hexdigest()


def check_security_preferences(preferences: Mapping[str, Any]) -> List[str]:
    """Return exact application-global preference mismatches.

    ``False`` is checked by identity so integer 0 cannot accidentally satisfy
    the contract.
    """

    issues = []
    if preferences.get("hot_exit") != "disabled":
        issues.append('"hot_exit" must be exactly "disabled"')
    if preferences.get("hot_exit_projects") is not False:
        issues.append('"hot_exit_projects" must be exactly false')
    if preferences.get("remember_open_files") is not False:
        issues.append('"remember_open_files" must be exactly false')
    if preferences.get("update_system_recent_files") is not False:
        issues.append('"update_system_recent_files" must be exactly false')
    return issues


def validate_logical_path(value: str, allow_directory: bool = False) -> str:
    if not isinstance(value, str):
        raise ModelError("Logical path is invalid")
    if allow_directory and value == "":
        return value
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or len(value.encode("utf-8")) > 1024
    ):
        raise ModelError("Logical path is invalid")
    components = value.split("/")
    for index, component in enumerate(components):
        encoded = component.encode("utf-8")
        if (
            not component
            or component in (".", "..")
            or len(encoded) > 255
            or component.startswith(" ")
            or component.endswith((" ", "."))
            or any(unicodedata.category(character) == "Cc" for character in component)
            or any(character in '<>:"|?*' for character in component)
        ):
            raise ModelError("Logical path is invalid")
        lowered = component.lower()
        if lowered in (".git", ".vault-local"):
            raise ModelError("Logical path enters reserved storage")
        if index == 0 and lowered == "vault.json":
            raise ModelError("Logical path collides with vault metadata")
        basename = component.split(".", 1)[0].rstrip(" ")
        if basename.upper() in ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"):
            raise ModelError("Logical path is not portable")
        if _DOS_DEVICE_RE.fullmatch(basename) or re.search(r"~[0-9]$", basename):
            raise ModelError("Logical path is not portable")
    if not allow_directory:
        if not components[-1].endswith(".md") or len(components[-1].encode("utf-8")) > 251:
            raise ModelError("Logical document path is invalid")
    return value


def classify_text_command(managed: bool, command_name: str) -> Optional[str]:
    if not managed:
        return None
    if command_name in SAVE_COMMANDS:
        return "save"
    if command_name in SAVE_AS_COMMANDS:
        return "block_save_as"
    if command_name in PLAINTEXT_BROADENING_COMMANDS:
        return "block_plaintext"
    if command_name in PLAINTEXT_DISCLOSURE_COMMANDS:
        return "block_disclosure"
    if command_name in MACRO_CONTROL_COMMANDS:
        return "block_macro"
    if command_name in CLOSE_ACTIVE_COMMANDS:
        return "close_active"
    return None


def classify_window_command(
    has_managed: bool, active_managed: bool, command_name: str
) -> Optional[str]:
    if not has_managed:
        return None
    if command_name in SAVE_ALL_COMMANDS:
        return "save_all"
    if active_managed and command_name in SAVE_COMMANDS:
        return "save"
    if active_managed and command_name in SAVE_AS_COMMANDS:
        return "block_save_as"
    if active_managed and command_name in PLAINTEXT_BROADENING_COMMANDS:
        return "block_plaintext"
    if active_managed and command_name in PLAINTEXT_DISCLOSURE_COMMANDS:
        return "block_disclosure"
    if command_name == "run_macro_file":
        return "block_macro"
    if active_managed and command_name in MACRO_CONTROL_COMMANDS:
        return "block_macro"
    if active_managed and command_name in CLOSE_ACTIVE_COMMANDS:
        return "close_active"
    if command_name in CLOSE_MANY_COMMANDS:
        return "close_many"
    if command_name in CLOSE_FILTERED_COMMANDS:
        return "close_filtered"
    return None


class ManagedDocument:
    """Plugin-owned document state; no value from here enters view settings."""

    def __init__(
        self,
        view_id: int,
        logical_path: str,
        handle: str,
        etag: str,
        content: bytearray,
        umbra_render_map: Optional[Dict[str, Any]] = None,
        recovered: bool = False,
        stale_recovery: bool = False,
        recovery_base_etag: Optional[str] = None,
    ) -> None:
        if isinstance(view_id, bool) or not isinstance(view_id, int) or view_id <= 0:
            raise ModelError("View id is invalid")
        self.view_id = view_id
        self.logical_path = validate_logical_path(logical_path)
        if not isinstance(handle, str) or len(handle.encode("utf-8")) > 4096:
            raise ModelError("Document handle is invalid")
        if umbra_render_map is None and not handle:
            raise ModelError("Document handle is invalid")
        if umbra_render_map is not None and handle:
            raise ModelError("Umbra document must not have a normal handle")
        if not isinstance(etag, str) or not _ETAG_RE.fullmatch(etag):
            raise ModelError("Document etag is invalid")
        if not isinstance(content, bytearray) or len(content) > MAX_DOCUMENT_BYTES:
            raise ModelError("Document content exceeds the client limit")
        self.handle = handle
        self.umbra_render_map = umbra_render_map
        self.etag = etag
        if recovery_base_etag is not None and not _ETAG_RE.fullmatch(recovery_base_etag):
            raise ModelError("Recovery base etag is invalid")
        self.draft_base_etag = recovery_base_etag if recovered else etag
        self.content = content
        self.version = 1 if recovered else 0
        self.saved_version = 0
        self.draft_version = self.version if recovered else -1
        self.requires_overwrite_confirmation = stale_recovery
        self.read_only = False
        self.closed = False
        self.debounce_generation = 0
        self.draft_epoch = 0
        self.draft_lock = threading.Lock()

    @property
    def dirty(self) -> bool:
        return self.version != self.saved_version

    @property
    def is_umbra(self) -> bool:
        return self.umbra_render_map is not None

    def replace(self, content: bytearray) -> int:
        if self.closed or self.read_only:
            wipe(content)
            raise ModelError("Document is not writable")
        if len(content) > MAX_DOCUMENT_BYTES:
            wipe(content)
            self.read_only = True
            raise ModelError("Document content exceeds the client limit")
        old = self.content
        self.content = content
        wipe(old)
        self.version += 1
        self.debounce_generation += 1
        return self.debounce_generation

    def snapshot(self) -> Tuple[int, bytearray]:
        if self.closed:
            raise ModelError("Document is closed")
        return self.version, bytearray(self.content)

    def mark_saved(self, version: int, etag: str) -> None:
        if not _ETAG_RE.fullmatch(etag):
            raise ModelError("Document etag is invalid")
        self.etag = etag
        self.draft_base_etag = etag
        if version == self.version:
            self.saved_version = version
            self.requires_overwrite_confirmation = False

    def replace_umbra_projection(
        self, content: bytearray, etag: str, render_map: Dict[str, Any]
    ) -> None:
        if not self.is_umbra or self.closed or self.read_only:
            wipe(content)
            raise ModelError("Document is not an active Umbra projection")
        if not isinstance(content, bytearray) or len(content) > MAX_DOCUMENT_BYTES:
            wipe(content)
            raise ModelError("Umbra projection exceeds the client limit")
        if not isinstance(etag, str) or not _ETAG_RE.fullmatch(etag) or not isinstance(render_map, dict):
            wipe(content)
            raise ModelError("Umbra projection identity is invalid")
        old = self.content
        self.content = content
        wipe(old)
        self.etag = etag
        self.draft_base_etag = etag
        self.umbra_render_map = render_map
        self.version += 1
        self.saved_version = self.version
        self.draft_version = self.version
        self.requires_overwrite_confirmation = False

    def mark_drafted(self, version: int) -> None:
        if version <= self.version:
            self.draft_version = max(self.draft_version, version)

    def invalidate_drafts(self) -> int:
        if self.closed:
            raise ModelError("Document is closed")
        self.debounce_generation += 1
        self.draft_epoch += 1
        return self.draft_epoch

    def draft_snapshot_is_current(self, version: int, draft_epoch: int) -> bool:
        return (
            not self.closed
            and self.version == version
            and self.draft_epoch == draft_epoch
        )

    def rename_clean(self, logical_path: str, etag: str) -> str:
        if self.closed or self.dirty:
            raise ModelError("Only a clean open document can be renamed")
        destination = validate_logical_path(logical_path)
        if not isinstance(etag, str) or not _ETAG_RE.fullmatch(etag):
            raise ModelError("Document etag is invalid")
        source = self.logical_path
        self.logical_path = destination
        self.etag = etag
        self.draft_base_etag = etag
        self.draft_epoch += 1
        self.requires_overwrite_confirmation = False
        return source

    def lock(self) -> None:
        self.read_only = True

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        self.read_only = True
        self.draft_epoch += 1
        wipe(self.content)
        self.content = bytearray()
        # Handles/session tokens are immutable Python strings and cannot be
        # zeroized, but dropping the references is still useful.
        self.handle = ""
        self.umbra_render_map = None


class DocumentRegistry:
    def __init__(self) -> None:
        self._documents: Dict[int, ManagedDocument] = {}
        self._bypass: Dict[Tuple[int, str], int] = {}

    def add(self, document: ManagedDocument) -> None:
        if document.view_id in self._documents:
            raise ModelError("View is already managed")
        self._documents[document.view_id] = document

    def get(self, view_id: int) -> Optional[ManagedDocument]:
        return self._documents.get(view_id)

    def remove(self, view_id: int) -> Optional[ManagedDocument]:
        return self._documents.pop(view_id, None)

    def values(self) -> List[ManagedDocument]:
        return list(self._documents.values())

    def any_for_views(self, view_ids: Iterable[int]) -> bool:
        return any(view_id in self._documents for view_id in view_ids)

    def grant_bypass(self, owner_id: int, command_name: str) -> None:
        key = (owner_id, command_name)
        self._bypass[key] = self._bypass.get(key, 0) + 1

    def consume_bypass(self, owner_id: int, command_name: str) -> bool:
        key = (owner_id, command_name)
        count = self._bypass.get(key, 0)
        if count <= 0:
            return False
        if count == 1:
            self._bypass.pop(key, None)
        else:
            self._bypass[key] = count - 1
        return True

    def clear(self) -> None:
        for document in self._documents.values():
            document.close()
        self._documents.clear()
        self._bypass.clear()


def scrub_then_remove(
    registry: DocumentRegistry, view_id: int, scrub: Callable[[], None]
) -> Optional[str]:
    """Scrub a possibly surviving view before dropping its in-memory owner."""

    document = registry.get(view_id)
    if document is None:
        return None
    handle = document.handle
    scrub()
    removed = registry.remove(view_id)
    if removed is not document:
        raise ModelError("Managed document changed during scrub")
    document.close()
    return handle


def draft_filename(vault_id: str, logical_path: str) -> str:
    validate_logical_path(logical_path)
    material = (vault_id + "\x00" + logical_path).encode("utf-8")
    return hashlib.sha256(material).hexdigest() + ".edry"


def _metadata_is_link(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    file_attributes = getattr(metadata, "st_file_attributes", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(file_attributes & reparse_flag)


def atomic_write_ciphertext(directory: str, filename: str, envelope: bytearray) -> str:
    """Atomically persist one bounded EDRY envelope and never plaintext."""

    if not os.path.isabs(directory) or not _DRAFT_NAME_RE.fullmatch(filename):
        raise DraftStorageError("Encrypted draft destination is invalid")
    if (
        not isinstance(envelope, bytearray)
        or len(envelope) > MAX_DRAFT_BYTES
        or not envelope.startswith(b"EDRY")
    ):
        raise DraftStorageError("Encrypted draft envelope is invalid")
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        metadata = os.lstat(directory)
    except OSError:
        raise DraftStorageError("Encrypted draft directory is unavailable")
    if _metadata_is_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
        raise DraftStorageError("Encrypted draft directory is unsafe")
    destination = os.path.join(directory, filename)
    temporary = os.path.join(
        directory, ".%s.tmp-%s" % (filename, secrets.token_hex(12))
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(temporary, flags, 0o600)
        offset = 0
        while offset < len(envelope):
            written = os.write(descriptor, envelope[offset:])
            if written <= 0:
                raise OSError("short encrypted draft write")
            offset += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, destination)
        try:
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            # Windows and some filesystems cannot fsync directories. The file
            # itself was synced and replace remains atomic on supported hosts.
            pass
        result_metadata = os.lstat(destination)
        if _metadata_is_link(result_metadata) or not stat.S_ISREG(
            result_metadata.st_mode
        ):
            raise DraftStorageError("Encrypted draft destination is unsafe")
        return destination
    except DraftStorageError:
        raise
    except OSError:
        raise DraftStorageError("Encrypted draft write failed")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            os.unlink(temporary)
        except OSError:
            pass


def read_encrypted_draft(directory: str, filename: str) -> Optional[bytearray]:
    """Read one bounded regular EDRY file without following the final symlink."""

    if not os.path.isabs(directory) or not _DRAFT_NAME_RE.fullmatch(filename):
        raise DraftStorageError("Encrypted draft source is invalid")
    path = os.path.join(directory, filename)
    try:
        directory_metadata = os.lstat(directory)
    except FileNotFoundError:
        return None
    except OSError:
        raise DraftStorageError("Encrypted draft directory is unavailable")
    if _metadata_is_link(directory_metadata) or not stat.S_ISDIR(
        directory_metadata.st_mode
    ):
        raise DraftStorageError("Encrypted draft directory is unsafe")
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError:
        raise DraftStorageError("Encrypted draft is unavailable")
    if (
        _metadata_is_link(metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size < 4
        or metadata.st_size > MAX_DRAFT_BYTES
    ):
        raise DraftStorageError("Encrypted draft is unsafe or invalid")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    content = bytearray()
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_size != metadata.st_size
            or (hasattr(metadata, "st_ino") and opened.st_ino != metadata.st_ino)
        ):
            raise DraftStorageError("Encrypted draft changed while opening")
        remaining = metadata.st_size
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise DraftStorageError("Encrypted draft is truncated")
            content.extend(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise DraftStorageError("Encrypted draft exceeds its byte limit")
        if not content.startswith(b"EDRY"):
            raise DraftStorageError("Encrypted draft envelope is invalid")
        return content
    except DraftStorageError:
        wipe(content)
        raise
    except OSError:
        wipe(content)
        raise DraftStorageError("Encrypted draft read failed")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def remove_encrypted_draft(directory: str, filename: str) -> bool:
    """Delete only a verified regular ciphertext draft; never follow links."""

    if not os.path.isabs(directory) or not _DRAFT_NAME_RE.fullmatch(filename):
        raise DraftStorageError("Encrypted draft destination is invalid")
    try:
        directory_metadata = os.lstat(directory)
    except FileNotFoundError:
        return False
    except OSError:
        raise DraftStorageError("Encrypted draft directory is unavailable")
    if (
        _metadata_is_link(directory_metadata)
        or not stat.S_ISDIR(directory_metadata.st_mode)
    ):
        raise DraftStorageError("Encrypted draft directory is unsafe")

    anchored = (
        os.stat in os.supports_dir_fd
        and os.stat in os.supports_follow_symlinks
        and os.unlink in os.supports_dir_fd
    )
    if anchored:
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = None
        try:
            descriptor = os.open(directory, flags)
            opened_directory = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(opened_directory.st_mode)
                or opened_directory.st_dev != directory_metadata.st_dev
                or opened_directory.st_ino != directory_metadata.st_ino
            ):
                raise DraftStorageError("Encrypted draft directory changed while opening")
            try:
                metadata = os.stat(filename, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return False
            if _metadata_is_link(metadata) or not stat.S_ISREG(metadata.st_mode):
                raise DraftStorageError("Encrypted draft destination is unsafe")
            os.unlink(filename, dir_fd=descriptor)
            try:
                os.fsync(descriptor)
            except OSError:
                pass
            return True
        except DraftStorageError:
            raise
        except OSError:
            raise DraftStorageError("Encrypted draft delete failed")
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    # Windows does not expose Python dir_fd operations. Recheck the exact
    # directory identity immediately before unlinking so ordinary symlink or
    # junction replacement fails closed within the available API boundary.
    path = os.path.join(directory, filename)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        raise DraftStorageError("Encrypted draft is unavailable")
    if _metadata_is_link(metadata) or not stat.S_ISREG(metadata.st_mode):
        raise DraftStorageError("Encrypted draft destination is unsafe")
    try:
        current_directory = os.lstat(directory)
        if (
            _metadata_is_link(current_directory)
            or not stat.S_ISDIR(current_directory.st_mode)
            or current_directory.st_dev != directory_metadata.st_dev
            or current_directory.st_ino != directory_metadata.st_ino
        ):
            raise DraftStorageError("Encrypted draft directory changed before delete")
        os.unlink(path)
        try:
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            pass
        return True
    except DraftStorageError:
        raise
    except OSError:
        raise DraftStorageError("Encrypted draft delete failed")
