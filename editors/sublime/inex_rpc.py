"""Strict Content-Length JSON-RPC client used by the Sublime package.

This module deliberately has no Sublime API imports so its framing and process
lifecycle can be tested with the host Python.  It only uses Python 3.8 syntax.
"""

from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple


MAX_FRAME_BYTES = 24 * 1024 * 1024
MAX_HEADER_BYTES = 8 * 1024
MAX_PENDING_CALLS = 128
MAX_OUTSTANDING_FRAME_BYTES = MAX_FRAME_BYTES + 64 * 1024
MAX_STDERR_BYTES = 64 * 1024
MAX_PIPE_READ_BYTES = 64 * 1024
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_DRAFT_BYTES = MAX_DOCUMENT_BYTES + 12 + 4096 + 16
MAX_UMBRA_MAP_ENTRIES = 100000
SESSION_TOKEN_TEXT_BYTES = 43
DOCUMENT_HANDLE_TEXT_BYTES = 22
REQUEST_TIMEOUT_SECONDS = 120.0
PROTOCOL_MAJOR = 1
SESSION_RENEWING_METHODS = frozenset(
    (
        "system.ping",
        "vault.status",
        "vault.listTree",
        "file.stat",
        "file.read",
        "file.write",
        "file.mkdir",
        "file.rename",
        "file.delete",
        "document.open",
        "document.close",
        "draft.encrypt",
        "draft.decrypt",
        "search.query",
        "cache.evict",
        "umbra.status",
        "umbra.config.get",
    )
)


class RpcProtocolError(Exception):
    """The child violated the frozen v1 framing or response contract."""


class RpcLifecycleError(Exception):
    """The child is unavailable or a bounded local operation failed."""


class RpcRemoteError(Exception):
    """A validated, display-safe application error from inexd."""

    def __init__(self, code: int, stable_name: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.stable_name = stable_name


ERROR_CONTRACT = {
    -32700: ("PARSE_ERROR", "Parse error"),
    -32600: ("INVALID_REQUEST", "Invalid Request"),
    -32601: ("METHOD_NOT_FOUND", "Method not found"),
    -32602: ("INVALID_PARAMS", "Invalid params"),
    -32603: ("INTERNAL_ERROR", "Internal error"),
    -32000: ("AUTH_FAILED", "Authentication failed"),
    -32001: ("SESSION_INVALID", "Session is invalid or expired"),
    -32002: ("VAULT_INVALID", "Vault configuration is invalid"),
    -32003: ("PATH_INVALID", "Logical path is invalid"),
    -32004: ("NOT_FOUND", "Logical entry was not found"),
    -32005: ("ALREADY_EXISTS", "Logical entry already exists"),
    -32006: ("ETAG_CONFLICT", "Ciphertext etag conflict"),
    -32007: ("INTEGRITY_FAILED", "Encrypted document integrity check failed"),
    -32008: ("LIMIT_EXCEEDED", "Request exceeds the configured limit"),
    -32009: ("IO_FAILED", "Storage operation failed"),
    -32010: ("KDF_POLICY", "KDF parameters violate policy"),
    -32011: ("UNSUPPORTED", "Feature is unsupported"),
    -32012: ("BUSY", "Vault mutation is busy"),
}

_CONTENT_LENGTH_RE = re.compile(
    br"^[ \t]*content-length[ \t]*:[ \t]*([0-9]+)[ \t]*$", re.IGNORECASE
)
_ETAG_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_CAPABILITY_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


def _read_pipe_once(stream: Any) -> bytes:
    """Return at most one available pipe chunk without waiting to fill it."""

    while True:
        try:
            read_once = getattr(stream, "read1", None)
            if read_once is not None:
                if not callable(read_once):
                    raise RpcLifecycleError("Inex sidecar pipe reader is invalid")
                chunk = read_once(MAX_PIPE_READ_BYTES)
            else:
                descriptor = stream.fileno()
                if isinstance(descriptor, bool) or not isinstance(descriptor, int):
                    raise RpcLifecycleError("Inex sidecar pipe descriptor is invalid")
                chunk = os.read(descriptor, MAX_PIPE_READ_BYTES)
        except InterruptedError:
            continue
        if not isinstance(chunk, bytes) or len(chunk) > MAX_PIPE_READ_BYTES:
            raise RpcLifecycleError("Inex sidecar pipe returned an invalid chunk")
        return chunk


def _valid_id(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return -(2**53 - 1) <= value <= 2**53 - 1
    return isinstance(value, str) and len(value.encode("utf-8")) <= 4096


def _is_json_value(value: Any) -> bool:
    pending = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if depth > 64 or visited > 100000:
            return False
        if item is None or isinstance(item, bool):
            continue
        if isinstance(item, str):
            try:
                item.encode("utf-8")
            except UnicodeError:
                return False
            continue
        if isinstance(item, int) and not isinstance(item, bool):
            if -(2**53 - 1) <= item <= 2**53 - 1:
                continue
            return False
        if isinstance(item, float):
            # JSON numbers reaching Python may be non-finite unless rejected.
            if item == item and item not in (float("inf"), float("-inf")):
                continue
            return False
        if isinstance(item, list):
            for child in item:
                pending.append((child, depth + 1))
            continue
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            for child in item.values():
                pending.append((child, depth + 1))
            continue
        return False
    return True


def encode_request(request_id: Any, method: str, params: Dict[str, Any]) -> bytearray:
    """Encode one request while enforcing the same bound as the daemon."""

    if not _valid_id(request_id) or not isinstance(method, str) or not method:
        raise RpcProtocolError("RPC request id or method is invalid")
    if not isinstance(params, dict) or not _is_json_value(params):
        raise RpcProtocolError("RPC request params are invalid")
    try:
        body = json.dumps(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise RpcProtocolError("RPC request serialization failed")
    if len(body) > MAX_FRAME_BYTES:
        raise RpcProtocolError("RPC request exceeds its byte limit")
    header = ("Content-Length: %d\r\n\r\n" % len(body)).encode("ascii")
    return bytearray(header + body)


def _parse_content_length(header: bytes) -> int:
    if any(byte > 0x7F for byte in header):
        raise RpcProtocolError("RPC response header is not ASCII")
    if b"\r\n" in header:
        raise RpcProtocolError("RPC response has unsupported headers")
    match = _CONTENT_LENGTH_RE.fullmatch(header)
    if match is None or len(match.group(1)) > 20:
        raise RpcProtocolError("RPC response Content-Length is invalid")
    value = int(match.group(1))
    if value > MAX_FRAME_BYTES:
        raise RpcProtocolError("RPC response exceeds its byte limit")
    return value


def _parse_response(body: bytes) -> Dict[str, Any]:
    def unique_object(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    try:
        text = body.decode("utf-8", "strict")
        value = json.loads(
            text,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            object_pairs_hook=unique_object,
        )
    except (UnicodeError, ValueError, json.JSONDecodeError, RecursionError):
        raise RpcProtocolError("RPC response body is not valid UTF-8 JSON")
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise RpcProtocolError("RPC response envelope is invalid")
    has_result = "result" in value
    has_error = "error" in value
    if len(value) != 3 or has_result == has_error:
        raise RpcProtocolError("RPC response envelope is invalid")
    if has_result:
        if not _valid_id(value.get("id")) or not _is_json_value(value["result"]):
            raise RpcProtocolError("RPC success response is invalid")
        return value
    if value.get("id") is not None and not _valid_id(value.get("id")):
        raise RpcProtocolError("RPC error response id is invalid")
    error = value.get("error")
    if not isinstance(error, dict) or set(error) != {"code", "message", "data"}:
        raise RpcProtocolError("RPC error response is invalid")
    code = error.get("code")
    data = error.get("data")
    if (
        isinstance(code, bool)
        or not isinstance(code, int)
        or not isinstance(error.get("message"), str)
        or not isinstance(data, dict)
        or not isinstance(data.get("name"), str)
        or not _is_json_value(data)
    ):
        raise RpcProtocolError("RPC error response is invalid")
    return value


class FrameDecoder:
    """Incremental, strict, bounded Content-Length response decoder."""

    def __init__(self) -> None:
        self._pending = bytearray()
        self._expected: Optional[int] = None

    def feed(self, chunk: bytes) -> List[Dict[str, Any]]:
        if not chunk:
            return []
        self._pending.extend(chunk)
        responses = []
        while True:
            if self._expected is None:
                boundary = self._pending.find(b"\r\n\r\n")
                if boundary < 0:
                    if len(self._pending) > MAX_HEADER_BYTES:
                        self._fail("RPC response header exceeds its byte limit")
                    break
                if boundary + 4 > MAX_HEADER_BYTES:
                    self._fail("RPC response header exceeds its byte limit")
                header = bytes(self._pending[:boundary])
                try:
                    self._expected = _parse_content_length(header)
                except Exception:
                    self.clear()
                    raise
                self._wipe_prefix(boundary + 4)
            expected = self._expected
            if expected is None or len(self._pending) < expected:
                break
            body = bytes(self._pending[:expected])
            self._wipe_prefix(expected)
            self._expected = None
            responses.append(_parse_response(body))
        return responses

    def finish(self) -> None:
        if self._pending or self._expected is not None:
            self._fail("RPC response stream ended in a partial frame")

    def clear(self) -> None:
        for index in range(len(self._pending)):
            self._pending[index] = 0
        self._pending.clear()
        self._expected = None

    def _wipe_prefix(self, count: int) -> None:
        for index in range(count):
            self._pending[index] = 0
        del self._pending[:count]

    def _fail(self, message: str) -> None:
        self.clear()
        raise RpcProtocolError(message)


def response_result(response: Dict[str, Any]) -> Any:
    if "error" not in response:
        return response["result"]
    error = response["error"]
    contract = ERROR_CONTRACT.get(error["code"])
    if (
        contract is None
        or contract[0] != error["data"].get("name")
        or contract[1] != error["message"]
    ):
        raise RpcProtocolError("RPC error contract is invalid")
    raise RpcRemoteError(error["code"], contract[0], contract[1])


def resolve_sidecar(configured_path: str, package_dir: str, platform: str) -> str:
    """Resolve only an explicit absolute or package-owned regular executable."""

    filename = "inexd.exe" if platform == "windows" else "inexd"
    candidate = configured_path if isinstance(configured_path, str) else ""
    if candidate != candidate.strip():
        raise RpcLifecycleError("Inex sidecar path contains unsafe edge whitespace")
    if not candidate:
        candidate = os.path.join(package_dir, "bin", filename)
    if not os.path.isabs(candidate):
        raise RpcLifecycleError("Inex sidecar path must be absolute")
    candidate = os.path.normpath(candidate)
    try:
        metadata = os.lstat(candidate)
    except OSError:
        raise RpcLifecycleError("Inex sidecar executable is unavailable")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise RpcLifecycleError("Inex sidecar must be a regular file")
    if platform != "windows" and metadata.st_mode & 0o111 == 0:
        raise RpcLifecycleError("Inex sidecar is not executable")
    return candidate


class _Pending:
    def __init__(self, method: str) -> None:
        self.method = method
        self.event = threading.Event()
        self.response: Optional[Dict[str, Any]] = None
        self.error: Optional[Exception] = None


class InexRpcClient:
    """One-child, one-vault synchronous facade with background frame reads."""

    REQUIRED_CAPABILITIES = {
        "vault",
        "files",
        "documents",
        "encryptedDrafts",
        "search",
        "authenticatedPing",
    }

    def __init__(
        self,
        executable: str,
        on_session_lost: Optional[Callable[[Exception], None]] = None,
        on_session_activity: Optional[Callable[[], None]] = None,
        timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self.executable = executable
        self.on_session_lost = on_session_lost
        self.on_session_activity = on_session_activity
        self.timeout_seconds = timeout_seconds
        self._process: Optional[subprocess.Popen] = None
        self._decoder = FrameDecoder()
        self._pending: Dict[int, _Pending] = {}
        self._pending_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._next_id = 1
        self._terminal_error: Optional[Exception] = None
        self._session: Optional[str] = None
        self._outstanding_bytes = 0
        self._stderr_bytes = 0

    @property
    def has_session(self) -> bool:
        with self._state_lock:
            return self._session is not None

    def start(self, client_version: str) -> Dict[str, Any]:
        if self._process is not None:
            raise RpcLifecycleError("Inex sidecar is already started")
        process_options = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
            "close_fds": True,
        }
        if os.name == "nt":
            process_options["creationflags"] = subprocess.CREATE_NO_WINDOW
        try:
            process = subprocess.Popen(
                [self.executable],
                **process_options,
            )
        except OSError:
            raise RpcLifecycleError("Inex sidecar process failed to start")
        self._process = process
        threading.Thread(target=self._read_stdout, name="inex-rpc-stdout", daemon=True).start()
        threading.Thread(target=self._drain_stderr, name="inex-rpc-stderr", daemon=True).start()
        threading.Thread(target=self._watch_process, name="inex-rpc-watch", daemon=True).start()
        result = _expect_object(
            self._call_raw(
                "system.hello",
                {
                    "client": "sublime",
                    "clientVersion": client_version,
                    "protocolMajor": PROTOCOL_MAJOR,
                },
            ),
            "hello result",
        )
        if (
            set(result) != {"server", "serverVersion", "protocolMajor", "capabilities"}
            or
            result.get("server") != "inexd"
            or result.get("protocolMajor") != PROTOCOL_MAJOR
            or not isinstance(result.get("serverVersion"), str)
        ):
            self._fail_terminal(RpcProtocolError("Inex sidecar negotiation failed"))
            raise RpcProtocolError("Inex sidecar negotiation failed")
        capabilities = result.get("capabilities")
        if (
            not isinstance(capabilities, list)
            or any(not isinstance(value, str) or not _CAPABILITY_RE.fullmatch(value) for value in capabilities)
            or len(capabilities) != len(set(capabilities))
            or not self.REQUIRED_CAPABILITIES.issubset(set(capabilities))
        ):
            self._fail_terminal(RpcProtocolError("Inex sidecar capability negotiation failed"))
            raise RpcProtocolError("Inex sidecar capability negotiation failed")
        return result

    def unlock(self, vault_path: str, password: str) -> Dict[str, Any]:
        if not isinstance(vault_path, str) or not os.path.isabs(vault_path):
            raise RpcProtocolError("Vault path must be absolute")
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "vault.unlock",
                    {"vaultPath": vault_path, "password": password},
                ),
                {"session", "vaultId", "idleTimeoutMs", "warnings"},
                "unlock result",
            )
            session = _expect_session_token(result.get("session"))
            idle = result.get("idleTimeoutMs")
            vault_id = result.get("vaultId")
            warnings = result.get("warnings")
            if (
                isinstance(idle, bool)
                or not isinstance(idle, int)
                or idle < 1000
                or idle > 60 * 60 * 1000
                or not isinstance(vault_id, str)
                or not _UUID_RE.fullmatch(vault_id)
                or not isinstance(warnings, list)
            ):
                raise RpcProtocolError("RPC unlock result is invalid")
        except RpcProtocolError as error:
            self._terminate_protocol(error)
        with self._state_lock:
            self._session = session
        return {"vaultId": vault_id, "idleTimeoutMs": idle, "warnings": warnings}

    def list_tree(self, prefix: Optional[str] = None) -> List[Dict[str, str]]:
        params = self._protected_params()
        if prefix is not None:
            params["prefix"] = prefix
        try:
            result = _expect_exact_object(
                self._call_raw("vault.listTree", params), {"entries"}, "tree result"
            )
            entries = result.get("entries")
            if not isinstance(entries, list) or len(entries) > 100000:
                raise RpcProtocolError("RPC tree result is invalid")
            parsed = []
            seen = set()
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {"kind", "logicalPath"}:
                    raise RpcProtocolError("RPC tree entry is invalid")
                if entry["kind"] not in ("directory", "file") or not isinstance(entry["logicalPath"], str):
                    raise RpcProtocolError("RPC tree entry is invalid")
                identity = (entry["kind"], entry["logicalPath"])
                if identity in seen:
                    raise RpcProtocolError("RPC tree contains a duplicate entry")
                seen.add(identity)
                parsed.append({"kind": entry["kind"], "logicalPath": entry["logicalPath"]})
            return parsed
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def open_document(self, logical_path: str) -> Tuple[str, bytearray, str]:
        content = bytearray()
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "document.open",
                    dict(self._protected_params(), logicalPath=logical_path),
                ),
                {"handle", "contentBase64", "etag", "metadata"},
                "document result",
            )
            handle = _expect_document_handle(result.get("handle"))
            content = decode_base64url(result.get("contentBase64"), MAX_DOCUMENT_BYTES)
            etag = _expect_etag(result.get("etag"))
            _validate_metadata(result.get("metadata"), logical_path, (0, 1))
            return handle, content, etag
        except RpcProtocolError as error:
            wipe(content)
            self._terminate_protocol(error)

    def umbra_status(self) -> Dict[str, bool]:
        """Return only the non-secret Umbra lock state for this session."""
        try:
            result = _expect_exact_object(
                self._call_raw("umbra.status", self._protected_params()),
                {"initialized", "unlocked"},
                "Umbra status result",
            )
            initialized = result.get("initialized")
            unlocked = result.get("unlocked")
            if not isinstance(initialized, bool) or not isinstance(unlocked, bool):
                raise RpcProtocolError("RPC Umbra status is invalid")
            return {"initialized": initialized, "unlocked": unlocked}
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def load_umbra_annotation_config(self) -> Dict[str, Any]:
        """Load the encrypted catalog only after daemon-side Umbra unlock."""
        try:
            result = _expect_exact_object(
                self._call_raw("umbra.config.get", self._protected_params()),
                {"tags", "profiles", "defaults"},
                "Umbra config result",
            )
            tags = result.get("tags")
            profiles = result.get("profiles")
            defaults = result.get("defaults")
            if not isinstance(tags, list) or not isinstance(profiles, list) or not isinstance(defaults, dict):
                raise RpcProtocolError("RPC Umbra config is invalid")
            if len(tags) > 4096 or len(profiles) > 4096:
                raise RpcProtocolError("RPC Umbra config exceeds the client limit")
            tag_ids = set()
            for tag in tags:
                if not isinstance(tag, dict) or not isinstance(tag.get("id"), str) or not tag.get("id"):
                    raise RpcProtocolError("RPC Umbra tag is invalid")
                tag_ids.add(tag["id"])
            profile_ids = set()
            for profile in profiles:
                if not isinstance(profile, dict) or not isinstance(profile.get("id"), str) or not profile.get("id"):
                    raise RpcProtocolError("RPC Umbra profile is invalid")
                values = profile.get("tagIds")
                if not isinstance(values, list) or any(not isinstance(value, str) or value not in tag_ids for value in values):
                    raise RpcProtocolError("RPC Umbra profile tags are invalid")
                profile_ids.add(profile["id"])
            default_profile = defaults.get("defaultProfileId")
            if not isinstance(default_profile, str) or (default_profile and default_profile not in profile_ids):
                raise RpcProtocolError("RPC Umbra default profile is invalid")
            return result
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def open_umbra_document(self, logical_path: str) -> Tuple[bytearray, str, Dict[str, Any]]:
        """Read an authenticated Umbra projection; never synthesize its render map."""
        content = bytearray()
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "umbra.document.open",
                    dict(self._protected_params(), logicalPath=logical_path),
                ),
                {"contentBase64", "etag", "metadata", "renderMap"},
                "Umbra document result",
            )
            content = decode_base64url(result.get("contentBase64"), MAX_DOCUMENT_BYTES)
            etag = _expect_etag(result.get("etag"))
            _validate_metadata(result.get("metadata"), logical_path, (2,))
            render_map = _parse_umbra_render_map(result.get("renderMap"), len(content))
            return content, etag, render_map
        except RpcProtocolError as error:
            wipe(content)
            self._terminate_protocol(error)

    def apply_private_annotation(
        self,
        logical_path: str,
        content: bytearray,
        etag: str,
        render_map: Dict[str, Any],
        selections: List[Dict[str, int]],
        spec: Dict[str, Any],
        merge_adjacent: bool = False,
    ) -> Tuple[bytearray, str, Dict[str, Any], str]:
        """Atomically wrap only ranges authenticated by the returned RenderMap."""
        return self._mutate_private_annotation(
            "umbra.annotation.apply", logical_path, content, etag, render_map,
            selections, spec, merge_adjacent,
        )

    def edit_private_annotation(
        self,
        logical_path: str,
        content: bytearray,
        etag: str,
        render_map: Dict[str, Any],
        selections: List[Dict[str, int]],
        spec: Dict[str, Any],
        merge_adjacent: bool = False,
    ) -> Tuple[bytearray, str, Dict[str, Any], str]:
        """Atomically edit metadata for ranges authenticated by the returned RenderMap."""
        return self._mutate_private_annotation(
            "umbra.annotation.edit", logical_path, content, etag, render_map,
            selections, spec, merge_adjacent,
        )

    def remove_private_annotations(
        self,
        logical_path: str,
        content: bytearray,
        etag: str,
        render_map: Dict[str, Any],
        selections: List[Dict[str, int]],
        merge_adjacent: bool = False,
    ) -> Tuple[bytearray, str, Dict[str, Any], str]:
        """Atomically unwrap complete private slots authenticated by the RenderMap."""
        return self._mutate_private_annotation(
            "umbra.annotation.remove", logical_path, content, etag, render_map,
            selections, None, merge_adjacent,
        )

    def _mutate_private_annotation(
        self,
        method: str,
        logical_path: str,
        content: bytearray,
        etag: str,
        render_map: Dict[str, Any],
        selections: List[Dict[str, int]],
        spec: Optional[Dict[str, Any]],
        merge_adjacent: bool,
    ) -> Tuple[bytearray, str, Dict[str, Any], str]:
        if not isinstance(content, bytearray):
            raise RpcProtocolError("Umbra projection is invalid")
        if not isinstance(merge_adjacent, bool):
            raise RpcProtocolError("Umbra merge option is invalid")
        params = dict(
            self._protected_params(),
            logicalPath=logical_path,
            ifMatch=_expect_etag(etag),
            contentBase64=encode_base64url(content, MAX_DOCUMENT_BYTES),
            renderMap=_parse_umbra_render_map(render_map, len(content)),
            selections=_serialize_umbra_selections(selections, len(content)),
            mergeAdjacent=merge_adjacent,
        )
        if spec is not None:
            params["spec"] = _serialize_private_annotation_spec(spec)
        next_content = bytearray()
        try:
            result = _expect_exact_object(
                self._call_raw(method, params),
                {"etag", "metadata", "durability", "contentBase64", "renderMap"},
                "Umbra annotation result",
            )
            next_content = decode_base64url(result.get("contentBase64"), MAX_DOCUMENT_BYTES)
            next_etag = _expect_etag(result.get("etag"))
            _validate_metadata(result.get("metadata"), logical_path, (2,))
            durability = _expect_durability(result.get("durability"), "Umbra annotation")
            next_map = _parse_umbra_render_map(result.get("renderMap"), len(next_content))
            return next_content, next_etag, next_map, durability
        except RpcProtocolError as error:
            wipe(next_content)
            self._terminate_protocol(error)

    def write_document(
        self, logical_path: str, content: bytearray, etag: str
    ) -> Tuple[str, str]:
        etag = _expect_etag(etag)
        encoded = encode_base64url(content, MAX_DOCUMENT_BYTES)
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "file.write",
                    dict(
                        self._protected_params(),
                        logicalPath=logical_path,
                        contentBase64=encoded,
                        ifMatch=etag,
                    ),
                ),
                {"etag", "metadata", "durability"},
                "write result",
            )
            new_etag = _expect_etag(result.get("etag"))
            _validate_metadata(result.get("metadata"), logical_path, (0, 1))
            durability = _expect_durability(result.get("durability"), "write")
            return new_etag, durability
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def create_document(self, logical_path: str) -> Tuple[str, str]:
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "file.write",
                    dict(
                        self._protected_params(),
                        logicalPath=logical_path,
                        contentBase64="",
                        ifNoneMatch="*",
                    ),
                ),
                {"etag", "metadata", "durability"},
                "create result",
            )
            etag = _expect_etag(result.get("etag"))
            _validate_metadata(result.get("metadata"), logical_path, (0, 1))
            durability = _expect_durability(result.get("durability"), "create")
            return etag, durability
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def create_directory(self, logical_path: str) -> None:
        try:
            self._expect_ok(
                self._call_raw(
                    "file.mkdir",
                    dict(self._protected_params(), logicalPath=logical_path),
                )
            )
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def rename_document(
        self, source: str, destination: str, source_etag: str
    ) -> Tuple[str, str, str]:
        source_etag = _expect_etag(source_etag)
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "file.rename",
                    dict(
                        self._protected_params(),
                        **{
                            "from": source,
                            "to": destination,
                            "sourceEtag": source_etag,
                            "destinationIfNoneMatch": "*",
                        }
                    ),
                ),
                {
                    "etag",
                    "metadata",
                    "destinationDurability",
                    "sourceDurability",
                },
                "rename result",
            )
            etag = _expect_etag(result.get("etag"))
            _validate_metadata(result.get("metadata"), destination, (0, 1))
            destination_durability = _expect_durability(
                result.get("destinationDurability"), "rename destination"
            )
            source_durability = _expect_durability(
                result.get("sourceDurability"), "rename source"
            )
            return etag, destination_durability, source_durability
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def delete_document(self, logical_path: str, etag: str) -> str:
        etag = _expect_etag(etag)
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "file.delete",
                    dict(
                        self._protected_params(),
                        logicalPath=logical_path,
                        ifMatch=etag,
                        recursive=False,
                    ),
                ),
                {"ok", "durability"},
                "delete result",
            )
            if result.get("ok") is not True:
                raise RpcProtocolError("RPC delete result is invalid")
            return _expect_durability(result.get("durability"), "delete")
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def encrypt_draft(
        self, logical_path: str, content: bytearray, base_etag: Optional[str]
    ) -> bytearray:
        encoded = encode_base64url(content, MAX_DOCUMENT_BYTES)
        envelope = bytearray()
        try:
            params = dict(
                self._protected_params(),
                logicalPath=logical_path,
                contentBase64=encoded,
            )
            if base_etag is not None:
                params["baseEtag"] = _expect_etag(base_etag)
            result = _expect_exact_object(
                self._call_raw(
                    "draft.encrypt",
                    params,
                ),
                {"draftBase64", "etag", "metadata"},
                "draft result",
            )
            envelope = decode_base64url(result.get("draftBase64"), MAX_DRAFT_BYTES)
            _expect_etag(result.get("etag"))
            _validate_metadata(result.get("metadata"), logical_path, (2, 3))
            if not envelope.startswith(b"EDRY"):
                raise RpcProtocolError("RPC draft envelope is invalid")
            return envelope
        except RpcProtocolError as error:
            wipe(envelope)
            self._terminate_protocol(error)

    def decrypt_draft(
        self, logical_path: str, envelope: bytearray
    ) -> Tuple[bytearray, Optional[str]]:
        if not isinstance(envelope, bytearray) or not envelope.startswith(b"EDRY"):
            raise RpcProtocolError("Encrypted draft envelope is invalid")
        encoded = encode_base64url(envelope, MAX_DRAFT_BYTES)
        content = bytearray()
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "draft.decrypt",
                    dict(
                        self._protected_params(),
                        logicalPath=logical_path,
                        draftBase64=encoded,
                    ),
                ),
                {"contentBase64", "baseEtag", "metadata"},
                "draft decrypt result",
            )
            content = decode_base64url(result.get("contentBase64"), MAX_DOCUMENT_BYTES)
            base_etag = result.get("baseEtag")
            if base_etag is not None:
                base_etag = _expect_etag(base_etag)
            _validate_metadata(result.get("metadata"), logical_path, (2, 3))
            return content, base_etag
        except RpcProtocolError as error:
            wipe(content)
            self._terminate_protocol(error)

    def search(self, query: str, limit: int = 100) -> List[Dict[str, Any]]:
        if not isinstance(query, str) or not 1 <= len(query.encode("utf-8")) <= 4096:
            raise RpcProtocolError("Search query exceeds the client limit")
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 1000:
            raise RpcProtocolError("Search limit is invalid")
        try:
            result = _expect_exact_object(
                self._call_raw(
                    "search.query",
                    dict(
                        self._protected_params(),
                        query=query,
                        limit=limit,
                        caseSensitive=False,
                        snippetByteLimit=4096,
                    ),
                ),
                {"results"},
                "search result",
            )
            entries = result.get("results")
            if not isinstance(entries, list) or len(entries) > limit:
                raise RpcProtocolError("RPC search result count is invalid")
            parsed = []
            for entry in entries:
                if not isinstance(entry, dict) or set(entry) != {
                    "logicalPath", "startByte", "endByte", "line", "utf16Column", "snippet"
                }:
                    raise RpcProtocolError("RPC search entry is invalid")
                path = entry.get("logicalPath")
                snippet = entry.get("snippet")
                numbers = [entry.get(key) for key in ("startByte", "endByte", "line", "utf16Column")]
                if (
                    not isinstance(path, str)
                    or not isinstance(snippet, str)
                    or len(snippet.encode("utf-8")) > 4096
                    or any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in numbers)
                    or numbers[1] < numbers[0]
                    or numbers[1] > MAX_DOCUMENT_BYTES
                ):
                    raise RpcProtocolError("RPC search entry is invalid")
                parsed.append(entry)
            return parsed
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def close_document(self, handle: str) -> None:
        handle = _expect_document_handle(handle)
        try:
            self._expect_ok(
                self._call_raw(
                    "document.close", dict(self._protected_params(), handle=handle)
                )
            )
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def ping(self) -> None:
        try:
            result = _expect_exact_object(
                self._call_raw("system.ping", self._protected_params()),
                {"ok", "uptimeMs", "sessionActive", "idleTimeoutMs"},
                "ping result",
            )
            uptime = result.get("uptimeMs")
            idle = result.get("idleTimeoutMs")
            if (
                result.get("ok") is not True
                or result.get("sessionActive") is not True
                or isinstance(uptime, bool)
                or not isinstance(uptime, int)
                or uptime < 0
                or isinstance(idle, bool)
                or not isinstance(idle, int)
                or idle < 0
                or idle > 60 * 60 * 1000
            ):
                raise RpcProtocolError("RPC authenticated ping result is invalid")
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def lock(self) -> None:
        session = self._session_value()
        try:
            try:
                self._expect_ok(self._call_raw("vault.lock", {"session": session}))
            except RpcProtocolError as error:
                self._terminate_protocol(error)
        finally:
            with self._state_lock:
                self._session = None

    def shutdown(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            if self._terminal_error is None:
                self._expect_ok(self._call_raw("system.shutdown", {}))
        except Exception:
            pass
        finally:
            with self._state_lock:
                self._session = None
            try:
                process.wait(timeout=2.0)
            except (subprocess.TimeoutExpired, OSError):
                process.kill()

    def dispose(self) -> None:
        process = self._process
        with self._state_lock:
            self._session = None
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        self._fail_terminal(RpcLifecycleError("Inex sidecar was disposed"), notify=False)

    def _protected_params(self) -> Dict[str, Any]:
        return {"session": self._session_value()}

    def _session_value(self) -> str:
        with self._state_lock:
            if self._session is None:
                raise RpcLifecycleError("Inex vault is locked")
            session = self._session
        try:
            return _expect_session_token(session)
        except RpcProtocolError as error:
            self._terminate_protocol(error)

    def _call_raw(self, method: str, params: Dict[str, Any]) -> Any:
        process = self._process
        if process is None or process.stdin is None:
            raise RpcLifecycleError("Inex sidecar is not running")
        with self._state_lock:
            terminal = self._terminal_error
        if terminal is not None:
            raise terminal
        with self._pending_lock:
            if len(self._pending) >= MAX_PENDING_CALLS:
                raise RpcLifecycleError("Inex sidecar call limit is reached")
            request_id = self._next_id
            if request_id > 2**53 - 1:
                raise RpcLifecycleError("Inex request id space is exhausted")
            self._next_id += 1
            pending = _Pending(method)
            self._pending[request_id] = pending
        try:
            frame = encode_request(request_id, method, params)
        except Exception:
            with self._pending_lock:
                self._pending.pop(request_id, None)
            raise
        try:
            with self._write_lock:
                if self._outstanding_bytes + len(frame) > MAX_OUTSTANDING_FRAME_BYTES:
                    raise RpcLifecycleError("Inex sidecar write queue byte limit is reached")
                self._outstanding_bytes += len(frame)
                try:
                    process.stdin.write(frame)
                    process.stdin.flush()
                finally:
                    self._outstanding_bytes -= len(frame)
        except Exception:
            wipe(frame)
            self._fail_terminal(RpcLifecycleError("Inex sidecar request write failed"))
            raise RpcLifecycleError("Inex sidecar request write failed")
        finally:
            wipe(frame)
        if not pending.event.wait(self.timeout_seconds):
            timeout_error = RpcLifecycleError(
                "Inex sidecar call timed out; mutation outcome is unknown"
            )
            self._fail_terminal(timeout_error)
            raise timeout_error
        if pending.error is not None:
            raise pending.error
        if pending.response is None:
            raise RpcLifecycleError("Inex sidecar response is unavailable")
        try:
            result = response_result(pending.response)
            if method in SESSION_RENEWING_METHODS and self.on_session_activity is not None:
                try:
                    self.on_session_activity()
                except Exception:
                    pass
            return result
        except RpcProtocolError as error:
            self._fail_terminal(error)
            raise
        except RpcRemoteError as error:
            if error.stable_name == "SESSION_INVALID":
                self._lose_session(error)
            raise

    def _read_stdout(self) -> None:
        process = self._process
        if process is None or process.stdout is None:
            return
        try:
            while True:
                chunk = _read_pipe_once(process.stdout)
                if not chunk:
                    self._decoder.finish()
                    self._fail_terminal(
                        RpcLifecycleError("Inex sidecar stdout closed")
                    )
                    return
                for response in self._decoder.feed(chunk):
                    self._accept_response(response)
        except Exception as error:
            self._fail_terminal(
                error
                if isinstance(error, (RpcLifecycleError, RpcProtocolError))
                else RpcLifecycleError("Inex sidecar stdout failed")
            )

    def _drain_stderr(self) -> None:
        process = self._process
        if process is None or process.stderr is None:
            return
        try:
            while True:
                chunk = _read_pipe_once(process.stderr)
                if not chunk:
                    return
                # Count and discard. Never echo child stderr into console or UI.
                self._stderr_bytes = min(MAX_STDERR_BYTES, self._stderr_bytes + len(chunk))
        except Exception:
            self._fail_terminal(RpcLifecycleError("Inex sidecar stderr failed"))

    def _watch_process(self) -> None:
        process = self._process
        if process is None:
            return
        try:
            code = process.wait()
        except OSError:
            code = -1
        self._fail_terminal(
            RpcLifecycleError(
                "Inex sidecar exited" if code == 0 else "Inex sidecar exited unexpectedly"
            )
        )

    def _accept_response(self, response: Dict[str, Any]) -> None:
        response_id = response.get("id")
        if response_id is None:
            self._fail_terminal(RpcProtocolError("Inex sidecar sent an uncorrelated error"))
            return
        with self._pending_lock:
            pending = self._pending.pop(response_id, None)
        if pending is None:
            self._fail_terminal(RpcProtocolError("Inex sidecar sent an unknown response id"))
            return
        pending.response = response
        pending.event.set()

    def _lose_session(self, error: Exception) -> None:
        with self._state_lock:
            had_session = self._session is not None
            self._session = None
        if had_session and self.on_session_lost is not None:
            try:
                self.on_session_lost(error)
            except Exception:
                pass

    def _fail_terminal(self, error: Exception, notify: bool = True) -> None:
        with self._state_lock:
            if self._terminal_error is not None:
                return
            self._terminal_error = error
            had_session = self._session is not None
            self._session = None
        self._decoder.clear()
        with self._pending_lock:
            pending_values = list(self._pending.values())
            self._pending.clear()
        for pending in pending_values:
            pending.error = error
            pending.event.set()
        process = self._process
        if process is not None and process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        if notify and had_session and self.on_session_lost is not None:
            try:
                self.on_session_lost(error)
            except Exception:
                pass

    def _terminate_protocol(self, error: RpcProtocolError) -> None:
        self._fail_terminal(error)
        raise error

    @staticmethod
    def _expect_ok(value: Any) -> None:
        if not isinstance(value, dict) or value != {"ok": True}:
            raise RpcProtocolError("RPC acknowledgement is invalid")


def encode_base64url(value: bytearray, maximum: int) -> str:
    if not isinstance(value, bytearray) or len(value) > maximum:
        raise RpcProtocolError("Binary request exceeds the client limit")
    return base64.urlsafe_b64encode(bytes(value)).rstrip(b"=").decode("ascii")


def decode_base64url(value: Any, maximum: int) -> bytearray:
    if not isinstance(value, str) or "=" in value or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        raise RpcProtocolError("RPC binary field is invalid")
    if len(value) > ((maximum + 2) // 3) * 4:
        raise RpcProtocolError("RPC binary field exceeds the client limit")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = bytearray(base64.b64decode(value + padding, altchars=b"-_", validate=True))
    except (ValueError, TypeError):
        raise RpcProtocolError("RPC binary field is invalid")
    if len(decoded) > maximum or encode_base64url(decoded, maximum) != value:
        wipe(decoded)
        raise RpcProtocolError("RPC binary field is not canonical")
    return decoded


def wipe(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0


def _expect_object(value: Any, name: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise RpcProtocolError("RPC %s is invalid" % name)
    return value


def _expect_exact_object(value: Any, keys: set, name: str) -> Dict[str, Any]:
    result = _expect_object(value, name)
    if set(result) != keys:
        raise RpcProtocolError("RPC %s is invalid" % name)
    return result


def _expect_bounded_string(value: Any, name: str, maximum: int) -> str:
    try:
        valid = isinstance(value, str) and bool(value) and len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        valid = False
    if not valid:
        raise RpcProtocolError("RPC %s is invalid" % name)
    return value


def _expect_session_token(value: Any) -> str:
    result = _expect_bounded_string(
        value, "session token", SESSION_TOKEN_TEXT_BYTES
    )
    if (
        len(result.encode("utf-8")) != SESSION_TOKEN_TEXT_BYTES
        or not _CAPABILITY_RE.fullmatch(result)
    ):
        raise RpcProtocolError("RPC session token is invalid")
    return result


def _expect_document_handle(value: Any) -> str:
    result = _expect_bounded_string(
        value, "document handle", DOCUMENT_HANDLE_TEXT_BYTES
    )
    if (
        len(result.encode("utf-8")) != DOCUMENT_HANDLE_TEXT_BYTES
        or not _CAPABILITY_RE.fullmatch(result)
    ):
        raise RpcProtocolError("RPC document handle is invalid")
    return result


def _expect_etag(value: Any) -> str:
    if not isinstance(value, str) or not _ETAG_RE.fullmatch(value):
        raise RpcProtocolError("RPC etag is invalid")
    return value


def _expect_durability(value: Any, operation: str) -> str:
    if value not in ("synced", "notSynced"):
        raise RpcProtocolError("RPC %s durability is invalid" % operation)
    return value


def _expect_umbra_range(value: Any, name: str, maximum: int) -> Dict[str, int]:
    if not isinstance(value, dict) or set(value) != {"startByte", "endByte"}:
        raise RpcProtocolError("RPC %s is invalid" % name)
    start = value.get("startByte")
    end = value.get("endByte")
    if (
        isinstance(start, bool)
        or isinstance(end, bool)
        or not isinstance(start, int)
        or not isinstance(end, int)
        or start < 0
        or end <= start
        or end > maximum
    ):
        raise RpcProtocolError("RPC %s is invalid" % name)
    return {"startByte": start, "endByte": end}


def _parse_umbra_render_map(value: Any, projection_bytes: int) -> Dict[str, Any]:
    """Validate and normalize a daemon-supplied or client-resubmitted map."""
    if (
        isinstance(projection_bytes, bool)
        or not isinstance(projection_bytes, int)
        or projection_bytes < 0
        or projection_bytes > MAX_DOCUMENT_BYTES
    ):
        raise RpcProtocolError("RPC Umbra projection length is invalid")
    render_map = _expect_exact_object(
        value,
        {"generationBase64", "projectionBytes", "privateSlots", "outerSegments"},
        "Umbra render map",
    )
    if render_map.get("projectionBytes") != projection_bytes:
        raise RpcProtocolError("RPC Umbra render map projection is invalid")
    generation = decode_base64url(render_map.get("generationBase64"), 32)
    try:
        if len(generation) != 32:
            raise RpcProtocolError("RPC Umbra render map generation is invalid")
    finally:
        wipe(generation)
    slots = render_map.get("privateSlots")
    segments = render_map.get("outerSegments")
    if (
        not isinstance(slots, list)
        or not isinstance(segments, list)
        or len(slots) > MAX_UMBRA_MAP_ENTRIES
        or len(segments) > MAX_UMBRA_MAP_ENTRIES
    ):
        raise RpcProtocolError("RPC Umbra render map exceeds the client limit")
    normalized_slots = []
    seen_slot_ids = set()
    previous_end = 0
    for slot in slots:
        if not isinstance(slot, dict) or set(slot) != {"slotId", "startByte", "endByte"}:
            raise RpcProtocolError("RPC Umbra private slot is invalid")
        slot_id = _expect_bounded_string(slot.get("slotId"), "Umbra slot id", 64)
        if slot_id in seen_slot_ids:
            raise RpcProtocolError("RPC Umbra private slots are duplicated")
        item = _expect_umbra_range(slot, "Umbra private slot range", projection_bytes)
        if item["startByte"] < previous_end:
            raise RpcProtocolError("RPC Umbra private slot ranges overlap")
        seen_slot_ids.add(slot_id)
        previous_end = item["endByte"]
        normalized_slots.append(dict(item, slotId=slot_id))
    normalized_segments = []
    previous_projection_end = 0
    previous_outer_end = 0
    for segment in segments:
        if not isinstance(segment, dict) or set(segment) != {
            "projectionStartByte", "projectionEndByte", "outerStartByte", "outerEndByte"
        }:
            raise RpcProtocolError("RPC Umbra outer segment is invalid")
        projection_range = _expect_umbra_range(
            {"startByte": segment.get("projectionStartByte"), "endByte": segment.get("projectionEndByte")},
            "Umbra projection segment", projection_bytes,
        )
        outer_start = segment.get("outerStartByte")
        outer_end = segment.get("outerEndByte")
        if (
            isinstance(outer_start, bool)
            or isinstance(outer_end, bool)
            or not isinstance(outer_start, int)
            or not isinstance(outer_end, int)
            or outer_start < 0
            or outer_end < outer_start
            or projection_range["startByte"] < previous_projection_end
            or outer_start < previous_outer_end
        ):
            raise RpcProtocolError("RPC Umbra outer segment range is invalid")
        previous_projection_end = projection_range["endByte"]
        previous_outer_end = outer_end
        normalized_segments.append({
            "projectionStartByte": projection_range["startByte"],
            "projectionEndByte": projection_range["endByte"],
            "outerStartByte": outer_start,
            "outerEndByte": outer_end,
        })
    return {
        "generationBase64": render_map["generationBase64"],
        "projectionBytes": projection_bytes,
        "privateSlots": normalized_slots,
        "outerSegments": normalized_segments,
    }


def _serialize_umbra_selections(value: Any, projection_bytes: int) -> List[Dict[str, int]]:
    if not isinstance(value, list) or not value or len(value) > MAX_UMBRA_MAP_ENTRIES:
        raise RpcProtocolError("Umbra selections are invalid")
    return [
        _expect_umbra_range(item, "Umbra selection", projection_bytes)
        for item in value
    ]


def _serialize_private_annotation_spec(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"kind", "tagIds", "outer"}:
        raise RpcProtocolError("Umbra annotation spec is invalid")
    kind = value.get("kind")
    tag_ids = value.get("tagIds")
    outer = value.get("outer")
    if kind not in ("block", "comment") or not isinstance(tag_ids, list):
        raise RpcProtocolError("Umbra annotation spec is invalid")
    if len(tag_ids) > MAX_UMBRA_MAP_ENTRIES:
        raise RpcProtocolError("Umbra annotation tags exceed the client limit")
    normalized_tags = []
    for tag_id in tag_ids:
        if not isinstance(tag_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", tag_id):
            raise RpcProtocolError("Umbra annotation tag is invalid")
        normalized_tags.append(tag_id)
    if normalized_tags != sorted(set(normalized_tags)):
        raise RpcProtocolError("Umbra annotation tags are not canonical")
    if not isinstance(outer, dict) or set(outer) not in ({"mode"}, {"mode", "coverText"}):
        raise RpcProtocolError("Umbra annotation outer strategy is invalid")
    mode = outer.get("mode")
    cover_text = outer.get("coverText")
    if mode not in ("drop", "cover", "placeholder") or (mode == "cover") != ("coverText" in outer):
        raise RpcProtocolError("Umbra annotation outer strategy is invalid")
    if mode == "cover":
        cover_text = _expect_bounded_string(cover_text, "Umbra cover text", MAX_DOCUMENT_BYTES)
    result = {"kind": kind, "tagIds": normalized_tags, "outer": {"mode": mode}}
    if mode == "cover":
        result["outer"]["coverText"] = cover_text
    return result


def _validate_metadata(value: Any, logical_path: str, allowed_flags: tuple) -> None:
    if not isinstance(value, dict) or set(value) != {
        "fileId", "logicalPath", "createdAt", "modifiedAt", "flags"
    }:
        raise RpcProtocolError("RPC document metadata is invalid")
    if value.get("logicalPath") != logical_path:
        raise RpcProtocolError("RPC document path binding is invalid")
    file_id = value.get("fileId")
    if not isinstance(file_id, str) or not _UUID_RE.fullmatch(file_id):
        raise RpcProtocolError("RPC document id is invalid")
    for key in ("createdAt", "modifiedAt", "flags"):
        item = value.get(key)
        if isinstance(item, bool) or not isinstance(item, int):
            raise RpcProtocolError("RPC document metadata is invalid")
    if value["flags"] not in allowed_flags:
        raise RpcProtocolError("RPC document flags are invalid")
