#!/usr/bin/env python3
"""Bounded Build 4200 isolated-profile smoke test for the Inex package."""

from __future__ import annotations

import argparse
import atexit
import base64
import ctypes
from dataclasses import dataclass, field
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform as host_platform
import re
import secrets
import select
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
SCRIPTS_DIRECTORY = REPOSITORY_ROOT / "scripts"
if str(SCRIPTS_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIRECTORY))

import drill_release_lifecycle as release_lifecycle
from audit_release_artifacts import validate_release_set_report
from release_common import (
    ReleaseError,
    portable_archive_key,
    sha256_bytes,
    source_revision,
)


BUILD = "4200"
FLOW_TIMEOUT_SECONDS = 75
HELPER_REPORT_MAX_BYTES = 1024 * 1024
HELPER_REPORT_MAX_LINE_BYTES = 16 * 1024
HELPER_REPORT_MAX_RECORDS = 256
ARTIFACT_REPORT_SCOPE = (
    "exact-packaged-sublime-build4200-single-scenario-evidence-non-release-approval"
)
RESTART_ARTIFACT_REPORT_SCOPE = (
    "exact-packaged-sublime-build4200-full-application-kill-restart-v4-evidence-"
    "non-release-approval"
)
ARTIFACT_HARNESS_FILES = (
    "editors/sublime/test/build4200/InexQA.py",
    "editors/sublime/test/build4200/run_build4200.py",
)
REPORT_TRUST_ASSUMPTIONS = (
    "exclusive-quiescent-clean-harness-artifact-and-isolated-profile",
    "no-same-principal-writer-from-snapshot-through-report-capture",
    "trusted-linux-kernel-procfs-x11-dbus-window-manager-python-and-build4200-installation",
)
COMMON_NOT_COVERED = (
    "adversarial-same-user-harness-artifact-profile-or-tool-writer",
    "artifact-signing-publication-independent-build-attestation-and-legal-review",
    "native-platforms-other-than-this-report",
    "sublime-builds-other-than-4200",
    "real-user-persistent-profile-hot-exit-local-history-sync-and-backup",
    "operating-system-memory-swap-gpu-and-window-system-forensics",
    "input-panel-quick-panel-mouse-accessibility-and-ime-interaction",
    "vscode-runtime-behavior-from-audited-but-not-executed-vsix",
)
SCAN_ENCODINGS = (
    "utf-8",
    "utf-16le",
    "utf-16be",
    "hex-lower",
    "base64-standard",
    "base64-standard-unpadded",
    "base64url",
    "base64url-unpadded",
)
NORMAL_EVENT_SEQUENCE = (
    "loaded",
    "unlock_dispatched",
    "password_prompt_answered",
    "ui",
    "opened",
    "saved",
    "ui",
    "crud_folder_created",
    "ui",
    "crud_markdown_created",
    "ui",
    "crud_markdown_renamed",
    "ui",
    "crud_markdown_deleted",
    "minimal_complete",
    "complete",
)
CRASH_EVENT_SEQUENCE = (
    "loaded",
    "unlock_dispatched",
    "password_prompt_answered",
    "ui",
    "opened",
    "saved",
    "plugin_host_crash_ready",
    "plugin_host_dead_clipboard_checked",
    "plugin_host_restart_required",
)
RESTART_EVENT_SEQUENCE = (
    "loaded",
    "unlock_dispatched",
    "password_prompt_answered",
    "ui",
    "opened",
    "saved",
    "full_application_restart_ready",
    "restart_loaded",
    "restart_preunlock_checked",
    "restart_unlock_dispatched",
    "password_prompt_answered",
    "ui",
    "restart_reopened",
    "restart_closed",
    "complete",
)
ROOT_ENVIRONMENT_KEYS = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR",
    "TMPDIR",
    "TMP",
    "TEMP",
)
PROCESS_IDENTITY_ENVIRONMENT_KEYS = ROOT_ENVIRONMENT_KEYS + ("GTK_USE_PORTAL",)
MOUNTINFO_MAX_BYTES = 1024 * 1024
MOUNTINFO_MAX_LINES = 4096
MOUNTINFO_MAX_LINE_BYTES = 16 * 1024
PORTAL_UNMOUNT_HELPER = Path("/usr/bin/fusermount3")
PR_SET_CHILD_SUBREAPER = 36
PR_GET_CHILD_SUBREAPER = 37


class QaFailure(RuntimeError):
    pass


class ProcessDisappeared(QaFailure):
    pass


_ACTIVE_ARTIFACT_ROOT: Optional[Tuple[Path, os.stat_result]] = None


def cleanup_active_artifact_root(
    *, allow_dead_failure_portal_unmount: bool = False
) -> None:
    """Delete only the exact private artifact-mode root registered by this process."""

    global _ACTIVE_ARTIFACT_ROOT
    active = _ACTIVE_ARTIFACT_ROOT
    if active is None:
        return
    root, expected = active
    try:
        observed = root.lstat()
    except FileNotFoundError:
        _ACTIVE_ARTIFACT_ROOT = None
        return
    except OSError as error:
        raise QaFailure("artifact evidence root identity is unavailable") from error
    if (
        release_lifecycle.is_link_like(root, observed)
        or not stat.S_ISDIR(observed.st_mode)
        or not os.path.samestat(expected, observed)
        or stat.S_IMODE(observed.st_mode) != 0o700
    ):
        raise QaFailure("artifact evidence root changed physical identity")
    table = process_table()
    runner_started = process_snapshot(os.getpid()).start_time_ticks
    strict_candidates = {
        snapshot.pid
        for snapshot in table.values()
        if snapshot.parent_pid == os.getpid()
        and snapshot.start_time_ticks >= runner_started
    }
    if stable_root_binding_census(
        root,
        expected_root_environment(root),
        strict_candidate_pids=strict_candidates,
    ):
        raise QaFailure("artifact evidence root retains a live process binding")
    mounts = root_mounts(root)
    if mounts:
        if not allow_dead_failure_portal_unmount:
            raise QaFailure("artifact evidence root retains a mount")
        unmount_exact_dead_failure_portal(root, mounts)
    shutil.rmtree(root)
    if os.path.lexists(root):
        raise QaFailure("artifact evidence root deletion was not verified")
    _ACTIVE_ARTIFACT_ROOT = None


def _atexit_cleanup_artifact_root() -> None:
    try:
        cleanup_active_artifact_root()
    except Exception as error:
        print("artifact-root-cleanup-failed=" + type(error).__name__, file=sys.stderr)


atexit.register(_atexit_cleanup_artifact_root)


@dataclass(frozen=True)
class PhysicalFileSeal:
    metadata: os.stat_result
    sha256: str


@dataclass(frozen=True)
class PhysicalTreeSeal:
    root: os.stat_result
    directories: Mapping[str, os.stat_result]
    files: Mapping[str, PhysicalFileSeal]


@dataclass(frozen=True)
class ProcessSnapshot:
    pid: int
    state: str = field(compare=False)
    parent_pid: int
    process_group_id: int
    session_id: int
    start_time_ticks: int


@dataclass
class StableProcessHandle:
    snapshot: ProcessSnapshot
    pidfd: int


@dataclass(frozen=True)
class RootBindingObservation:
    snapshot: ProcessSnapshot
    sources: Tuple[str, ...]
    environment_keys: Tuple[str, ...]
    argv_mentions_root: bool


@dataclass(frozen=True)
class MountInfoRecord:
    mount_id: int
    parent_id: int
    major_minor: str
    root: str
    mount_point: str
    mount_options: str
    optional_fields: Tuple[str, ...]
    filesystem_type: str
    mount_source: str
    super_options: str


def _metadata_signature(metadata: os.stat_result) -> Tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def capture_physical_file_seal(
    path: Path,
    label: str,
    *,
    strip_posix_write_bits: bool = False,
    require_posix_executable: bool = False,
) -> PhysicalFileSeal:
    """Bind one regular path to its open-file identity, metadata, and bytes."""

    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        before = path.lstat()
        if (
            release_lifecycle.is_link_like(path, before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise QaFailure(label + " is not a non-link single-link regular file")
        descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not os.path.samestat(before, opened)
        ):
            raise QaFailure(label + " changed physical identity while opening")
        if require_posix_executable and os.name != "nt":
            if stat.S_IMODE(opened.st_mode) & 0o111 == 0:
                raise QaFailure(label + " is not executable")
            if strip_posix_write_bits:
                if stat.S_IMODE(opened.st_mode) & 0o222:
                    os.fchmod(descriptor, stat.S_IMODE(opened.st_mode) & ~0o222)
                    opened = os.fstat(descriptor)
                if stat.S_IMODE(opened.st_mode) & 0o222:
                    raise QaFailure(label + " retains a POSIX write bit")
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
        after_opened = os.fstat(descriptor)
        after_path = path.lstat()
        if (
            not os.path.samestat(opened, after_opened)
            or not os.path.samestat(opened, after_path)
            or _metadata_signature(opened) != _metadata_signature(after_opened)
            or _metadata_signature(opened) != _metadata_signature(after_path)
        ):
            raise QaFailure(label + " changed while its identity was captured")
        return PhysicalFileSeal(metadata=after_path, sha256=digest.hexdigest())
    except OSError as error:
        raise QaFailure(label + " physical identity is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def verify_physical_file_seal(
    path: Path,
    seal: PhysicalFileSeal,
    label: str,
    *,
    require_posix_executable: bool = False,
) -> None:
    observed = capture_physical_file_seal(
        path,
        label,
        require_posix_executable=require_posix_executable,
    )
    if (
        not os.path.samestat(seal.metadata, observed.metadata)
        or _metadata_signature(seal.metadata)
        != _metadata_signature(observed.metadata)
        or seal.sha256 != observed.sha256
    ):
        raise QaFailure(label + " changed physical identity or contents")


def _walk_physical_tree(
    root: Path,
) -> Tuple[os.stat_result, Dict[str, os.stat_result], Dict[str, Path]]:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise QaFailure("sealed tree root is unavailable") from error
    if release_lifecycle.is_link_like(root, root_metadata) or not stat.S_ISDIR(
        root_metadata.st_mode
    ):
        raise QaFailure("sealed tree root is not a non-link directory")
    directories: Dict[str, os.stat_result] = {".": root_metadata}
    files: Dict[str, Path] = {}
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = sorted(
                    (Path(entry.path) for entry in entries), key=lambda path: path.name
                )
        except OSError as error:
            raise QaFailure("sealed tree traversal failed closed") from error
        for child in children:
            try:
                metadata = child.lstat()
                relative = child.relative_to(root).as_posix()
            except (OSError, ValueError) as error:
                raise QaFailure("sealed tree entry identity is unavailable") from error
            if release_lifecycle.is_link_like(child, metadata):
                raise QaFailure("sealed tree contains a link-like entry")
            if stat.S_ISDIR(metadata.st_mode):
                directories[relative] = metadata
                pending.append(child)
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                files[relative] = child
            else:
                raise QaFailure("sealed tree contains a non-regular file")
    return root_metadata, directories, files


def capture_physical_tree_seal(root: Path, label: str) -> PhysicalTreeSeal:
    root_metadata, directories, paths = _walk_physical_tree(root)
    files = {
        relative: capture_physical_file_seal(path, label + " file " + relative)
        for relative, path in sorted(paths.items())
    }
    root_after, directories_after, paths_after = _walk_physical_tree(root)
    if (
        _metadata_signature(root_metadata) != _metadata_signature(root_after)
        or set(directories) != set(directories_after)
        or set(paths) != set(paths_after)
        or any(
            _metadata_signature(directories[name])
            != _metadata_signature(directories_after[name])
            for name in directories
        )
    ):
        raise QaFailure(label + " changed while its tree seal was captured")
    return PhysicalTreeSeal(root_after, directories_after, files)


def verify_physical_tree_seal(
    root: Path, seal: PhysicalTreeSeal, label: str
) -> None:
    observed = capture_physical_tree_seal(root, label)
    if (
        not os.path.samestat(seal.root, observed.root)
        or _metadata_signature(seal.root) != _metadata_signature(observed.root)
        or set(seal.directories) != set(observed.directories)
        or set(seal.files) != set(observed.files)
    ):
        raise QaFailure(label + " changed physical tree identity")
    for relative in seal.directories:
        if (
            not os.path.samestat(
                seal.directories[relative], observed.directories[relative]
            )
            or _metadata_signature(seal.directories[relative])
            != _metadata_signature(observed.directories[relative])
        ):
            raise QaFailure(label + " directory changed: " + relative)
    for relative in seal.files:
        expected = seal.files[relative]
        actual = observed.files[relative]
        if (
            not os.path.samestat(expected.metadata, actual.metadata)
            or _metadata_signature(expected.metadata)
            != _metadata_signature(actual.metadata)
            or expected.sha256 != actual.sha256
        ):
            raise QaFailure(label + " file changed: " + relative)


def seal_record(name: str, seal: PhysicalFileSeal) -> Dict[str, object]:
    metadata = seal.metadata
    return {
        "name": name,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "linkCount": metadata.st_nlink,
        "size": metadata.st_size,
        "mtimeNs": metadata.st_mtime_ns,
        "ctimeNs": metadata.st_ctime_ns,
        "sha256": seal.sha256,
    }


def directory_binding(path: Path) -> Dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QaFailure("restart profile directory identity is unavailable") from error
    if (
        release_lifecycle.is_link_like(path, metadata)
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o700 != 0o700
    ):
        raise QaFailure("restart profile directory is not owner-accessible and physical")
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "path": str(path),
        "pathSha256": sha256_bytes(str(path).encode("utf-8")),
    }


def token_fingerprint_set_digest(
    fingerprints: Iterable[Tuple[int, str]]
) -> str:
    records = [
        {"byte_count": byte_count, "content_sha256": digest}
        for byte_count, digest in sorted(fingerprints)
    ]
    return sha256_bytes(
        json.dumps(
            records,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def physical_tree_report_digest(seal: PhysicalTreeSeal) -> str:
    records = [
        seal_record(name, seal.files[name]) for name in sorted(seal.files)
    ]
    return sha256_bytes(
        json.dumps(
            records,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _snapshot_file_paths(root: Path) -> Dict[str, Path]:
    try:
        metadata = root.lstat()
        paths = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise QaFailure("the four-file artifact snapshot is unavailable") from error
    if (
        release_lifecycle.is_link_like(root, metadata)
        or not stat.S_ISDIR(metadata.st_mode)
        or len(paths) != 4
        or len({path.name for path in paths}) != 4
        or "SHA256SUMS" not in {path.name for path in paths}
    ):
        raise QaFailure("the artifact snapshot is not exactly four direct files")
    return {path.name: path for path in paths}


def capture_artifact_snapshot(
    artifact_directory: Path, destination: Path
) -> Dict[str, PhysicalFileSeal]:
    try:
        release_lifecycle.snapshot_artifact_directory(
            artifact_directory.resolve(strict=True), destination
        )
    except (OSError, ReleaseError) as error:
        raise QaFailure("strict artifact snapshot failed: " + str(error)) from error
    return {
        name: capture_physical_file_seal(path, "artifact snapshot file " + name)
        for name, path in _snapshot_file_paths(destination).items()
    }


def verify_artifact_snapshot(
    root: Path, seals: Mapping[str, PhysicalFileSeal]
) -> None:
    paths = _snapshot_file_paths(root)
    if set(paths) != set(seals):
        raise QaFailure("the four-file artifact snapshot changed its file set")
    for name in sorted(paths):
        verify_physical_file_seal(
            paths[name], seals[name], "artifact snapshot file " + name
        )


def capture_audited_artifact_entries(
    snapshot: Path, seals: Mapping[str, PhysicalFileSeal]
) -> Tuple[
    Dict[str, Dict[str, Tuple[bytes, int]]],
    Dict[str, str],
    Dict[str, object],
    str,
    str,
    Dict[str, object],
]:
    verify_artifact_snapshot(snapshot, seals)
    try:
        captured = release_lifecycle.capture_audited_artifacts(snapshot)
    except (OSError, ReleaseError, UnicodeError, ValueError) as error:
        raise QaFailure("strict release-set audit failed: " + str(error)) from error
    verify_artifact_snapshot(snapshot, seals)
    return captured


def write_exclusive_member(path: Path, content: bytes, mode: int) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | binary,
            mode,
        )
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, mode)
    except OSError as error:
        raise QaFailure("packaged member could not be materialized exclusively") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def materialize_packaged_inputs(
    entries_by_kind: Mapping[str, Mapping[str, Tuple[bytes, int]]],
    platform_name: str,
    cli_directory: Path,
    packages_directory: Path,
) -> Tuple[Path, Path, List[Dict[str, object]]]:
    if platform_name != release_lifecycle.native_platform():
        raise QaFailure("the packaged artifact does not match the native host")
    suffix = ".exe" if platform_name.startswith("windows-") else ""
    rust_entries = entries_by_kind.get("rust", {})
    sublime_entries = entries_by_kind.get("sublime", {})
    cli_members = [
        name for name in rust_entries if name.endswith("/bin/inex" + suffix)
    ]
    sidecar_member = "Inex/bin/inexd" + suffix
    if len(cli_members) != 1 or sidecar_member not in sublime_entries:
        raise QaFailure("audited packages omit the required CLI or Sublime sidecar")

    cli_directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    cli = cli_directory / ("inex" + suffix)
    cli_content, cli_mode = rust_entries[cli_members[0]]
    cli_mode = (cli_mode | 0o111) & ~0o222 if os.name != "nt" else cli_mode
    write_exclusive_member(cli, cli_content, cli_mode)

    inex_package = packages_directory / "Inex"
    inex_package.mkdir(mode=0o700, parents=False, exist_ok=False)
    records: List[Dict[str, object]] = [
        {
            "archiveKind": "rust",
            "memberName": cli_members[0],
            "mode": cli_mode,
            "size": len(cli_content),
            "sha256": sha256_bytes(cli_content),
        }
    ]
    for member_name in sorted(sublime_entries):
        pure = PurePosixPath(member_name)
        if not pure.parts or pure.parts[0] != "Inex" or len(pure.parts) < 2:
            raise QaFailure("audited Sublime member is outside the Inex package")
        relative = pure.parts[1:]
        output = inex_package.joinpath(*relative)
        output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        content, archive_mode = sublime_entries[member_name]
        output_mode = archive_mode
        if member_name == sidecar_member and os.name != "nt":
            output_mode = (output_mode | 0o111) & ~0o222
        write_exclusive_member(output, content, output_mode)
        records.append(
            {
                "archiveKind": "sublime",
                "memberName": member_name,
                "mode": output_mode,
                "size": len(content),
                "sha256": sha256_bytes(content),
            }
        )
    sidecar = inex_package / "bin" / ("inexd" + suffix)
    return cli, sidecar, records


def parse_arguments(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="retain the isolated root")
    scenario = parser.add_mutually_exclusive_group()
    scenario.add_argument(
        "--plugin-host-crash",
        action="store_true",
        help="kill and restart the isolated Python 3.8 plugin host with plaintext open",
    )
    scenario.add_argument(
        "--full-application-kill-restart",
        action="store_true",
        help="SIGKILL the isolated application and reopen through the same profile",
    )
    parser.add_argument("--root", type=Path, help="use an explicit empty test root")
    parser.add_argument(
        "--artifact-directory",
        type=Path,
        help="strict four-file final platform artifact directory",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="create-new external canonical artifact evidence report",
    )
    arguments = parser.parse_args(argv)
    if (arguments.artifact_directory is None) != (arguments.output is None):
        parser.error("--artifact-directory and --output are required together")
    return arguments


def raise_on_termination(signum: int, _frame: object) -> None:
    raise QaFailure("received termination signal %d" % signum)


def run_checked(argv: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess:
    options = dict(kwargs)
    options.setdefault("check", True)
    options.setdefault("timeout", 20)
    return subprocess.run(list(argv), **options)


def verified_system_zenity() -> Optional[str]:
    """Resolve only the same absolute regular helpers accepted by production."""

    for candidate in (Path("/usr/bin/zenity"), Path("/usr/local/bin/zenity")):
        try:
            metadata = candidate.lstat()
        except OSError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_mode & 0o111
        ):
            return str(candidate)
    return None


def fixed_child_environment(root: Path) -> Dict[str, str]:
    environment = {
        "HOME": str(root / "home"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_RUNTIME_DIR": str(root / "runtime"),
        "TMPDIR": str(root / "tmp"),
        "TMP": str(root / "tmp"),
        "TEMP": str(root / "tmp"),
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    return environment


def restart_child_environment(root: Path) -> Dict[str, str]:
    environment = fixed_child_environment(root)
    environment["GTK_USE_PORTAL"] = "0"
    return environment


def private_dbus_config_bytes(socket_path: Path) -> bytes:
    raw_path = str(socket_path)
    if (
        not socket_path.is_absolute()
        or os.path.normpath(raw_path) != raw_path
        or any(character in raw_path for character in "&<>\"'\r\n")
    ):
        raise QaFailure("private D-Bus socket path is unsafe for fixed XML")
    return (
        "<!DOCTYPE busconfig PUBLIC \"-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN\"\n"
        " \"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd\">\n"
        "<busconfig>\n"
        "  <type>session</type>\n"
        "  <keep_umask/>\n"
        "  <listen>unix:path="
        + raw_path
        + "</listen>\n"
        "  <auth>EXTERNAL</auth>\n"
        "  <policy context=\"default\">\n"
        "    <allow send_destination=\"*\" eavesdrop=\"true\"/>\n"
        "    <allow eavesdrop=\"true\"/>\n"
        "    <allow own=\"*\"/>\n"
        "  </policy>\n"
        "</busconfig>\n"
    ).encode("utf-8")


def bounded_tool_version(path: Path, arguments: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            [str(path), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise QaFailure("tool version probe failed: " + path.name) from error
    if result.returncode != 0 or len(result.stdout) > 16 * 1024:
        raise QaFailure("tool version probe returned an invalid status: " + path.name)
    try:
        lines = [line.strip() for line in result.stdout.decode("utf-8").splitlines() if line.strip()]
    except UnicodeError as error:
        raise QaFailure("tool version output is not UTF-8: " + path.name) from error
    if not lines or len(lines[0]) > 256:
        raise QaFailure("tool version output is empty or oversized: " + path.name)
    return lines[0]


def capture_harness_state(
    repository: Path,
) -> Tuple[Dict[str, object], Dict[str, PhysicalFileSeal]]:
    try:
        revision = source_revision(repository)
    except (OSError, ReleaseError, UnicodeError, ValueError) as error:
        raise QaFailure("Build 4200 harness provenance is unavailable") from error
    if revision.get("dirtySourceTree") is not False:
        raise QaFailure("artifact evidence requires a clean harness source tree")
    seals = {
        name: capture_physical_file_seal(repository / name, "harness file " + name)
        for name in ARTIFACT_HARNESS_FILES
    }
    return revision, seals


def verify_harness_state(
    repository: Path,
    expected_revision: Mapping[str, object],
    seals: Mapping[str, PhysicalFileSeal],
    *,
    recheck_revision: bool = False,
) -> None:
    for name in ARTIFACT_HARNESS_FILES:
        if name not in seals:
            raise QaFailure("Build 4200 harness seal set is incomplete")
        verify_physical_file_seal(
            repository / name, seals[name], "harness file " + name
        )
    if recheck_revision:
        try:
            observed = source_revision(repository)
        except (OSError, ReleaseError, UnicodeError, ValueError) as error:
            raise QaFailure("Build 4200 harness provenance recheck failed") from error
        if observed != expected_revision:
            raise QaFailure("Build 4200 harness source changed during execution")


def packaged_sidecar_pids(
    executable: Path, seal: PhysicalFileSeal
) -> List[int]:
    expected = str(executable)
    matches: List[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        command = process_cmdline(pid)
        if command != [expected]:
            continue
        try:
            opened = (entry / "exe").stat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise QaFailure("packaged sidecar /proc/exe identity is unavailable") from error
        if (
            not os.path.samestat(seal.metadata, opened)
            or _metadata_signature(seal.metadata) != _metadata_signature(opened)
        ):
            raise QaFailure("sidecar PID does not execute the sealed packaged daemon")
        matches.append(pid)
    return matches


def verify_binding_inputs(
    artifact_snapshot: Path,
    artifact_seals: Mapping[str, PhysicalFileSeal],
    installed_inex: Path,
    installed_seal: PhysicalTreeSeal,
    executables: Mapping[str, Path],
    executable_seals: Mapping[str, PhysicalFileSeal],
    tools: Mapping[str, Path],
    tool_seals: Mapping[str, PhysicalFileSeal],
    harness_source: Mapping[str, object],
    harness_seals: Mapping[str, PhysicalFileSeal],
) -> None:
    verify_artifact_snapshot(artifact_snapshot, artifact_seals)
    verify_physical_tree_seal(installed_inex, installed_seal, "installed Inex package")
    for name, path in executables.items():
        verify_physical_file_seal(
            path,
            executable_seals[name],
            "packaged " + name,
            require_posix_executable=True,
        )
    for name, path in tools.items():
        verify_physical_file_seal(
            path, tool_seals[name], "Build 4200 helper " + name, require_posix_executable=True
        )
    verify_harness_state(
        REPOSITORY_ROOT, harness_source, harness_seals, recheck_revision=False
    )


def wait_until(label: str, predicate, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise QaFailure("timed out: " + label)


def child_pids(parent: int) -> List[int]:
    result: List[int] = []
    frontier = [parent]
    while frontier:
        current = frontier.pop()
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry / "stat").read_text().split()
                ppid = int(fields[3])
            except (OSError, ValueError, IndexError, UnicodeError):
                continue
            pid = int(entry.name)
            if ppid == current and pid not in result:
                result.append(pid)
                frontier.append(pid)
    return result


def process_cmdline(pid: int) -> List[str]:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return []
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def process_snapshot(pid: int) -> ProcessSnapshot:
    try:
        raw = (Path("/proc") / str(pid) / "stat").read_text()
    except FileNotFoundError as error:
        raise ProcessDisappeared("process disappeared during identity capture") from error
    except (OSError, UnicodeError) as error:
        raise QaFailure("process stat identity is unavailable") from error
    close = raw.rfind(")")
    if close < 0:
        raise QaFailure("process stat identity is malformed")
    fields = raw[close + 2 :].split()
    try:
        state = fields[0]
        parent_pid = int(fields[1])
        process_group_id = int(fields[2])
        session_id = int(fields[3])
        start_time_ticks = int(fields[19])
    except (IndexError, ValueError) as error:
        raise QaFailure("process stat identity is malformed") from error
    if (
        len(state) != 1
        or parent_pid < 0
        or process_group_id <= 1
        or session_id <= 1
        or start_time_ticks <= 0
    ):
        raise QaFailure("process stat identity is outside its bounds")
    return ProcessSnapshot(
        pid=pid,
        state=state,
        parent_pid=parent_pid,
        process_group_id=process_group_id,
        session_id=session_id,
        start_time_ticks=start_time_ticks,
    )


def process_stat_fields(pid: int) -> Tuple[str, int, int, int, int]:
    observed = process_snapshot(pid)
    return (
        observed.state,
        observed.parent_pid,
        observed.process_group_id,
        observed.session_id,
        observed.start_time_ticks,
    )


def enable_and_verify_child_subreaper() -> None:
    if sys.platform != "linux":
        raise QaFailure("full application restart evidence requires Linux subreaper support")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
    except (AttributeError, OSError) as error:
        raise QaFailure("Linux child subreaper control is unavailable") from error
    result = prctl(
        ctypes.c_int(PR_SET_CHILD_SUBREAPER),
        ctypes.c_ulong(1),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise QaFailure(
            "Linux child subreaper activation failed: " + os.strerror(error_number)
        )
    observed = ctypes.c_int(0)
    result = prctl(
        ctypes.c_int(PR_GET_CHILD_SUBREAPER),
        ctypes.byref(observed),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
        ctypes.c_ulong(0),
    )
    if result != 0 or observed.value != 1:
        raise QaFailure("Linux child subreaper activation was not confirmed")


def open_stable_process(
    pid: int, expected: Optional[ProcessSnapshot] = None
) -> StableProcessHandle:
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise QaFailure("stable process control requires Linux pidfd support")
    before = process_snapshot(pid)
    if before.state == "Z" or (expected is not None and before != expected):
        raise QaFailure("process identity changed before pidfd capture")
    descriptor = -1
    try:
        descriptor = os.pidfd_open(pid)
        after = process_snapshot(pid)
        if after != before or after.state == "Z":
            raise QaFailure("process identity changed during pidfd capture")
        return StableProcessHandle(snapshot=after, pidfd=descriptor)
    except OSError as error:
        if descriptor >= 0:
            os.close(descriptor)
        raise QaFailure("stable process pidfd capture failed") from error
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        raise


def close_process_handles(handles: Iterable[StableProcessHandle]) -> None:
    for handle in handles:
        try:
            os.close(handle.pidfd)
        except OSError:
            pass


def stable_process_alive(handle: StableProcessHandle) -> bool:
    poller = select.poll()
    poller.register(handle.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    if poller.poll(0):
        return False
    try:
        return process_snapshot(handle.snapshot.pid) == handle.snapshot
    except QaFailure:
        return False


def signal_stable_process(handle: StableProcessHandle, signum: int) -> None:
    if not stable_process_alive(handle):
        return
    try:
        signal.pidfd_send_signal(handle.pidfd, signum)
    except ProcessLookupError:
        return
    except OSError as error:
        raise QaFailure("pidfd signal delivery failed") from error


def wait_for_stable_processes(
    handles: Sequence[StableProcessHandle], label: str, timeout: float
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not any(stable_process_alive(handle) for handle in handles):
            return
        time.sleep(0.02)
    if any(stable_process_alive(handle) for handle in handles):
        raise QaFailure("timed out waiting for " + label)


def process_environment_binding(pid: int, expected: Mapping[str, str]) -> str:
    try:
        raw = (Path("/proc") / str(pid) / "environ").read_bytes()
    except OSError as error:
        raise QaFailure("process environment identity is unavailable") from error
    values: Dict[str, str] = {}
    for item in raw.split(b"\0"):
        if not item or b"=" not in item:
            continue
        key_bytes, value_bytes = item.split(b"=", 1)
        try:
            key = key_bytes.decode("ascii")
            value = value_bytes.decode("utf-8")
        except UnicodeError:
            continue
        if key in expected:
            values[key] = value
    if values != dict(expected):
        raise QaFailure("application process escaped the isolated environment")
    return sha256_bytes(
        json.dumps(values, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    )


def expected_root_environment(root: Path) -> Dict[str, str]:
    return {
        "HOME": str(root / "home"),
        "XDG_CONFIG_HOME": str(root / "config"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_RUNTIME_DIR": str(root / "runtime"),
        "TMPDIR": str(root / "tmp"),
        "TMP": str(root / "tmp"),
        "TEMP": str(root / "tmp"),
    }


def _path_target_within_root(target: str, root: Path) -> bool:
    deleted_suffix = " (deleted)"
    if target.endswith(deleted_suffix):
        target = target[: -len(deleted_suffix)]
    if not target.startswith(os.sep):
        return False
    try:
        return os.path.commonpath((target, str(root))) == str(root)
    except ValueError:
        return False


def _read_proc_link(pid: int, name: str) -> str:
    try:
        return os.readlink(Path("/proc") / str(pid) / name)
    except FileNotFoundError as error:
        raise ProcessDisappeared("process path disappeared during census") from error
    except OSError as error:
        raise QaFailure("procfs process path binding is unavailable") from error


def _process_environment_root_keys(
    pid: int, expected_environment: Mapping[str, str]
) -> Tuple[str, ...]:
    try:
        raw = (Path("/proc") / str(pid) / "environ").read_bytes()
    except FileNotFoundError as error:
        raise ProcessDisappeared("process environment disappeared during census") from error
    except OSError as error:
        raise QaFailure("procfs process environment census is unavailable") from error
    matches = set()
    encoded_expected = {
        key.encode("ascii"): value.encode("utf-8")
        for key, value in expected_environment.items()
    }
    for item in raw.split(b"\0"):
        if b"=" not in item:
            continue
        key, value = item.split(b"=", 1)
        if encoded_expected.get(key) == value:
            matches.add(key.decode("ascii"))
    return tuple(sorted(matches))


def _process_fd_targets(pid: int) -> Tuple[str, ...]:
    directory = Path("/proc") / str(pid) / "fd"
    try:
        before = sorted(entry.name for entry in directory.iterdir())
    except FileNotFoundError as error:
        raise ProcessDisappeared("process descriptors disappeared during census") from error
    except OSError as error:
        raise QaFailure("procfs process descriptor census is unavailable") from error
    targets = []
    for descriptor_name in before:
        try:
            targets.append(os.readlink(directory / descriptor_name))
        except FileNotFoundError:
            # A descriptor closed during the walk is no longer a surviving
            # binding. Two complete process censuses below still have to
            # agree before the result is accepted.
            continue
        except OSError as error:
            raise QaFailure("procfs process descriptor binding is unavailable") from error
    return tuple(targets)


def capture_root_binding_observation(
    pid: int, root: Path, expected_environment: Mapping[str, str]
) -> Optional[RootBindingObservation]:
    try:
        owner = (Path("/proc") / str(pid)).stat().st_uid
    except FileNotFoundError as error:
        raise ProcessDisappeared("process ownership disappeared during census") from error
    except OSError as error:
        raise QaFailure("procfs process ownership is unavailable") from error
    if owner != os.geteuid():
        return None
    before = process_snapshot(pid)
    if before.state == "Z":
        return None
    sources = set()
    for name in ("exe", "cwd", "root"):
        target = _read_proc_link(pid, name)
        if _path_target_within_root(target, root):
            sources.add(name)
    if any(
        _path_target_within_root(target, root)
        for target in _process_fd_targets(pid)
    ):
        sources.add("fd")
    environment_keys = _process_environment_root_keys(pid, expected_environment)
    if environment_keys:
        sources.add("environment")
    argv_mentions_root = any(
        str(root) in argument for argument in process_cmdline(pid)
    )
    after = process_snapshot(pid)
    if after != before:
        raise ProcessDisappeared("process identity changed during census")
    if not sources:
        return None
    return RootBindingObservation(
        snapshot=after,
        sources=tuple(sorted(sources)),
        environment_keys=environment_keys,
        argv_mentions_root=argv_mentions_root,
    )


def _root_binding_census_once(
    root: Path,
    expected_environment: Mapping[str, str],
    excluded_pids: Iterable[int],
    minimum_start_time_ticks: int,
    strict_candidate_pids: Iterable[int],
) -> Tuple[RootBindingObservation, ...]:
    excluded = set(excluded_pids)
    strict_candidates = set(strict_candidate_pids)
    observations = []
    try:
        entries = sorted(
            (entry for entry in Path("/proc").iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        )
    except OSError as error:
        raise QaFailure("procfs root-binding census is unavailable") from error
    for entry in entries:
        pid = int(entry.name)
        if pid in excluded:
            continue
        try:
            owner = entry.stat().st_uid
        except FileNotFoundError:
            continue
        except OSError as error:
            raise QaFailure("procfs process ownership census is unavailable") from error
        if owner != os.geteuid():
            continue
        try:
            snapshot = process_snapshot(pid)
        except ProcessDisappeared:
            continue
        if (
            snapshot.state == "Z"
            or snapshot.start_time_ticks < minimum_start_time_ticks
        ):
            continue
        try:
            observation = capture_root_binding_observation(
                pid, root, expected_environment
            )
        except ProcessDisappeared:
            continue
        except QaFailure:
            if pid in strict_candidates:
                raise
            continue
        if observation is not None:
            observations.append(observation)
    return tuple(observations)


def stable_root_binding_census(
    root: Path,
    expected_environment: Mapping[str, str],
    *,
    excluded_pids: Iterable[int] = (),
    minimum_start_time_ticks: Optional[int] = None,
    strict_candidate_pids: Iterable[int] = (),
) -> Tuple[RootBindingObservation, ...]:
    excluded = {os.getpid(), *ancestor_pids(os.getpid()), *excluded_pids}
    if minimum_start_time_ticks is None:
        minimum_start_time_ticks = process_snapshot(os.getpid()).start_time_ticks
    for _attempt in range(20):
        first = _root_binding_census_once(
            root,
            expected_environment,
            excluded,
            minimum_start_time_ticks,
            strict_candidate_pids,
        )
        time.sleep(0.01)
        second = _root_binding_census_once(
            root,
            expected_environment,
            excluded,
            minimum_start_time_ticks,
            strict_candidate_pids,
        )
        if first == second:
            return second
    raise QaFailure("procfs root-binding census did not stabilize")


def _decode_mountinfo_path(raw: bytes) -> str:
    decoded = bytearray()
    index = 0
    while index < len(raw):
        if raw[index] != 0x5C:
            decoded.append(raw[index])
            index += 1
            continue
        if index + 3 >= len(raw):
            raise QaFailure("mountinfo contains a truncated path escape")
        escaped = raw[index + 1 : index + 4]
        if any(byte < ord("0") or byte > ord("7") for byte in escaped):
            raise QaFailure("mountinfo contains a malformed path escape")
        value = int(escaped.decode("ascii"), 8)
        if value not in {0o11, 0o12, 0o40, 0o134}:
            raise QaFailure("mountinfo contains a noncanonical path escape")
        decoded.append(value)
        index += 4
    if b"\0" in decoded:
        raise QaFailure("mountinfo contains a NUL path")
    return os.fsdecode(bytes(decoded))


def parse_mountinfo(encoded: bytes) -> Tuple[MountInfoRecord, ...]:
    if len(encoded) > MOUNTINFO_MAX_BYTES:
        raise QaFailure("mountinfo exceeds its byte bound")
    if encoded and not encoded.endswith(b"\n"):
        raise QaFailure("mountinfo ends with an incomplete record")
    lines = encoded.splitlines()
    if len(lines) > MOUNTINFO_MAX_LINES:
        raise QaFailure("mountinfo exceeds its record bound")
    records = []
    for line in lines:
        if not line or len(line) > MOUNTINFO_MAX_LINE_BYTES:
            raise QaFailure("mountinfo contains an empty or oversized record")
        fields = line.split(b" ")
        if any(not field for field in fields) or fields.count(b"-") != 1:
            raise QaFailure("mountinfo contains malformed field boundaries")
        separator = fields.index(b"-")
        before = fields[:separator]
        after = fields[separator + 1 :]
        if len(before) < 6 or len(after) != 3:
            raise QaFailure("mountinfo contains an invalid record schema")
        try:
            mount_id = int(before[0].decode("ascii"))
            parent_id = int(before[1].decode("ascii"))
            major_minor = before[2].decode("ascii")
            mount_options = before[5].decode("ascii")
            optional_fields = tuple(
                field.decode("ascii") for field in before[6:]
            )
            filesystem_type = after[0].decode("ascii")
            mount_source = os.fsdecode(after[1])
            super_options = after[2].decode("ascii")
        except (UnicodeError, ValueError) as error:
            raise QaFailure("mountinfo contains an invalid scalar field") from error
        if (
            mount_id <= 0
            or parent_id < 0
            or re.fullmatch(r"[0-9]+:[0-9]+", major_minor) is None
        ):
            raise QaFailure("mountinfo contains invalid mount identity metadata")
        root = _decode_mountinfo_path(before[3])
        mount_point = _decode_mountinfo_path(before[4])
        if not root or not mount_point.startswith(os.sep):
            raise QaFailure("mountinfo contains an invalid root or mount path")
        records.append(
            MountInfoRecord(
                mount_id=mount_id,
                parent_id=parent_id,
                major_minor=major_minor,
                root=root,
                mount_point=mount_point,
                mount_options=mount_options,
                optional_fields=optional_fields,
                filesystem_type=filesystem_type,
                mount_source=mount_source,
                super_options=super_options,
            )
        )
    if len({record.mount_id for record in records}) != len(records):
        raise QaFailure("mountinfo repeats a mount identity")
    return tuple(records)


def read_mountinfo(path: Path = Path("/proc/self/mountinfo")) -> bytes:
    descriptor = -1
    chunks = bytearray()
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_BINARY", 0),
        )
        while True:
            chunk = os.read(
                descriptor,
                min(64 * 1024, MOUNTINFO_MAX_BYTES + 1 - len(chunks)),
            )
            if not chunk:
                break
            chunks.extend(chunk)
            if len(chunks) > MOUNTINFO_MAX_BYTES:
                raise QaFailure("mountinfo exceeds its byte bound")
    except OSError as error:
        raise QaFailure("mountinfo is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return bytes(chunks)


def root_mounts(root: Path) -> Tuple[MountInfoRecord, ...]:
    root_path = os.path.abspath(os.fspath(root))
    matches = []
    for record in parse_mountinfo(read_mountinfo()):
        try:
            within = os.path.commonpath((record.mount_point, root_path)) == root_path
        except ValueError as error:
            raise QaFailure("mountinfo path comparison failed") from error
        if within:
            matches.append(record)
    return tuple(sorted(matches, key=lambda record: record.mount_id))


def wait_for_no_root_bindings(
    root: Path,
    expected_environment: Mapping[str, str],
    timeout: float,
) -> None:
    deadline = time.monotonic() + timeout
    runner_started = process_snapshot(os.getpid()).start_time_ticks
    while True:
        table = process_table()
        strict_candidates = {
            snapshot.pid
            for snapshot in table.values()
            if snapshot.parent_pid == os.getpid()
            and snapshot.start_time_ticks >= runner_started
        }
        if not stable_root_binding_census(
            root,
            expected_environment,
            strict_candidate_pids=strict_candidates,
        ):
            return
        if time.monotonic() >= deadline:
            raise QaFailure("root-bound process did not exit after infrastructure stop")
        time.sleep(0.05)


def wait_for_no_root_mounts(root: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        if not root_mounts(root):
            return
        if time.monotonic() >= deadline:
            raise QaFailure("isolated root retains a mount after infrastructure stop")
        time.sleep(0.05)


def _dead_portal_mount_is_exact(root: Path, record: MountInfoRecord) -> bool:
    expected_mountpoint = root / "runtime" / "doc"
    if (
        record.mount_point != str(expected_mountpoint)
        or record.root != "/"
        or record.filesystem_type != "fuse.portal"
        or record.mount_source != "portal"
    ):
        return False
    try:
        expected_mountpoint.lstat()
    except OSError as error:
        return error.errno == errno.ENOTCONN
    return False


def unmount_exact_dead_failure_portal(
    root: Path, records: Sequence[MountInfoRecord]
) -> None:
    if len(records) != 1 or not _dead_portal_mount_is_exact(root, records[0]):
        raise QaFailure("failure cleanup encountered an unknown or live root mount")
    helper_seal = capture_physical_file_seal(
        PORTAL_UNMOUNT_HELPER,
        "failure cleanup fusermount3 helper",
        require_posix_executable=True,
    )
    if (
        helper_seal.metadata.st_uid != 0
        or stat.S_IMODE(helper_seal.metadata.st_mode) & stat.S_ISUID == 0
    ):
        raise QaFailure("failure cleanup fusermount3 helper is not root-owned setuid")
    run_checked(
        [str(PORTAL_UNMOUNT_HELPER), "-u", records[0].mount_point],
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
    )
    verify_physical_file_seal(
        PORTAL_UNMOUNT_HELPER,
        helper_seal,
        "failure cleanup fusermount3 helper",
        require_posix_executable=True,
    )
    wait_for_no_root_mounts(root, 5)


def capture_process_identity(
    pid: int,
    role: str,
    expected_environment: Mapping[str, str],
    *,
    expected_executable: Optional[Tuple[Path, PhysicalFileSeal]] = None,
    executable_name: Optional[str] = None,
    required_argument: Optional[str] = None,
) -> Dict[str, object]:
    state, parent_pid, process_group_id, session_id, start_time_ticks = (
        process_stat_fields(pid)
    )
    if state == "Z":
        raise QaFailure("cannot bind a zombie application process")
    command = process_cmdline(pid)
    if not command:
        raise QaFailure("application process command line is unavailable")
    if required_argument is not None and required_argument not in command:
        raise QaFailure("application process is not bound to the isolated profile")
    try:
        executable_path = (Path("/proc") / str(pid) / "exe").resolve(strict=True)
    except OSError as error:
        raise QaFailure("application process executable is unavailable") from error
    if executable_name is not None and executable_path.name != executable_name:
        raise QaFailure("application process executable has the wrong identity")
    executable_seal = capture_physical_file_seal(
        executable_path,
        "application process executable " + role,
        require_posix_executable=True,
    )
    if expected_executable is not None:
        expected_path, expected_seal = expected_executable
        if executable_path != expected_path or _metadata_signature(
            executable_seal.metadata
        ) != _metadata_signature(expected_seal.metadata) or executable_seal.sha256 != expected_seal.sha256:
            raise QaFailure("application process does not execute the sealed binary")
    command_bytes = b"\0".join(part.encode("utf-8") for part in command)
    return {
        "role": role,
        "pid": pid,
        "parentPid": parent_pid,
        "processGroupId": process_group_id,
        "sessionId": session_id,
        "startTimeTicks": start_time_ticks,
        "commandSha256": sha256_bytes(command_bytes),
        "environmentBindingSha256": process_environment_binding(
            pid, expected_environment
        ),
        "isolatedEnvironmentBound": True,
        "executablePath": str(executable_path),
        "executableSeal": seal_record(role, executable_seal),
    }


def process_identity_alive(identity: Mapping[str, object]) -> bool:
    pid = identity.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 1:
        raise QaFailure("recorded process identity has an invalid PID")
    try:
        state, _parent, group, session, started = process_stat_fields(pid)
    except QaFailure:
        return False
    if state == "Z":
        return False
    seal = identity.get("executableSeal")
    if not isinstance(seal, dict):
        raise QaFailure("recorded process identity omits its executable seal")
    try:
        opened = (Path("/proc") / str(pid) / "exe").stat()
    except OSError:
        return False
    return (
        started == identity.get("startTimeTicks")
        and group == identity.get("processGroupId")
        and session == identity.get("sessionId")
        and opened.st_dev == seal.get("device")
        and opened.st_ino == seal.get("inode")
    )


def capture_application_identities(
    main_pid: int,
    sublime_binary: Path,
    sublime_seal: PhysicalFileSeal,
    plugin_host: Path,
    plugin_host_seal: PhysicalFileSeal,
    profile: Path,
    sidecar: Path,
    sidecar_seal: PhysicalFileSeal,
    expected_environment: Mapping[str, str],
) -> List[Dict[str, object]]:
    hosts = command_pids("plugin_host-3.8", str(profile))
    sidecars = packaged_sidecar_pids(sidecar, sidecar_seal)
    if len(hosts) != 1 or len(sidecars) != 1:
        raise QaFailure("restart checkpoint requires one plugin host and one sidecar")
    identities = [
        capture_process_identity(
            main_pid,
            "sublime-main",
            expected_environment,
            expected_executable=(sublime_binary, sublime_seal),
        ),
        capture_process_identity(
            hosts[0],
            "plugin-host-3.8",
            expected_environment,
            expected_executable=(plugin_host, plugin_host_seal),
            executable_name="plugin_host-3.8",
            required_argument=str(profile),
        ),
        capture_process_identity(
            sidecars[0],
            "packaged-inexd",
            expected_environment,
            expected_executable=(sidecar, sidecar_seal),
        ),
    ]
    sessions = {identity["sessionId"] for identity in identities}
    if len(sessions) != 1:
        raise QaFailure("application process identities do not share one launch session")
    return identities


def session_process_pids(session_id: int) -> List[int]:
    matches: List[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            state, _parent, _group, observed_session, _started = process_stat_fields(pid)
        except QaFailure:
            continue
        if state != "Z" and observed_session == session_id:
            matches.append(pid)
    return sorted(matches)


def process_table() -> Dict[int, ProcessSnapshot]:
    observed: Dict[int, ProcessSnapshot] = {}
    try:
        entries = list(Path("/proc").iterdir())
    except OSError as error:
        raise QaFailure("procfs process table is unavailable") from error
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        try:
            snapshot = process_snapshot(pid)
        except QaFailure:
            continue
        if snapshot.state != "Z":
            observed[pid] = snapshot
    return observed


def _identity_snapshot(identity: Mapping[str, object]) -> ProcessSnapshot:
    values = {
        "pid": identity.get("pid"),
        "parent_pid": identity.get("parentPid"),
        "process_group_id": identity.get("processGroupId"),
        "session_id": identity.get("sessionId"),
        "start_time_ticks": identity.get("startTimeTicks"),
    }
    if any(
        not isinstance(value, int) or isinstance(value, bool)
        for value in values.values()
    ):
        raise QaFailure("recorded application identity is incomplete")
    return ProcessSnapshot(
        pid=values["pid"],
        state=process_snapshot(values["pid"]).state,
        parent_pid=values["parent_pid"],
        process_group_id=values["process_group_id"],
        session_id=values["session_id"],
        start_time_ticks=values["start_time_ticks"],
    )


def _descendant_closure(
    table: Mapping[int, ProcessSnapshot], seeds: Iterable[int]
) -> set:
    closure = set(seeds)
    while True:
        added = {
            pid
            for pid, snapshot in table.items()
            if snapshot.parent_pid in closure and pid not in closure
        }
        if not added:
            return closure
        closure.update(added)


def _launch_closure_snapshots(
    table: Mapping[int, ProcessSnapshot],
    session_id: int,
    adopted_root_bound_pids: Iterable[int],
) -> Dict[int, ProcessSnapshot]:
    seeds = {
        pid for pid, snapshot in table.items() if snapshot.session_id == session_id
    }
    seeds.update(pid for pid in adopted_root_bound_pids if pid in table)
    closure = _descendant_closure(table, seeds)
    return {pid: table[pid] for pid in sorted(closure) if pid in table}


def capture_stable_launch_closure(
    identities: Sequence[Mapping[str, object]],
    launcher: subprocess.Popen,
    root: Path,
    expected_environment: Mapping[str, str],
    excluded_infrastructure_pids: Iterable[int],
) -> Tuple[List[StableProcessHandle], ProcessSnapshot]:
    if len(identities) != 3 or any(
        not process_identity_alive(identity) for identity in identities
    ):
        raise QaFailure("application process identity changed before closure capture")
    sessions = {identity.get("sessionId") for identity in identities}
    if len(sessions) != 1:
        raise QaFailure("application process closure session is ambiguous")
    session_id = next(iter(sessions))
    if (
        not isinstance(session_id, int)
        or isinstance(session_id, bool)
        or session_id <= 1
        or session_id == os.getsid(0)
        or launcher.poll() is not None
    ):
        raise QaFailure("application launcher is outside the verified closure")
    launcher_snapshot = process_snapshot(launcher.pid)
    if launcher_snapshot.session_id != session_id:
        raise QaFailure("application launcher escaped its verified session")
    required = {
        snapshot.pid: snapshot for snapshot in map(_identity_snapshot, identities)
    }
    required[launcher_snapshot.pid] = launcher_snapshot
    infrastructure = set(excluded_infrastructure_pids)
    for _attempt in range(20):
        first_table = process_table()
        first_session_closure = _launch_closure_snapshots(
            first_table, session_id, ()
        )
        first_strict_candidates = set(first_session_closure) | {
            snapshot.pid
            for snapshot in first_table.values()
            if snapshot.parent_pid == os.getpid()
            and snapshot.start_time_ticks >= launcher_snapshot.start_time_ticks
            and snapshot.pid not in infrastructure
        }
        first_bindings = stable_root_binding_census(
            root,
            expected_environment,
            excluded_pids=infrastructure,
            strict_candidate_pids=first_strict_candidates,
        )
        adopted = {
            observation.snapshot.pid
            for observation in first_bindings
            if observation.snapshot.parent_pid == os.getpid()
            and observation.snapshot.start_time_ticks
            >= launcher_snapshot.start_time_ticks
        }
        first = _launch_closure_snapshots(first_table, session_id, adopted)
        if any(first.get(pid) != snapshot for pid, snapshot in required.items()):
            raise QaFailure("required application role escaped the launch closure")
        handles: List[StableProcessHandle] = []
        try:
            handles = [
                open_stable_process(pid, snapshot)
                for pid, snapshot in sorted(first.items())
            ]
            second_table = process_table()
            second_session_closure = _launch_closure_snapshots(
                second_table, session_id, ()
            )
            second_strict_candidates = set(second_session_closure) | {
                snapshot.pid
                for snapshot in second_table.values()
                if snapshot.parent_pid == os.getpid()
                and snapshot.start_time_ticks >= launcher_snapshot.start_time_ticks
                and snapshot.pid not in infrastructure
            }
            second_bindings = stable_root_binding_census(
                root,
                expected_environment,
                excluded_pids=infrastructure,
                strict_candidate_pids=second_strict_candidates,
            )
            adopted_second = {
                observation.snapshot.pid
                for observation in second_bindings
                if observation.snapshot.parent_pid == os.getpid()
                and observation.snapshot.start_time_ticks
                >= launcher_snapshot.start_time_ticks
            }
            second = _launch_closure_snapshots(
                second_table, session_id, adopted_second
            )
            if first == second and all(stable_process_alive(handle) for handle in handles):
                return handles, launcher_snapshot
        except QaFailure:
            pass
        close_process_handles(handles)
        time.sleep(0.05)
    raise QaFailure("application launch closure did not stabilize")


def _reap_known_subreaper_children(
    handles: Sequence[StableProcessHandle], launcher_pid: int
) -> None:
    for handle in handles:
        if handle.snapshot.pid == launcher_pid:
            continue
        try:
            os.waitpid(handle.snapshot.pid, os.WNOHANG)
        except ChildProcessError:
            pass


def kill_verified_application_session(
    identities: Sequence[Mapping[str, object]],
    launcher: subprocess.Popen,
    root: Path,
    expected_environment: Mapping[str, str],
    excluded_infrastructure_pids: Iterable[int],
) -> int:
    handles, launcher_snapshot = capture_stable_launch_closure(
        identities,
        launcher,
        root,
        expected_environment,
        excluded_infrastructure_pids,
    )
    all_handles = list(handles)
    infrastructure = set(excluded_infrastructure_pids)
    try:
        for handle in sorted(
            handles, key=lambda item: item.snapshot.pid, reverse=True
        ):
            signal_stable_process(handle, signal.SIGKILL)
        wait_for_stable_processes(handles, "old application closure to die", 5)
        if any(process_identity_alive(identity) for identity in identities):
            raise QaFailure("old application role survived pidfd SIGKILL")
        try:
            launcher.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise QaFailure("SIGKILL launcher did not terminate") from error
        _reap_known_subreaper_children(handles, launcher_snapshot.pid)

        # A process which daemonized while the first closure was being killed
        # is reparented to this confirmed subreaper. Capture and kill only that
        # parent-bound identity; an unrelated root-bound process is never
        # signalled and instead makes the evidence fail closed below.
        for _attempt in range(20):
            table = process_table()
            adopted = [
                snapshot
                for snapshot in table.values()
                if snapshot.parent_pid == os.getpid()
                and snapshot.start_time_ticks >= launcher_snapshot.start_time_ticks
                and snapshot.pid not in infrastructure
                and snapshot.pid != os.getpid()
            ]
            if not adopted:
                break
            sweep_handles = [
                open_stable_process(snapshot.pid, snapshot)
                for snapshot in sorted(adopted, key=lambda item: item.pid)
            ]
            all_handles.extend(sweep_handles)
            for handle in sweep_handles:
                signal_stable_process(handle, signal.SIGKILL)
            wait_for_stable_processes(
                sweep_handles, "subreaper-adopted application descendants", 5
            )
            _reap_known_subreaper_children(sweep_handles, launcher_snapshot.pid)
        else:
            raise QaFailure("subreaper-adopted application descendants did not drain")

        return len(all_handles)
    finally:
        close_process_handles(all_handles)


def sublime_multiinstance_pids(binary: Path) -> List[int]:
    matches: List[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        command = process_cmdline(int(entry.name))
        if command[:2] == [str(binary), "--multiinstance"]:
            matches.append(int(entry.name))
    return matches


def command_pids(executable_name: str, required_argument: str) -> List[int]:
    matches: List[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        command = process_cmdline(int(entry.name))
        if (
            command
            and Path(command[0]).name == executable_name
            and required_argument in command
        ):
            matches.append(int(entry.name))
    return matches


def ancestor_pids(pid: int) -> List[int]:
    ancestors: List[int] = []
    current = pid
    while current > 1:
        try:
            fields = (Path("/proc") / str(current) / "stat").read_text().split()
            parent = int(fields[3])
        except (OSError, ValueError, IndexError, UnicodeError):
            break
        if parent <= 1 or parent in ancestors:
            break
        ancestors.append(parent)
        current = parent
    return ancestors


def terminate_process_snapshot(
    expected: ProcessSnapshot, grace: float = 2.0
) -> None:
    handle: Optional[StableProcessHandle] = None
    try:
        try:
            handle = open_stable_process(expected.pid, expected)
        except QaFailure:
            if not (Path("/proc") / str(expected.pid)).exists():
                return
            raise
        signal_stable_process(handle, signal.SIGTERM)
        try:
            wait_for_stable_processes([handle], "process SIGTERM", grace)
            return
        except QaFailure:
            pass
        signal_stable_process(handle, signal.SIGKILL)
        wait_for_stable_processes([handle], "process SIGKILL", 5)
    finally:
        if handle is not None:
            close_process_handles([handle])


def terminate_pid(pid: Optional[int], grace: float = 2.0) -> None:
    if pid is None:
        return
    try:
        snapshot = process_snapshot(pid)
    except QaFailure:
        return
    terminate_process_snapshot(snapshot, grace)


def reap_subreaper_process(expected: ProcessSnapshot) -> None:
    try:
        os.waitpid(expected.pid, os.WNOHANG)
    except ChildProcessError:
        pass


def _capture_cleanup_closure(
    main_pid: Optional[int], launcher: Optional[subprocess.Popen], root: Path
) -> List[StableProcessHandle]:
    expected_environment = expected_root_environment(root)
    for _attempt in range(20):
        table = process_table()
        seeds = set()
        if launcher is not None and launcher.poll() is None:
            launcher_snapshot = table.get(launcher.pid)
            if launcher_snapshot is None:
                time.sleep(0.02)
                continue
            seeds.update(
                pid
                for pid, snapshot in table.items()
                if snapshot.session_id == launcher_snapshot.session_id
            )
        if main_pid is not None and main_pid in table:
            try:
                binding = capture_root_binding_observation(
                    main_pid, root, expected_environment
                )
            except ProcessDisappeared:
                time.sleep(0.02)
                continue
            if binding is None:
                raise QaFailure("cleanup main PID is not bound to the isolated root")
            seeds.add(main_pid)
        if not seeds:
            return []
        closure = _descendant_closure(table, seeds)
        snapshots = {pid: table[pid] for pid in closure if pid in table}
        handles: List[StableProcessHandle] = []
        try:
            handles = [
                open_stable_process(pid, snapshot)
                for pid, snapshot in sorted(snapshots.items())
            ]
            table_after = process_table()
            if all(table_after.get(pid) == snapshot for pid, snapshot in snapshots.items()):
                return handles
        except QaFailure:
            pass
        close_process_handles(handles)
        time.sleep(0.02)
    raise QaFailure("cleanup application process closure did not stabilize")


def terminate_sublime_tree(
    main_pid: Optional[int], launcher: Optional[subprocess.Popen], root: Path
) -> None:
    handles = _capture_cleanup_closure(main_pid, launcher, root)
    try:
        for handle in sorted(
            handles, key=lambda item: item.snapshot.pid, reverse=True
        ):
            signal_stable_process(handle, signal.SIGTERM)
        try:
            wait_for_stable_processes(handles, "isolated Sublime SIGTERM", 0.5)
        except QaFailure:
            for handle in handles:
                signal_stable_process(handle, signal.SIGKILL)
            wait_for_stable_processes(handles, "isolated Sublime SIGKILL", 5)
    finally:
        close_process_handles(handles)
    if launcher is not None:
        try:
            launcher.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise QaFailure("isolated Sublime launcher did not terminate") from error


def read_new_reports(path: Path, offset: int) -> Tuple[int, List[Dict[str, object]]]:
    if not path.exists():
        return offset, []
    try:
        metadata = path.lstat()
    except OSError as error:
        raise QaFailure("QA helper report identity is unavailable") from error
    if (
        release_lifecycle.is_link_like(path, metadata)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > HELPER_REPORT_MAX_BYTES
        or offset < 0
        or offset > metadata.st_size
    ):
        raise QaFailure("QA helper report violates its physical or size bounds")
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read(HELPER_REPORT_MAX_BYTES - offset + 1)
        new_offset = stream.tell()
    if new_offset > HELPER_REPORT_MAX_BYTES:
        raise QaFailure("QA helper report exceeded its byte ceiling")
    if data and not data.endswith(b"\n"):
        return offset, []
    records: List[Dict[str, object]] = []
    for line in data.splitlines():
        if not line:
            raise QaFailure("QA helper report contains an empty record")
        if len(line) > HELPER_REPORT_MAX_LINE_BYTES:
            raise QaFailure("QA helper report contains an oversized record")
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as error:
            raise QaFailure("QA helper report contains malformed JSON") from error
        if not isinstance(value, dict) or not isinstance(value.get("event"), str):
            raise QaFailure("QA helper report contains an invalid record")
        records.append(value)
        if len(records) > HELPER_REPORT_MAX_RECORDS:
            raise QaFailure("QA helper report exceeded its record ceiling")
    return new_offset, records


def append_report(path: Path, value: Dict[str, object]) -> None:
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)


def validate_restart_checkpoint_state(
    path: Path,
    helper_records: Sequence[Mapping[str, object]],
    content_tokens: Sequence[str],
) -> Dict[str, object]:
    seal = capture_physical_file_seal(path, "restart checkpoint state")
    if seal.metadata.st_size > 16 * 1024:
        raise QaFailure("restart checkpoint state exceeds its size bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QaFailure("restart checkpoint state is malformed") from error
    expected_keys = {
        "schema_version",
        "phase",
        "logical_path",
        "opened_byte_count",
        "opened_content_sha256",
        "saved_byte_count",
        "saved_content_sha256",
        "token_fingerprints",
    }
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise QaFailure("restart checkpoint state has an invalid schema")
    observations = {
        record.get("event"): record
        for record in helper_records
        if record.get("event")
        in {"opened", "saved", "full_application_restart_ready"}
    }
    opened = observations.get("opened")
    saved = observations.get("saved")
    ready = observations.get("full_application_restart_ready")
    canonical_bytes = (json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    if path.read_bytes() != canonical_bytes or seal.sha256 != sha256_bytes(canonical_bytes):
        raise QaFailure("restart checkpoint state is not canonical or seal-bound")
    if (
        value.get("schema_version") != 1
        or value.get("phase") != "await_full_application_restart"
        or value.get("logical_path") != "qa.md"
        or not isinstance(opened, Mapping)
        or not isinstance(saved, Mapping)
        or not isinstance(ready, Mapping)
        or value.get("opened_byte_count") != opened.get("byte_count")
        or value.get("opened_content_sha256") != opened.get("content_sha256")
        or value.get("saved_byte_count") != saved.get("byte_count")
        or value.get("saved_content_sha256") != saved.get("content_sha256")
    ):
        raise QaFailure("restart checkpoint state is not bound to helper observations")
    token_fingerprints = value.get("token_fingerprints")
    expected_tokens = sorted(
        (
            len(token.encode("utf-8")),
            sha256_bytes(token.encode("utf-8")),
        )
        for token in content_tokens
    )
    if (
        not isinstance(token_fingerprints, list)
        or len(token_fingerprints) != len(expected_tokens)
    ):
        raise QaFailure("restart checkpoint state omits token fingerprints")
    observed_tokens: List[Tuple[int, str]] = []
    for token in token_fingerprints:
        if (
            not isinstance(token, dict)
            or set(token) != {"byte_count", "content_sha256"}
            or not isinstance(token.get("byte_count"), int)
            or isinstance(token.get("byte_count"), bool)
            or token["byte_count"] <= 0
            or not _valid_digest(token.get("content_sha256"))
        ):
            raise QaFailure("restart checkpoint state has an invalid token fingerprint")
        observed_tokens.append((token["byte_count"], token["content_sha256"]))
    if observed_tokens != expected_tokens:
        raise QaFailure("restart checkpoint token fingerprints are not exact")
    token_fingerprint_set_sha256 = token_fingerprint_set_digest(observed_tokens)
    if (
        ready.get("token_fingerprint_count") != len(observed_tokens)
        or ready.get("token_fingerprint_set_sha256")
        != token_fingerprint_set_sha256
    ):
        raise QaFailure("restart checkpoint token fingerprints are not helper-bound")
    return {
        "schemaVersion": value["schema_version"],
        "phase": value["phase"],
        "logicalPath": value["logical_path"],
        "opened": {
            "byteCount": value["opened_byte_count"],
            "contentSha256": value["opened_content_sha256"],
        },
        "saved": {
            "byteCount": value["saved_byte_count"],
            "contentSha256": value["saved_content_sha256"],
        },
        "tokenFingerprints": [
            {"byteCount": byte_count, "contentSha256": digest}
            for byte_count, digest in observed_tokens
        ],
        "tokenFingerprintSetSha256": token_fingerprint_set_sha256,
        "plaintextFieldsAbsent": True,
    }


def encoded_needles(tokens: Iterable[str]) -> List[Tuple[str, bytes]]:
    needles: List[Tuple[str, bytes]] = []
    for token in tokens:
        raw = token.encode("utf-8")
        standard_base64 = base64.b64encode(raw)
        url_base64 = base64.urlsafe_b64encode(raw)
        needles.extend(
            [
                ("utf-8", raw),
                ("utf-16le", token.encode("utf-16le")),
                ("utf-16be", token.encode("utf-16be")),
                ("hex-lower", raw.hex().encode("ascii")),
                ("base64-standard", standard_base64),
                ("base64-standard-unpadded", standard_base64.rstrip(b"=")),
                ("base64url", url_base64),
                ("base64url-unpadded", url_base64.rstrip(b"=")),
            ]
        )
    return sorted(set(needles))


def scan_for_tokens(roots: Iterable[Path], tokens: Sequence[str]) -> List[str]:
    needles = encoded_needles(tokens)
    if not needles:
        raise QaFailure("residue scan requires at least one nonempty token")
    hits: List[str] = []
    for root in roots:
        try:
            root_metadata = root.lstat()
        except OSError as error:
            raise QaFailure("residue scan root is unavailable") from error
        if release_lifecycle.is_link_like(root, root_metadata):
            raise QaFailure("residue scan root is link-like")
        pending = [root]
        while pending:
            path = pending.pop()
            try:
                info = path.lstat()
                relative_parts = (
                    () if path == root else path.relative_to(root).parts
                )
            except (OSError, ValueError) as error:
                raise QaFailure("residue scan traversal failed closed") from error
            for component in relative_parts:
                component_bytes = component.encode("utf-8", "strict")
                found = next(
                    (label for label, needle in needles if needle in component_bytes),
                    None,
                )
                if found is not None:
                    hits.append(str(path) + ":path-" + found)
                    break
            if stat.S_ISDIR(info.st_mode):
                if release_lifecycle.is_link_like(path, info):
                    raise QaFailure("residue scan encountered a link-like directory")
                try:
                    with os.scandir(path) as entries:
                        children = sorted(
                            (Path(entry.path) for entry in entries),
                            key=lambda child: child.name,
                            reverse=True,
                        )
                except OSError as error:
                    raise QaFailure("residue scan directory read failed closed") from error
                pending.extend(children)
                continue
            if (
                release_lifecycle.is_link_like(path, info)
                or not stat.S_ISREG(info.st_mode)
            ):
                raise QaFailure("residue scan encountered a non-regular entry")
            try:
                overlap = max(len(needle) for _label, needle in needles) - 1
                tail = b""
                descriptor = os.open(
                    path,
                    os.O_RDONLY
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_BINARY", 0),
                )
                try:
                    opened = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(opened.st_mode)
                        or not os.path.samestat(info, opened)
                    ):
                        raise QaFailure("residue scan file changed while opening")
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        window = tail + chunk
                        found = next((label for label, needle in needles if needle in window), None)
                        if found is not None:
                            hits.append(str(path) + ":" + found)
                            break
                        tail = window[-overlap:] if overlap > 0 else b""
                    after = path.lstat()
                    if not os.path.samestat(opened, after):
                        raise QaFailure("residue scan file changed while reading")
                finally:
                    os.close(descriptor)
            except OSError as error:
                raise QaFailure("residue scan file read failed closed") from error
    return sorted(set(hits))


def assert_ciphertext(vault: Path, tokens: Sequence[str]) -> None:
    documents = list(vault.rglob("*.md.enc"))
    if len(documents) != 1:
        raise QaFailure("expected exactly one encrypted Markdown document")
    data = documents[0].read_bytes()
    if not data.startswith(b"EDRY"):
        raise QaFailure("vault document does not start with EDRY")
    for token in tokens:
        if token.encode("utf-8") in data:
            raise QaFailure("vault document contains a plaintext QA token")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def _path_is_within(candidate: Path, parent: Path) -> bool:
    try:
        return os.path.commonpath(
            (os.path.abspath(os.fspath(candidate)), os.path.abspath(os.fspath(parent)))
        ) == os.path.abspath(os.fspath(parent))
    except ValueError:
        return False


def resolve_artifact_output_path(
    output: Path, artifact_directory: Path, root_candidate: Optional[Path]
) -> Path:
    try:
        portable_archive_key(output.name)
        artifact = artifact_directory.resolve(strict=True)
        parent = output.parent.resolve(strict=True)
    except (OSError, ReleaseError) as error:
        raise QaFailure("artifact report output or input path is unsafe") from error
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise QaFailure("artifact report output parent is unavailable") from error
    if (
        release_lifecycle.is_link_like(parent, parent_metadata)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or (os.name != "nt" and stat.S_IMODE(parent_metadata.st_mode) != 0o700)
        or not output.name
    ):
        raise QaFailure("artifact report output parent is unsafe")
    resolved = parent / output.name
    forbidden = [artifact, REPOSITORY_ROOT.resolve(strict=True)]
    if root_candidate is not None:
        forbidden.append(root_candidate.absolute())
    if any(_path_is_within(resolved, root) for root in forbidden):
        raise QaFailure("artifact report output must be external to artifact, source, and root")
    try:
        resolved.lstat()
    except FileNotFoundError:
        return resolved
    except OSError as error:
        raise QaFailure("artifact report output path is unavailable") from error
    raise QaFailure("artifact report output path already exists")


def write_artifact_report(path: Path, encoded: bytes) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = -1
    created = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | binary,
            0o600,
        )
        created = True
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(descriptor)
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
    except OSError as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise QaFailure("artifact report could not be written with create-new semantics") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    seal = capture_physical_file_seal(path, "artifact report")
    if (
        seal.sha256 != sha256_bytes(encoded)
        or (os.name != "nt" and stat.S_IMODE(seal.metadata.st_mode) != 0o600)
    ):
        try:
            path.unlink()
        except OSError:
            pass
        raise QaFailure("artifact report identity or mode is invalid")


def report_not_covered(scenario: str, result: str) -> List[str]:
    values = list(COMMON_NOT_COVERED)
    if scenario == "normal":
        values.append("plugin-host-crash-and-application-restart-recovery-in-this-report")
    elif scenario == "plugin-host-crash":
        values.extend(
            [
                "normal-close-and-encrypted-crud-path-in-this-report",
                "full-application-restart-recovery-after-plugin-host-loss",
            ]
        )
        if result == "PASS_WITH_DOCUMENTED_BOUNDARY":
            values.append(
                "crash-time-plaintext-erasure-before-required-full-application-restart"
            )
    elif scenario == "full-application-kill-restart":
        values.extend(
            [
                "normal-close-and-encrypted-crud-path-in-this-report",
                "plugin-host-only-crash-boundary-in-this-report",
                "persistent-profile-matrix-beyond-one-full-application-kill-restart",
            ]
        )
    else:
        raise QaFailure("unknown Build 4200 scenario")
    return values


def scenario_event_sequence(scenario: str) -> Tuple[str, ...]:
    if scenario == "normal":
        return NORMAL_EVENT_SEQUENCE
    if scenario == "plugin-host-crash":
        return CRASH_EVENT_SEQUENCE
    if scenario == "full-application-kill-restart":
        return RESTART_EVENT_SEQUENCE
    raise QaFailure("unknown Build 4200 scenario")


def normalize_helper_records(
    records: Sequence[Mapping[str, object]], scenario: str
) -> List[Dict[str, object]]:
    expected_events = scenario_event_sequence(scenario)
    if tuple(record.get("event") for record in records) != expected_events:
        raise QaFailure("QA helper report has an unexpected successful event sequence")
    schemas = {
        "loaded": {"event", "time", "build", "gate_ok", "issue_count"},
        "unlock_dispatched": {"event", "time", "plugin_active", "in_progress"},
        "password_prompt_answered": {"event", "masked"},
        "ui": {"event", "time", "action"},
        "opened": {
            "event",
            "time",
            "scratch",
            "unnamed",
            "initial_ok",
            "initial_clean",
            "byte_count",
            "content_sha256",
        },
        "saved": {
            "event",
            "time",
            "persisted_shape",
            "scratch",
            "unnamed",
            "byte_count",
            "content_sha256",
        },
        "crud_folder_created": {"event", "time", "exists"},
        "crud_markdown_created": {
            "event",
            "time",
            "clean",
            "scratch",
            "unnamed",
            "empty",
        },
        "crud_markdown_renamed": {"event", "time", "clean"},
        "crud_markdown_deleted": {"event", "time", "absent"},
        "minimal_complete": {"event", "time", "managed_count", "crud_complete"},
        "complete": {"event", "time", "managed_count", "crud_complete"},
        "plugin_host_crash_ready": {
            "event",
            "time",
            "view_id",
            "byte_count",
            "content_sha256",
            "marker",
        },
        "plugin_host_dead_clipboard_checked": {
            "event",
            "byte_count",
            "content_sha256",
            "same_length_and_hash",
            "host_dead_plaintext_copyable",
            "clipboard_read_ok",
            "selection_channel",
        },
        "plugin_host_restart_required": {
            "event",
            "documented_platform_boundary",
        },
        "full_application_restart_ready": {
            "event",
            "time",
            "view_id",
            "logical_path",
            "byte_count",
            "content_sha256",
            "marker",
            "state_written",
            "token_fingerprint_count",
            "token_fingerprint_set_sha256",
        },
        "restart_loaded": {"event", "time", "build", "gate_ok", "issue_count"},
        "restart_preunlock_checked": {
            "event",
            "time",
            "view_count",
            "managed_count",
            "client_present",
            "session_active",
            "vault_id_present",
            "vault_path_present",
            "unlock_in_progress",
            "pending_plaintext_count",
            "handoff_count",
            "scrubbing_count",
            "fixed_scrub_ack_count",
            "orphan_scrub_blocked",
            "marker_count",
            "known_fingerprint_count",
            "token_window_match_count",
            "clean",
            "stable_duration_ms",
        },
        "restart_unlock_dispatched": {
            "event",
            "time",
            "plugin_active",
            "in_progress",
        },
        "restart_reopened": {
            "event",
            "time",
            "scratch",
            "unnamed",
            "clean",
            "marker",
            "session_active",
            "logical_path_matches",
            "fingerprint_matches",
            "byte_count",
            "content_sha256",
        },
        "restart_closed": {
            "event",
            "time",
            "managed_count",
            "view_absent",
            "normal_close",
        },
    }
    if scenario == "full-application-kill-restart":
        schemas["complete"] = {"event", "time", "restarted", "managed_count"}
    normalized: List[Dict[str, object]] = []
    for record in records:
        event = record.get("event")
        if not isinstance(event, str) or event not in schemas or set(record) != schemas[event]:
            raise QaFailure("QA helper report has an invalid event schema")
        if "time" in record:
            observed_time = record["time"]
            if (
                not isinstance(observed_time, (int, float))
                or isinstance(observed_time, bool)
                or observed_time < 0
            ):
                raise QaFailure("QA helper report has an invalid monotonic timestamp")
        normalized_record = {
            key: value for key, value in record.items() if key != "time"
        }
        if any(
            not isinstance(value, (bool, int, float, str)) and value is not None
            for value in normalized_record.values()
        ):
            raise QaFailure("QA helper report contains a non-scalar observation")
        normalized.append(normalized_record)

    by_event = {record["event"]: record for record in normalized if record["event"] != "ui"}
    if (
        by_event["loaded"].get("build") != BUILD
        or by_event["loaded"].get("gate_ok") is not True
        or by_event["loaded"].get("issue_count") != 0
        or by_event["unlock_dispatched"].get("plugin_active") is not True
        or by_event["unlock_dispatched"].get("in_progress") is not True
        or by_event["password_prompt_answered"].get("masked") is not True
        or by_event["opened"].get("scratch") is not True
        or by_event["opened"].get("unnamed") is not True
        or by_event["opened"].get("initial_ok") is not True
        or by_event["opened"].get("initial_clean") is not True
        or by_event["saved"].get("persisted_shape") is not True
        or by_event["saved"].get("scratch") is not True
        or by_event["saved"].get("unnamed") is not True
    ):
        raise QaFailure("QA helper report has a false core scenario observation")
    for name in ("opened", "saved"):
        observation = by_event[name]
        if (
            not isinstance(observation.get("byte_count"), int)
            or isinstance(observation.get("byte_count"), bool)
            or observation["byte_count"] <= 0
            or not _valid_digest(observation.get("content_sha256"))
        ):
            raise QaFailure("QA helper report has an invalid content fingerprint")

    ui_actions = [record["action"] for record in normalized if record["event"] == "ui"]
    if scenario == "normal":
        if ui_actions != [
            "select_tree",
            "crud_new_folder",
            "crud_new_markdown",
            "crud_rename",
            "crud_delete_confirm",
        ]:
            raise QaFailure("QA helper report has an invalid normal UI sequence")
        required_true = (
            ("crud_folder_created", "exists"),
            ("crud_markdown_created", "clean"),
            ("crud_markdown_created", "scratch"),
            ("crud_markdown_created", "unnamed"),
            ("crud_markdown_created", "empty"),
            ("crud_markdown_renamed", "clean"),
            ("crud_markdown_deleted", "absent"),
            ("minimal_complete", "crud_complete"),
            ("complete", "crud_complete"),
        )
        if any(by_event[event].get(field) is not True for event, field in required_true):
            raise QaFailure("QA helper report has a false normal CRUD observation")
        if by_event["minimal_complete"].get("managed_count") != 0 or by_event[
            "complete"
        ].get("managed_count") != 0:
            raise QaFailure("QA helper report retained a managed view at completion")
    elif scenario == "plugin-host-crash":
        if ui_actions != ["select_tree"]:
            raise QaFailure("QA helper report has an invalid crash UI sequence")
        ready = by_event["plugin_host_crash_ready"]
        clipboard = by_event["plugin_host_dead_clipboard_checked"]
        known_plaintext_fingerprints = {
            (by_event[name].get("byte_count"), by_event[name].get("content_sha256"))
            for name in ("opened", "saved")
        }
        if (
            ready.get("marker") is not True
            or not isinstance(ready.get("view_id"), int)
            or isinstance(ready.get("view_id"), bool)
            or ready["view_id"] <= 0
            or not isinstance(ready.get("byte_count"), int)
            or isinstance(ready.get("byte_count"), bool)
            or ready["byte_count"] <= 0
            or not _valid_digest(ready.get("content_sha256"))
            or (ready.get("byte_count"), ready.get("content_sha256"))
            != (
                by_event["saved"].get("byte_count"),
                by_event["saved"].get("content_sha256"),
            )
            or (clipboard.get("byte_count"), clipboard.get("content_sha256"))
            not in known_plaintext_fingerprints
            or clipboard.get("same_length_and_hash") is not True
            or clipboard.get("host_dead_plaintext_copyable") is not True
            or clipboard.get("clipboard_read_ok") is not True
            or clipboard.get("selection_channel") not in {"clipboard", "primary"}
            or by_event["plugin_host_restart_required"].get(
                "documented_platform_boundary"
            )
            is not True
        ):
            raise QaFailure("QA helper report has an invalid crash-boundary observation")
    else:
        if ui_actions != ["select_tree", "select_tree_after_restart"]:
            raise QaFailure("QA helper report has an invalid restart UI sequence")
        ready = by_event["full_application_restart_ready"]
        preunlock = by_event["restart_preunlock_checked"]
        reopened = by_event["restart_reopened"]
        closed = by_event["restart_closed"]
        if (
            ready.get("marker") is not True
            or ready.get("state_written") is not True
            or ready.get("logical_path") != "qa.md"
            or ready.get("token_fingerprint_count") != 2
            or not _valid_digest(ready.get("token_fingerprint_set_sha256"))
            or not isinstance(ready.get("view_id"), int)
            or isinstance(ready.get("view_id"), bool)
            or ready["view_id"] <= 0
            or (ready.get("byte_count"), ready.get("content_sha256"))
            != (
                by_event["saved"].get("byte_count"),
                by_event["saved"].get("content_sha256"),
            )
            or by_event["restart_loaded"].get("build") != BUILD
            or by_event["restart_loaded"].get("gate_ok") is not True
            or by_event["restart_loaded"].get("issue_count") != 0
            or preunlock.get("clean") is not True
            or preunlock.get("managed_count") != 0
            or preunlock.get("client_present") is not False
            or preunlock.get("session_active") is not False
            or preunlock.get("vault_id_present") is not False
            or preunlock.get("vault_path_present") is not False
            or preunlock.get("unlock_in_progress") is not False
            or preunlock.get("pending_plaintext_count") != 0
            or preunlock.get("handoff_count") != 0
            or preunlock.get("scrubbing_count") != 0
            or preunlock.get("fixed_scrub_ack_count") != 0
            or preunlock.get("orphan_scrub_blocked") is not False
            or preunlock.get("marker_count") != 0
            or preunlock.get("known_fingerprint_count") != 0
            or preunlock.get("token_window_match_count") != 0
            or preunlock.get("stable_duration_ms") != 2000
            or not isinstance(preunlock.get("view_count"), int)
            or isinstance(preunlock.get("view_count"), bool)
            or preunlock["view_count"] < 0
            or by_event["restart_unlock_dispatched"].get("plugin_active") is not True
            or by_event["restart_unlock_dispatched"].get("in_progress") is not True
            or any(
                reopened.get(field) is not True
                for field in (
                    "scratch",
                    "unnamed",
                    "clean",
                    "marker",
                    "session_active",
                    "logical_path_matches",
                    "fingerprint_matches",
                )
            )
            or (reopened.get("byte_count"), reopened.get("content_sha256"))
            != (
                by_event["saved"].get("byte_count"),
                by_event["saved"].get("content_sha256"),
            )
            or closed.get("managed_count") != 0
            or closed.get("view_absent") is not True
            or closed.get("normal_close") is not True
            or by_event["complete"].get("restarted") is not True
            or by_event["complete"].get("managed_count") != 0
        ):
            raise QaFailure("QA helper report has an invalid full-restart observation")
    return normalized


def _valid_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _validate_bound_package_manifest(
    value: object,
    *,
    kind: str,
    artifact_source: object,
    release_version: object,
    native_platform: object,
    expected_sha256: object,
) -> Dict[str, Dict[str, object]]:
    expected = {
        "rust": (
            "rust-binaries",
            "portable ZIP with bin/inex and bin/inexd",
            f"inex-{release_version}-{native_platform}/",
            f"inex-{release_version}-{native_platform}/PACKAGE-MANIFEST.json",
        ),
        "sublime": (
            "sublime-unpacked-package",
            "extract the Inex directory into the Sublime Text Packages directory",
            "Inex/",
            "Inex/PACKAGE-MANIFEST.json",
        ),
    }.get(kind)
    if expected is None:
        raise QaFailure("artifact report has an unknown package-manifest kind")
    package_name, install_format, prefix, manifest_name = expected
    if (
        not isinstance(value, dict)
        or set(value)
        != {
            "schemaVersion",
            "package",
            "platform",
            "version",
            "installFormat",
            "source",
            "files",
        }
        or value.get("schemaVersion") != 1
        or isinstance(value.get("schemaVersion"), bool)
        or value.get("package") != package_name
        or value.get("platform") != native_platform
        or value.get("version") != release_version
        or value.get("installFormat") != install_format
        or value.get("source") != artifact_source
        or not isinstance(value.get("files"), list)
        or not value["files"]
        or len(value["files"]) > 4096
    ):
        raise QaFailure("artifact report has an invalid bound package manifest")
    file_map: Dict[str, Dict[str, object]] = {}
    paths: List[str] = []
    for record in value["files"]:
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "sha256", "size"}
            or not isinstance(record.get("path"), str)
            or not isinstance(record.get("size"), int)
            or isinstance(record.get("size"), bool)
            or record["size"] < 0
            or not _valid_digest(record.get("sha256"))
        ):
            raise QaFailure("artifact report package manifest has invalid file metadata")
        path = str(record["path"])
        pure = PurePosixPath(path)
        if (
            not path.startswith(prefix)
            or path == manifest_name
            or pure.is_absolute()
            or pure.as_posix() != path
            or any(component in {"", ".", ".."} for component in pure.parts)
            or "\\" in path
            or path in file_map
        ):
            raise QaFailure("artifact report package manifest has an unsafe file path")
        paths.append(path)
        file_map[path] = record
    if paths != sorted(paths):
        raise QaFailure("artifact report package manifest files are not sorted")
    try:
        encoded = (
            json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise QaFailure("artifact report package manifest is not canonical JSON") from error
    if len(encoded) > 2 * 1024 * 1024 or sha256_bytes(encoded) != expected_sha256:
        raise QaFailure("artifact report package manifest digest differs from its audit")
    return file_map


def _validate_source(value: object, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"commit", "dirtySourceTree", "repository"}
        or value.get("dirtySourceTree") is not False
        or value.get("repository") != "https://github.com/JekYUlll/Inex"
        or not isinstance(value.get("commit"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value["commit"])
        is None
    ):
        raise QaFailure("artifact report has invalid " + label)


def _validate_seal_record(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "name",
        "device",
        "inode",
        "mode",
        "linkCount",
        "size",
        "mtimeNs",
        "ctimeNs",
        "sha256",
    }:
        raise QaFailure("artifact report has an invalid physical seal record")
    if (
        not isinstance(value.get("name"), str)
        or not value["name"]
        or value.get("linkCount") != 1
        or not _valid_digest(value.get("sha256"))
    ):
        raise QaFailure("artifact report has an invalid physical seal identity")
    for field in ("device", "inode", "mode", "size", "mtimeNs", "ctimeNs"):
        item = value.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item < 0:
            raise QaFailure("artifact report has invalid physical metadata")


def _validate_process_identity_record(value: object, role: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "role",
        "pid",
        "parentPid",
        "processGroupId",
        "sessionId",
        "startTimeTicks",
        "commandSha256",
        "environmentBindingSha256",
        "isolatedEnvironmentBound",
        "executablePath",
        "executableSeal",
    }:
        raise QaFailure("artifact report has an invalid process identity schema")
    if (
        value.get("role") != role
        or value.get("isolatedEnvironmentBound") is not True
        or not isinstance(value.get("executablePath"), str)
        or not os.path.isabs(str(value["executablePath"]))
        or not _valid_digest(value.get("commandSha256"))
        or not _valid_digest(value.get("environmentBindingSha256"))
    ):
        raise QaFailure("artifact report has an invalid process identity binding")
    for field, minimum in (
        ("pid", 2),
        ("parentPid", 0),
        ("processGroupId", 2),
        ("sessionId", 2),
        ("startTimeTicks", 1),
    ):
        item = value.get(field)
        if not isinstance(item, int) or isinstance(item, bool) or item < minimum:
            raise QaFailure("artifact report has invalid process identity metadata")
    _validate_seal_record(value.get("executableSeal"))
    if value["executableSeal"].get("name") != role:
        raise QaFailure("artifact report process executable seal has the wrong role")


def _same_sealed_file(left: Mapping[str, object], right: Mapping[str, object]) -> bool:
    return all(
        left.get(field) == right.get(field)
        for field in (
            "device",
            "inode",
            "mode",
            "linkCount",
            "size",
            "mtimeNs",
            "ctimeNs",
            "sha256",
        )
    )


def validate_artifact_report(report: Dict[str, object]) -> None:
    base_root_fields = {
        "schemaVersion",
        "reportType",
        "reportScope",
        "artifactSource",
        "harnessSource",
        "harnessFiles",
        "helperReport",
        "releaseSetAudit",
        "packageManifests",
        "releaseVersion",
        "nativePlatform",
        "scenario",
        "importProcess",
        "build4200",
        "artifactSetFiles",
        "materializedMembers",
        "installedInexTree",
        "packagedExecutables",
        "tools",
        "harnessRuntime",
        "childEnvironmentPolicy",
        "x11Isolation",
        "residueScan",
        "scenarioResult",
        "reportProtection",
        "rootDeletionVerified",
        "notCovered",
        "trustAssumptions",
    }
    schema_version = report.get("schemaVersion")
    scenario = report.get("scenario")
    expected_root_fields = base_root_fields | (
        {"restartLifecycle"}
        if schema_version == 4 and scenario == "full-application-kill-restart"
        else set()
    )
    if set(report) != expected_root_fields:
        raise QaFailure("artifact report has an invalid root schema")
    result = report.get("scenarioResult")
    fixed_schema_ok = (
        schema_version == 2
        and report.get("reportScope") == ARTIFACT_REPORT_SCOPE
        and scenario in {"normal", "plugin-host-crash"}
    ) or (
        schema_version == 4
        and report.get("reportScope") == RESTART_ARTIFACT_REPORT_SCOPE
        and scenario == "full-application-kill-restart"
    )
    if (
        not fixed_schema_ok
        or report.get("reportType") != "inex-sublime-build4200-evidence"
        or report.get("nativePlatform") != "linux-x64"
        or not isinstance(result, dict)
        or report.get("reportProtection") != "create-new-posix-mode-0600"
        or report.get("rootDeletionVerified") is not True
        or report.get("trustAssumptions") != list(REPORT_TRUST_ASSUMPTIONS)
    ):
        raise QaFailure("artifact report has invalid fixed scope metadata")
    result_value = result.get("result")
    if report.get("notCovered") != report_not_covered(str(scenario), str(result_value)):
        raise QaFailure("artifact report has invalid exclusions")
    _validate_source(report.get("artifactSource"), "artifact source")
    _validate_source(report.get("harnessSource"), "harness source")

    release_audit = report.get("releaseSetAudit")
    if not isinstance(release_audit, dict):
        raise QaFailure("artifact report omits the strict release-set audit")
    try:
        validate_release_set_report(release_audit)
    except ReleaseError as error:
        raise QaFailure("artifact report embeds an invalid release-set audit") from error
    if (
        report.get("releaseVersion") != release_audit.get("releaseVersion")
        or report.get("nativePlatform") != release_audit.get("platform")
        or report.get("artifactSource") != release_audit.get("source")
    ):
        raise QaFailure("artifact report release identity differs from its audit")

    harness_files = report.get("harnessFiles")
    if (
        not isinstance(harness_files, list)
        or [record.get("name") if isinstance(record, dict) else None for record in harness_files]
        != list(ARTIFACT_HARNESS_FILES)
    ):
        raise QaFailure("artifact report has an invalid harness file set")
    for record in harness_files:
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "sha256"}
            or not _valid_digest(record.get("sha256"))
        ):
            raise QaFailure("artifact report has an invalid harness file record")

    artifact_files = report.get("artifactSetFiles")
    audit_artifacts = release_audit.get("artifacts")
    if not isinstance(artifact_files, list) or not isinstance(audit_artifacts, list):
        raise QaFailure("artifact report omits its artifact file bindings")
    expected_artifact_names = sorted(
        ["SHA256SUMS"]
        + [str(record.get("name")) for record in audit_artifacts if isinstance(record, dict)]
    )
    if len(expected_artifact_names) != 4 or [
        record.get("name") if isinstance(record, dict) else None for record in artifact_files
    ] != expected_artifact_names:
        raise QaFailure("artifact report artifact-set files are not exact and sorted")
    artifact_file_map: Dict[str, Dict[str, object]] = {}
    for record in artifact_files:
        _validate_seal_record(record)
        artifact_file_map[str(record["name"])] = record
    for audit_record in audit_artifacts:
        if (
            not isinstance(audit_record, dict)
            or artifact_file_map[str(audit_record.get("name"))].get("sha256")
            != audit_record.get("sha256")
        ):
            raise QaFailure("artifact report archive digest differs from its audit")
    expected_checksum_bytes = "".join(
        f"{record['sha256']}  {record['name']}\n" for record in audit_artifacts
    ).encode("ascii")
    checksum_seal = artifact_file_map["SHA256SUMS"]
    if (
        checksum_seal.get("size") != len(expected_checksum_bytes)
        or checksum_seal.get("sha256") != sha256_bytes(expected_checksum_bytes)
    ):
        raise QaFailure("artifact report checksum manifest differs from its audit")

    audit_manifest_digests: Dict[str, object] = {}
    for audit_record in audit_artifacts:
        if not isinstance(audit_record, dict):
            raise QaFailure("artifact report has an invalid audited artifact record")
        name = str(audit_record.get("name"))
        if name.startswith("inex-rust-"):
            kind = "rust"
        elif name.startswith("inex-sublime-"):
            kind = "sublime"
        else:
            continue
        if kind in audit_manifest_digests:
            raise QaFailure("artifact report repeats an audited package kind")
        audit_manifest_digests[kind] = audit_record.get("packageManifestSha256")
    package_manifests = report.get("packageManifests")
    if (
        not isinstance(package_manifests, dict)
        or set(package_manifests) != {"rust", "sublime"}
        or set(audit_manifest_digests) != {"rust", "sublime"}
    ):
        raise QaFailure("artifact report omits its executed package manifests")
    manifest_file_maps = {
        kind: _validate_bound_package_manifest(
            package_manifests[kind],
            kind=kind,
            artifact_source=report.get("artifactSource"),
            release_version=report.get("releaseVersion"),
            native_platform=report.get("nativePlatform"),
            expected_sha256=audit_manifest_digests[kind],
        )
        for kind in ("rust", "sublime")
    }

    members = report.get("materializedMembers")
    if not isinstance(members, list) or not members:
        raise QaFailure("artifact report has no materialized package members")
    member_map: Dict[Tuple[str, str], Dict[str, object]] = {}
    member_order: List[Tuple[str, str]] = []
    for member in members:
        if (
            not isinstance(member, dict)
            or set(member) != {"archiveKind", "memberName", "mode", "size", "sha256"}
            or member.get("archiveKind") not in {"rust", "sublime"}
            or not isinstance(member.get("memberName"), str)
            or not member["memberName"]
            or not isinstance(member.get("mode"), int)
            or isinstance(member.get("mode"), bool)
            or not 0 <= member["mode"] <= 0o777
            or not isinstance(member.get("size"), int)
            or isinstance(member.get("size"), bool)
            or member["size"] < 0
            or not _valid_digest(member.get("sha256"))
        ):
            raise QaFailure("artifact report has an invalid materialized member")
        key = (str(member["archiveKind"]), str(member["memberName"]))
        if key in member_map:
            raise QaFailure("artifact report repeats a materialized member")
        member_map[key] = member
        member_order.append(key)
    if member_order != sorted(member_order):
        raise QaFailure("artifact report materialized members are not sorted")
    rust_members = [key for key in member_map if key[0] == "rust"]
    sublime_members = [key for key in member_map if key[0] == "sublime"]
    if len(rust_members) != 1 or not sublime_members:
        raise QaFailure("artifact report has an invalid package member split")
    rust_prefix = f"inex-{report.get('releaseVersion')}-{report.get('nativePlatform')}"
    rust_cli_name = rust_prefix + "/bin/inex"
    rust_sidecar_name = rust_prefix + "/bin/inexd"
    rust_manifest_files = manifest_file_maps["rust"]
    sublime_manifest_files = manifest_file_maps["sublime"]
    expected_sublime_member_names = sorted(
        ["Inex/PACKAGE-MANIFEST.json", *sublime_manifest_files]
    )
    if (
        rust_members[0][1] != rust_cli_name
        or rust_cli_name not in rust_manifest_files
        or rust_sidecar_name not in rust_manifest_files
        or sorted(key[1] for key in sublime_members) != expected_sublime_member_names
        or "Inex/bin/inexd" not in sublime_manifest_files
    ):
        raise QaFailure("artifact report package members differ from their manifests")
    sublime_manifest_bytes = (
        json.dumps(
            package_manifests["sublime"],
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")
    materialized_sublime_manifest = member_map[
        ("sublime", "Inex/PACKAGE-MANIFEST.json")
    ]
    if (
        materialized_sublime_manifest.get("size") != len(sublime_manifest_bytes)
        or materialized_sublime_manifest.get("sha256")
        != sha256_bytes(sublime_manifest_bytes)
    ):
        raise QaFailure("artifact report materialized Sublime manifest is not bound")
    for key in sublime_members:
        if key[1] == "Inex/PACKAGE-MANIFEST.json":
            continue
        member = member_map[key]
        manifest_record = sublime_manifest_files[key[1]]
        if any(member[field] != manifest_record[field] for field in ("size", "sha256")):
            raise QaFailure("artifact report Sublime member differs from its manifest")
    rust_cli_member = member_map[rust_members[0]]
    if any(
        rust_cli_member[field] != rust_manifest_files[rust_cli_name][field]
        for field in ("size", "sha256")
    ):
        raise QaFailure("artifact report CLI differs from its package manifest")

    tree = report.get("installedInexTree")
    if (
        not isinstance(tree, dict)
        or set(tree) != {"directoryCount", "fileCount", "treeSha256", "files"}
        or not isinstance(tree.get("files"), list)
        or not isinstance(tree.get("directoryCount"), int)
        or isinstance(tree.get("directoryCount"), bool)
        or tree["directoryCount"] <= 0
        or tree.get("fileCount") != len(tree["files"])
    ):
        raise QaFailure("artifact report has an invalid installed Inex tree")
    tree_files = tree["files"]
    tree_names = [record.get("name") if isinstance(record, dict) else None for record in tree_files]
    if tree_names != sorted(set(tree_names)):
        raise QaFailure("artifact report installed tree files are not unique and sorted")
    tree_map: Dict[str, Dict[str, object]] = {}
    for record in tree_files:
        _validate_seal_record(record)
        tree_map[str(record["name"])] = record
    calculated_tree_digest = sha256_bytes(
        json.dumps(
            tree_files,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    if tree.get("treeSha256") != calculated_tree_digest:
        raise QaFailure("artifact report installed tree digest is invalid")
    expected_tree_names = sorted(key[1][len("Inex/") :] for key in sublime_members)
    if tree_names != expected_tree_names:
        raise QaFailure("artifact report installed tree differs from Sublime members")
    for key in sublime_members:
        member = member_map[key]
        relative = key[1][len("Inex/") :]
        seal = tree_map[relative]
        if any(seal[field] != member[field] for field in ("mode", "size", "sha256")):
            raise QaFailure("artifact report installed file differs from its archive member")

    executables = report.get("packagedExecutables")
    if not isinstance(executables, list) or len(executables) != 2:
        raise QaFailure("artifact report must bind two packaged executables")
    expected_executable_products = ["inex", "inexd"]
    if [record.get("product") if isinstance(record, dict) else None for record in executables] != expected_executable_products:
        raise QaFailure("artifact report packaged executables are not exact and sorted")
    executable_map: Dict[str, Dict[str, object]] = {}
    for record in executables:
        if (
            not isinstance(record, dict)
            or set(record) != {"product", "memberName", "productionResolution", "seal"}
            or not isinstance(record.get("memberName"), str)
        ):
            raise QaFailure("artifact report has an invalid packaged executable record")
        _validate_seal_record(record.get("seal"))
        if record["seal"].get("name") != record.get("product"):
            raise QaFailure("artifact report executable seal has the wrong product name")
        executable_map[str(record["product"])] = record
    if (
        executable_map["inex"].get("memberName") != rust_members[0][1]
        or executable_map["inex"].get("productionResolution")
        != "rust-portable-package"
        or executable_map["inexd"].get("memberName") != "Inex/bin/inexd"
        or executable_map["inexd"].get("productionResolution")
        != "package-owned-default-empty-setting"
    ):
        raise QaFailure("artifact report executable resolution is invalid")
    for product, member_key in (
        ("inex", rust_members[0]),
        ("inexd", ("sublime", "Inex/bin/inexd")),
    ):
        seal = executable_map[product]["seal"]
        member = member_map[member_key]
        if any(seal[field] != member[field] for field in ("mode", "size", "sha256")):
            raise QaFailure("artifact report executable differs from its package member")
    if (
        executable_map["inexd"]["seal"].get("sha256")
        != release_audit.get("sharedSidecarSha256")
        or any(
            executable_map["inexd"]["seal"][field] != tree_map["bin/inexd"][field]
            for field in ("mode", "size", "sha256")
        )
    ):
        raise QaFailure("artifact report sidecar binding is invalid")

    tools = report.get("tools")
    expected_tool_names = sorted(
        {"sublime-text", "zenity", "xdotool", "Xvfb", "dbus-daemon", "metacity", "xauth"}
        | ({"xclip"} if scenario == "plugin-host-crash" else set())
    )
    if not isinstance(tools, list) or [
        record.get("name") if isinstance(record, dict) else None for record in tools
    ] != expected_tool_names:
        raise QaFailure("artifact report tool set is incomplete or unsorted")
    tool_map: Dict[str, Dict[str, object]] = {}
    for record in tools:
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "path", "version", "seal"}
            or not isinstance(record.get("path"), str)
            or not os.path.isabs(str(record["path"]))
            or (record.get("version") is not None and not isinstance(record["version"], str))
        ):
            raise QaFailure("artifact report has an invalid tool record")
        _validate_seal_record(record.get("seal"))
        if record["seal"].get("name") != record.get("name"):
            raise QaFailure("artifact report tool seal has the wrong name")
        tool_map[str(record["name"])] = record
    build = report.get("build4200")
    if (
        not isinstance(build, dict)
        or set(build) != {"build", "path", "version", "seal"}
        or build.get("build") != BUILD
        or build.get("version") != "Sublime Text Build 4200"
        or build.get("path") != tool_map["sublime-text"].get("path")
        or build.get("seal") != tool_map["sublime-text"].get("seal")
        or tool_map["sublime-text"].get("version") != build.get("version")
    ):
        raise QaFailure("artifact report has an invalid Build 4200 identity")

    runtime = report.get("harnessRuntime")
    if runtime != {"implementation": "CPython", "pythonVersion": "3.13.14"}:
        raise QaFailure("artifact report has an invalid harness runtime")
    environment_policy = report.get("childEnvironmentPolicy")
    expected_allowed_variables = sorted(
        restart_child_environment(Path("/unused"))
        if schema_version == 4
        else fixed_child_environment(Path("/unused"))
    )
    if environment_policy != {
        "policy": "fixed-allowlist",
        "allowedVariables": expected_allowed_variables,
        "explicitScenarioVariables": [
            "DBUS_SESSION_BUS_ADDRESS",
            "DISPLAY",
            "INEX_PASSWORD_STDIN",
            "XAUTHORITY",
        ],
        "removedCategories": ["GIT", "INEX-nonessential", "LD", "proxy", "PYTHON"],
    }:
        raise QaFailure("artifact report has an invalid child environment policy")
    expected_x11_isolation = {
        "authentication": "isolated-root-xauthority-cookie",
        "tcpListening": False,
        "dbusAddress": "isolated-root-runtime-path",
    }
    if schema_version == 4:
        expected_x11_isolation.update(
            {
                "gtkUsePortal": "0",
                "dbusServiceActivation": "disabled-private-config",
            }
        )
    if report.get("x11Isolation") != expected_x11_isolation:
        raise QaFailure("artifact report has an invalid X11 isolation claim")

    import_process = report.get("importProcess")
    if (
        not isinstance(import_process, dict)
        or set(import_process)
        != {
            "exitStatus",
            "stdoutBytes",
            "stdoutSha256",
            "stderrBytes",
            "stderrSha256",
            "dynamicSensitiveOutput",
        }
        or import_process.get("exitStatus") != 0
        or not isinstance(import_process.get("stdoutBytes"), int)
        or isinstance(import_process.get("stdoutBytes"), bool)
        or import_process["stdoutBytes"] <= 0
        or not _valid_digest(import_process.get("stdoutSha256"))
        or import_process.get("stderrBytes") != 0
        or import_process.get("stderrSha256") != sha256_bytes(b"")
        or import_process.get("dynamicSensitiveOutput") is not False
    ):
        raise QaFailure("artifact report has an invalid packaged import observation")

    helper_report = report.get("helperReport")
    if (
        not isinstance(helper_report, dict)
        or set(helper_report)
        != {
            "seal",
            "recordCount",
            "eventCounts",
            "normalizedSha256",
            "normalizedObservations",
        }
        or not isinstance(helper_report.get("normalizedObservations"), list)
    ):
        raise QaFailure("artifact report has an invalid helper report object")
    _validate_seal_record(helper_report.get("seal"))
    if (
        helper_report["seal"].get("name") != "control/report.jsonl"
        or helper_report["seal"].get("size", HELPER_REPORT_MAX_BYTES + 1)
        > HELPER_REPORT_MAX_BYTES
    ):
        raise QaFailure("artifact report helper report seal is invalid")
    normalized_observations = helper_report["normalizedObservations"]
    no_time_events = {
        "password_prompt_answered",
        "plugin_host_dead_clipboard_checked",
        "plugin_host_restart_required",
    }
    reconstructed = [
        dict(record, **({} if record.get("event") in no_time_events else {"time": 0.0}))
        if isinstance(record, dict)
        else record
        for record in normalized_observations
    ]
    if normalize_helper_records(reconstructed, str(scenario)) != normalized_observations:
        raise QaFailure("artifact report normalized helper observations are invalid")
    normalized_bytes = json.dumps(
        normalized_observations,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    expected_events = list(scenario_event_sequence(str(scenario)))
    expected_counts = {event: expected_events.count(event) for event in sorted(set(expected_events))}
    if (
        helper_report.get("recordCount") != len(normalized_observations)
        or helper_report.get("eventCounts") != expected_counts
        or helper_report.get("normalizedSha256") != sha256_bytes(normalized_bytes)
    ):
        raise QaFailure("artifact report helper report summary is invalid")

    residue = report.get("residueScan")
    if residue != {
        "roots": ["isolated-root"],
        "excludedRoots": [],
        "pathScope": "all-relative-path-components",
        "contentScope": "all-nonlink-regular-files-fail-closed",
        "encodings": list(SCAN_ENCODINGS),
        "randomFilenameCanaryScanned": True,
        "entropyFragmentsScanned": True,
        "entropyFragmentMinimumCharacters": 16,
        "hits": 0,
    }:
        raise QaFailure("artifact report has an invalid residue scan claim")

    v2_result_fields = {
        "scenario",
        "result",
        "events",
        "rootScanHits",
        "vaultEnvelope",
        "crudComplete",
        "pluginHostRestarted",
        "sublimeRestartRequired",
        "hostDeadPlaintextCopyable",
        "hostDeadClipboardReadOk",
        "packagedSidecarObserved",
        "packagedSidecarMatchCount",
        "packagedSidecarExeSeal",
    }
    restart_result_fields = {
        "scenario",
        "result",
        "events",
        "rootScanHits",
        "vaultEnvelope",
        "packagedSidecarObserved",
        "packagedSidecarMatchCount",
        "packagedSidecarExeSeal",
        "applicationRestarted",
        "sameProfileAndInstalledPackage",
        "oldProcessIdentitiesDead",
        "preUnlockClean",
        "reopenedFingerprintMatches",
        "normalCloseComplete",
    }
    expected_result_fields = (
        restart_result_fields
        if scenario == "full-application-kill-restart"
        else v2_result_fields
    )
    if set(result) != expected_result_fields or result.get("scenario") != scenario:
        raise QaFailure("artifact report has an invalid single-scenario result")
    _validate_seal_record(result.get("packagedSidecarExeSeal"))
    if (
        result.get("events") != expected_events
        or result.get("rootScanHits") != 0
        or result.get("vaultEnvelope") != "EDRY"
        or result.get("packagedSidecarObserved") is not True
        or result.get("packagedSidecarMatchCount")
        != (2 if scenario == "full-application-kill-restart" else 1)
        or result.get("packagedSidecarExeSeal")
        != executable_map["inexd"].get("seal")
    ):
        raise QaFailure("artifact report has a false required scenario result")
    if scenario == "normal":
        if (
            result_value != "PASS"
            or result.get("crudComplete") is not True
            or any(
                result.get(field) is not None
                for field in (
                    "pluginHostRestarted",
                    "sublimeRestartRequired",
                    "hostDeadPlaintextCopyable",
                    "hostDeadClipboardReadOk",
                )
            )
        ):
            raise QaFailure("artifact report has an invalid normal result")
    elif scenario == "plugin-host-crash" and (
        result_value != "PASS_WITH_DOCUMENTED_BOUNDARY"
        or result.get("crudComplete") is not False
        or result.get("pluginHostRestarted") is not False
        or result.get("sublimeRestartRequired") is not True
        or result.get("hostDeadPlaintextCopyable") is not True
        or result.get("hostDeadClipboardReadOk") is not True
    ):
        raise QaFailure("artifact report has an invalid crash-boundary result")
    elif scenario == "full-application-kill-restart":
        if (
            result_value != "PASS"
            or any(
                result.get(field) is not True
                for field in (
                    "applicationRestarted",
                    "sameProfileAndInstalledPackage",
                    "oldProcessIdentitiesDead",
                    "preUnlockClean",
                    "reopenedFingerprintMatches",
                    "normalCloseComplete",
                )
            )
        ):
            raise QaFailure("artifact report has an invalid full-restart result")
        lifecycle = report.get("restartLifecycle")
        if not isinstance(lifecycle, dict) or set(lifecycle) != {
            "launchCount",
            "sameProfilePath",
            "sameInstalledPackageTree",
            "childSubreaperConfirmed",
            "processClosurePolicy",
            "mountPolicy",
            "signalDelivery",
            "killSignal",
            "killedProcessClosureCount",
            "isolatedEnvironment",
            "profileDirectoryBindings",
            "installedPackageTreeSha256ByLaunch",
            "canaryFingerprintSetSha256",
            "pluginHostExecutable",
            "firstLaunchProcessIdentities",
            "oldProcessIdentitiesDead",
            "checkpoint",
            "secondLaunchProcessIdentities",
            "secondLaunchIdentitiesDistinct",
        }:
            raise QaFailure("artifact report has an invalid restart lifecycle schema")
        if (
            lifecycle.get("launchCount") != 2
            or lifecycle.get("sameProfilePath") is not True
            or lifecycle.get("sameInstalledPackageTree") is not True
            or lifecycle.get("childSubreaperConfirmed") is not True
            or lifecycle.get("signalDelivery")
            != "pidfd-per-stable-session-descendant-closure"
            or lifecycle.get("killSignal") != "SIGKILL"
            or not isinstance(lifecycle.get("killedProcessClosureCount"), int)
            or isinstance(lifecycle.get("killedProcessClosureCount"), bool)
            or lifecycle["killedProcessClosureCount"] < 4
            or lifecycle.get("oldProcessIdentitiesDead") is not True
            or lifecycle.get("secondLaunchIdentitiesDistinct") is not True
        ):
            raise QaFailure("artifact report has a false restart lifecycle claim")
        if lifecycle.get("processClosurePolicy") != {
            "stablePidfdIdentity": True,
            "sessionAndDescendantClosure": True,
            "subreaperAdoptionSweep": True,
            "rootBindingSources": ["cwd", "environment", "exe", "fd", "root"],
            "argvOnlyIsNotBinding": True,
            "unverifiedRootBoundSurvivors": 0,
        }:
            raise QaFailure("artifact report has an invalid process closure policy")
        if lifecycle.get("mountPolicy") != {
            "source": "/proc/self/mountinfo",
            "boundedParser": True,
            "checkpointRootMounts": 0,
            "finalRootMounts": 0,
            "successPathUnmounts": False,
            "failurePortalUnmount": "exact-dead-fuse.portal-non-lazy-only",
        }:
            raise QaFailure("artifact report has an invalid root mount policy")
        roles = ["sublime-main", "plugin-host-3.8", "packaged-inexd"]
        isolated_environment = lifecycle.get("isolatedEnvironment")
        if (
            not isinstance(isolated_environment, dict)
            or set(isolated_environment)
            != set(PROCESS_IDENTITY_ENVIRONMENT_KEYS)
            or any(
                not isinstance(isolated_environment.get(key), str)
                or not os.path.isabs(str(isolated_environment[key]))
                or os.path.normpath(str(isolated_environment[key]))
                != isolated_environment[key]
                for key in ROOT_ENVIRONMENT_KEYS
            )
        ):
            raise QaFailure("artifact report has an invalid isolated environment")
        if isolated_environment.get("GTK_USE_PORTAL") != "0":
            raise QaFailure("artifact report did not disable GTK portal integration")
        isolated_root = Path(str(isolated_environment["HOME"])).parent
        if {
            key: isolated_environment[key] for key in ROOT_ENVIRONMENT_KEYS
        } != expected_root_environment(isolated_root):
            raise QaFailure("artifact report environment paths do not share one root")
        expected_environment_digest = sha256_bytes(
            json.dumps(
                isolated_environment,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        expected_profile_path = Path(
            str(isolated_environment["XDG_CONFIG_HOME"])
        ) / "sublime-text"
        expected_sidecar_path = (
            expected_profile_path / "Packages" / "Inex" / "bin" / "inexd"
        )
        profile_bindings = lifecycle.get("profileDirectoryBindings")
        if (
            not isinstance(profile_bindings, list)
            or len(profile_bindings) != 2
            or profile_bindings[0] != profile_bindings[1]
        ):
            raise QaFailure("artifact report profile identity changed across restart")
        for binding in profile_bindings:
            if not isinstance(binding, dict) or set(binding) != {
                "device",
                "inode",
                "mode",
                "path",
                "pathSha256",
            }:
                raise QaFailure("artifact report has an invalid profile identity")
            for field in ("device", "inode", "mode"):
                item = binding.get(field)
                if not isinstance(item, int) or isinstance(item, bool) or item < 0:
                    raise QaFailure("artifact report has invalid profile metadata")
            if (
                binding["mode"] & 0o700 != 0o700
                or binding.get("path") != str(expected_profile_path)
                or binding.get("pathSha256")
                != sha256_bytes(str(expected_profile_path).encode("utf-8"))
            ):
                raise QaFailure("artifact report has an unsafe profile identity")
        tree_digests = lifecycle.get("installedPackageTreeSha256ByLaunch")
        if (
            not isinstance(tree_digests, list)
            or len(tree_digests) != 2
            or tree_digests[0] != tree.get("treeSha256")
            or tree_digests[1] != tree.get("treeSha256")
        ):
            raise QaFailure("artifact report package tree changed across restart")
        plugin_host_executable = lifecycle.get("pluginHostExecutable")
        if (
            not isinstance(plugin_host_executable, dict)
            or set(plugin_host_executable) != {"path", "seal"}
            or not isinstance(plugin_host_executable.get("path"), str)
            or not os.path.isabs(str(plugin_host_executable["path"]))
            or Path(str(plugin_host_executable["path"])).name != "plugin_host-3.8"
        ):
            raise QaFailure("artifact report has an invalid presealed plugin host")
        _validate_seal_record(plugin_host_executable.get("seal"))
        if plugin_host_executable["seal"].get("name") != "plugin-host-3.8":
            raise QaFailure("artifact report plugin-host seal has the wrong name")
        first_identities = lifecycle.get("firstLaunchProcessIdentities")
        second_identities = lifecycle.get("secondLaunchProcessIdentities")
        if (
            not isinstance(first_identities, list)
            or not isinstance(second_identities, list)
            or len(first_identities) != len(roles)
            or len(second_identities) != len(roles)
        ):
            raise QaFailure("artifact report omits restart process identities")
        for records in (first_identities, second_identities):
            for record, role in zip(records, roles):
                _validate_process_identity_record(record, role)
            if len({record["sessionId"] for record in records}) != 1:
                raise QaFailure("artifact report process roles escaped their launch session")
        for first, second in zip(first_identities, second_identities):
            if second["startTimeTicks"] <= first["startTimeTicks"]:
                raise QaFailure("artifact report second process identity is not newer")
        environment_bindings = {
            record["environmentBindingSha256"]
            for record in first_identities + second_identities
        }
        if environment_bindings != {expected_environment_digest}:
            raise QaFailure("artifact report process environments differ across launches")
        build_seal = build.get("seal")
        sidecar_seal = executable_map["inexd"].get("seal")
        for records in (first_identities, second_identities):
            if (
                records[0].get("executablePath") != build.get("path")
                or not _same_sealed_file(records[0]["executableSeal"], build_seal)
                or Path(str(records[1].get("executablePath"))).name
                != "plugin_host-3.8"
                or records[1].get("executablePath")
                != plugin_host_executable.get("path")
                or not _same_sealed_file(
                    records[1]["executableSeal"], plugin_host_executable["seal"]
                )
                or not _same_sealed_file(
                    records[2]["executableSeal"], sidecar_seal
                )
                or records[2].get("executablePath") != str(expected_sidecar_path)
            ):
                raise QaFailure("artifact report process executable binding is invalid")
        checkpoint = lifecycle.get("checkpoint")
        if not isinstance(checkpoint, dict) or set(checkpoint) != {
            "stateSeal",
            "stateBinding",
            "runtimeAndSocketsStopped",
            "residueScan",
        }:
            raise QaFailure("artifact report has an invalid restart checkpoint")
        _validate_seal_record(checkpoint.get("stateSeal"))
        if (
            checkpoint["stateSeal"].get("name") != "control/state.json"
            or checkpoint["stateSeal"].get("mode") != 0o600
            or checkpoint.get("runtimeAndSocketsStopped") is not True
        ):
            raise QaFailure("artifact report restart state seal is invalid")
        checkpoint_scan = checkpoint.get("residueScan")
        expected_checkpoint_scan = dict(residue)
        expected_checkpoint_scan["roots"] = [
            "isolated-root-after-sigkill-before-second-launch"
        ]
        if checkpoint_scan != expected_checkpoint_scan:
            raise QaFailure("artifact report restart checkpoint scan is invalid")
        state_binding = checkpoint.get("stateBinding")
        if not isinstance(state_binding, dict) or set(state_binding) != {
            "schemaVersion",
            "phase",
            "logicalPath",
            "opened",
            "saved",
            "tokenFingerprints",
            "tokenFingerprintSetSha256",
            "plaintextFieldsAbsent",
        }:
            raise QaFailure("artifact report restart state binding is invalid")
        observations_by_event = {
            observation["event"]: observation
            for observation in normalized_observations
            if isinstance(observation, dict)
        }
        expected_opened = {
            "byteCount": observations_by_event["opened"]["byte_count"],
            "contentSha256": observations_by_event["opened"]["content_sha256"],
        }
        expected_saved = {
            "byteCount": observations_by_event["saved"]["byte_count"],
            "contentSha256": observations_by_event["saved"]["content_sha256"],
        }
        if (
            state_binding.get("schemaVersion") != 1
            or state_binding.get("phase") != "await_full_application_restart"
            or state_binding.get("logicalPath") != "qa.md"
            or state_binding.get("opened") != expected_opened
            or state_binding.get("saved") != expected_saved
            or state_binding.get("plaintextFieldsAbsent") is not True
        ):
            raise QaFailure("artifact report restart state is not observation-bound")
        token_fingerprints = state_binding.get("tokenFingerprints")
        if not isinstance(token_fingerprints, list) or len(token_fingerprints) != 2:
            raise QaFailure("artifact report restart token bindings are incomplete")
        for token in token_fingerprints:
            if (
                not isinstance(token, dict)
                or set(token) != {"byteCount", "contentSha256"}
                or not isinstance(token.get("byteCount"), int)
                or isinstance(token.get("byteCount"), bool)
                or token["byteCount"] <= 0
                or not _valid_digest(token.get("contentSha256"))
            ):
                raise QaFailure("artifact report restart token binding is invalid")
        token_pairs = [
            (token["byteCount"], token["contentSha256"])
            for token in token_fingerprints
        ]
        if token_pairs != sorted(set(token_pairs)):
            raise QaFailure("artifact report restart token bindings are not canonical")
        token_fingerprint_set_sha256 = token_fingerprint_set_digest(token_pairs)
        ready_observation = observations_by_event.get(
            "full_application_restart_ready"
        )
        if (
            state_binding.get("tokenFingerprintSetSha256")
            != token_fingerprint_set_sha256
            or lifecycle.get("canaryFingerprintSetSha256")
            != token_fingerprint_set_sha256
            or not isinstance(ready_observation, dict)
            or ready_observation.get("token_fingerprint_set_sha256")
            != token_fingerprint_set_sha256
        ):
            raise QaFailure("artifact report restart token bindings are self-attested")
        reconstructed_state = {
            "schema_version": state_binding["schemaVersion"],
            "phase": state_binding["phase"],
            "logical_path": state_binding["logicalPath"],
            "opened_byte_count": state_binding["opened"]["byteCount"],
            "opened_content_sha256": state_binding["opened"]["contentSha256"],
            "saved_byte_count": state_binding["saved"]["byteCount"],
            "saved_content_sha256": state_binding["saved"]["contentSha256"],
            "token_fingerprints": [
                {
                    "byte_count": token["byteCount"],
                    "content_sha256": token["contentSha256"],
                }
                for token in token_fingerprints
            ],
        }
        reconstructed_state_bytes = (
            json.dumps(reconstructed_state, ensure_ascii=True, sort_keys=True) + "\n"
        ).encode("utf-8")
        if (
            checkpoint["stateSeal"].get("size") != len(reconstructed_state_bytes)
            or checkpoint["stateSeal"].get("sha256")
            != sha256_bytes(reconstructed_state_bytes)
        ):
            raise QaFailure("artifact report restart state seal is not canonical-bound")


def encode_artifact_report(report: Dict[str, object]) -> bytes:
    validate_artifact_report(report)
    return (
        json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def main() -> int:
    args = parse_arguments()
    scenario = (
        "full-application-kill-restart"
        if args.full_application_kill_restart
        else ("plugin-host-crash" if args.plugin_host_crash else "normal")
    )
    artifact_mode = args.artifact_directory is not None
    child_subreaper_confirmed = False
    if args.full_application_kill_restart:
        enable_and_verify_child_subreaper()
        child_subreaper_confirmed = True
    if artifact_mode and args.keep:
        raise QaFailure("artifact evidence cannot retain the isolated root")
    if artifact_mode and (
        host_platform.python_implementation() != "CPython"
        or host_platform.python_version() != "3.13.14"
    ):
        raise QaFailure("artifact evidence requires exact CPython 3.13.14")
    repo = REPOSITORY_ROOT
    sublime_binary = Path("/opt/sublime_text/sublime_text")
    xdotool = shutil.which("xdotool")
    xclip = shutil.which("xclip")
    xvfb = shutil.which("Xvfb")
    dbus_daemon = shutil.which("dbus-daemon")
    window_manager = shutil.which("metacity")
    xauth = shutil.which("xauth")
    zenity = verified_system_zenity()
    for binary in (sublime_binary,):
        if not binary.is_file():
            raise QaFailure("missing executable: " + str(binary))
    if (
        not xdotool
        or not xvfb
        or not dbus_daemon
        or not window_manager
        or not xauth
        or not zenity
    ):
        raise QaFailure(
            "Xvfb, xauth, xdotool, metacity, dbus-daemon, and zenity are required"
        )
    if args.plugin_host_crash and not xclip:
        raise QaFailure("xclip is required for the plugin-host crash fallback probe")
    resolved_helpers = {
        "sublime-text": sublime_binary.resolve(strict=True),
        "zenity": Path(zenity).resolve(strict=True),
        "xdotool": Path(xdotool).resolve(strict=True),
        "Xvfb": Path(xvfb).resolve(strict=True),
        "dbus-daemon": Path(dbus_daemon).resolve(strict=True),
        "metacity": Path(window_manager).resolve(strict=True),
        "xauth": Path(xauth).resolve(strict=True),
    }
    if args.plugin_host_crash and xclip:
        resolved_helpers["xclip"] = Path(xclip).resolve(strict=True)
    sublime_binary = resolved_helpers["sublime-text"]
    zenity = str(resolved_helpers["zenity"])
    xdotool = str(resolved_helpers["xdotool"])
    xvfb = str(resolved_helpers["Xvfb"])
    dbus_daemon = str(resolved_helpers["dbus-daemon"])
    window_manager = str(resolved_helpers["metacity"])
    xauth = str(resolved_helpers["xauth"])
    if xclip:
        xclip = str(Path(xclip).resolve(strict=True))
    version = bounded_tool_version(sublime_binary, ("--version",)) + "\n"
    if ("Build " + BUILD) not in version:
        raise QaFailure("Sublime Text Build 4200 is required")
    restart_plugin_host_path: Optional[Path] = None
    restart_plugin_host_seal: Optional[PhysicalFileSeal] = None
    if args.full_application_kill_restart:
        restart_plugin_host_path = sublime_binary.parent / "plugin_host-3.8"
        restart_plugin_host_seal = capture_physical_file_seal(
            restart_plugin_host_path,
            "Sublime Text Build 4200 plugin host",
            require_posix_executable=True,
        )

    output_path: Optional[Path] = None
    harness_source: Dict[str, object] = {}
    harness_seals: Dict[str, PhysicalFileSeal] = {}
    helper_seals: Dict[str, PhysicalFileSeal] = {}
    helper_versions: Dict[str, str] = {}
    if artifact_mode:
        if args.artifact_directory is None or args.output is None:
            raise QaFailure("artifact mode lost its paired paths")
        root_candidate = args.root.absolute() if args.root is not None else None
        output_path = resolve_artifact_output_path(
            args.output, args.artifact_directory, root_candidate
        )
        harness_source, harness_seals = capture_harness_state(repo)
        helper_seals = {
            name: capture_physical_file_seal(
                path, "Build 4200 helper " + name, require_posix_executable=True
            )
            for name, path in resolved_helpers.items()
        }
        helper_versions = {
            "sublime-text": version.strip(),
            "xdotool": bounded_tool_version(resolved_helpers["xdotool"], ("version",)),
        }

    if args.root is not None:
        root = args.root.resolve()
        root.mkdir(parents=True, exist_ok=False)
    else:
        root = Path(tempfile.mkdtemp(prefix="inex-build4200-"))
    os.chmod(root, 0o700)
    if artifact_mode:
        global _ACTIVE_ARTIFACT_ROOT
        _ACTIVE_ARTIFACT_ROOT = (root, root.lstat())
    signal.signal(signal.SIGTERM, raise_on_termination)
    signal.signal(signal.SIGINT, raise_on_termination)
    if artifact_mode:
        if args.artifact_directory is None or args.output is None:
            raise QaFailure("artifact mode lost its paired paths")
        checked_output = resolve_artifact_output_path(
            args.output, args.artifact_directory, root
        )
        if output_path != checked_output:
            raise QaFailure("artifact report output identity changed before execution")
    print("isolated-root=" + str(root), flush=True)

    home = root / "home"
    config = root / "config"
    cache = root / "cache"
    runtime = root / "runtime"
    isolated_tmp = root / "tmp"
    control = root / "control"
    source = root / "plaintext-source"
    vault = root / "vault"
    for path in (home, config, cache, runtime, isolated_tmp, control, source):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)

    profile = config / "sublime-text"
    packages = profile / "Packages"
    user = packages / "User"
    user.mkdir(parents=True)
    artifact_snapshot: Optional[Path] = None
    artifact_snapshot_seals: Dict[str, PhysicalFileSeal] = {}
    artifact_entries: Dict[str, Dict[str, Tuple[bytes, int]]] = {}
    artifact_hashes: Dict[str, str] = {}
    artifact_source: Dict[str, object] = {}
    release_version: Optional[str] = None
    platform_name: Optional[str] = None
    release_set_audit: Dict[str, object] = {}
    package_manifests: Dict[str, object] = {}
    materialized_members: List[Dict[str, object]] = []
    installed_inex_seal: Optional[PhysicalTreeSeal] = None
    executable_seals: Dict[str, PhysicalFileSeal] = {}
    if artifact_mode:
        if args.artifact_directory is None:
            raise QaFailure("artifact mode lost its artifact directory")
        artifact_snapshot = root / "artifact-snapshot"
        artifact_snapshot_seals = capture_artifact_snapshot(
            args.artifact_directory, artifact_snapshot
        )
        (
            artifact_entries,
            artifact_hashes,
            artifact_source,
            release_version,
            platform_name,
            release_set_audit,
        ) = capture_audited_artifact_entries(
            artifact_snapshot, artifact_snapshot_seals
        )
        manifest_members = {
            "rust": f"inex-{release_version}-{platform_name}/PACKAGE-MANIFEST.json",
            "sublime": "Inex/PACKAGE-MANIFEST.json",
        }
        try:
            package_manifests = {
                kind: json.loads(artifact_entries[kind][member][0].decode("utf-8"))
                for kind, member in manifest_members.items()
            }
        except (KeyError, UnicodeError, json.JSONDecodeError) as error:
            raise QaFailure("audited package manifests are unavailable") from error
        inex, inexd, materialized_members = materialize_packaged_inputs(
            artifact_entries,
            platform_name,
            root / "packaged-cli",
            packages,
        )
        installed_inex_seal = capture_physical_tree_seal(
            packages / "Inex", "installed Inex package"
        )
        executable_seals = {
            "inex": capture_physical_file_seal(
                inex,
                "packaged inex",
                strip_posix_write_bits=True,
                require_posix_executable=True,
            ),
            "inexd": capture_physical_file_seal(
                inexd,
                "packaged inexd",
                strip_posix_write_bits=True,
                require_posix_executable=True,
            ),
        }
        if artifact_snapshot is None or installed_inex_seal is None:
            raise QaFailure("artifact binding inputs are incomplete")
        verify_binding_inputs(
            artifact_snapshot,
            artifact_snapshot_seals,
            packages / "Inex",
            installed_inex_seal,
            {"inex": inex, "inexd": inexd},
            executable_seals,
            resolved_helpers,
            helper_seals,
            harness_source,
            harness_seals,
        )
    else:
        inex = repo / "target" / "debug" / "inex"
        inexd = repo / "target" / "debug" / "inexd"
        for binary in (inex, inexd):
            if not binary.is_file():
                raise QaFailure("missing executable: " + str(binary))

    content_tokens = [
        "INEXQA_INITIAL_" + secrets.token_hex(16),
        "INEXQA_EDIT_" + secrets.token_hex(16),
    ]
    document = "# Build 4200 QA\n\nINITIAL_TOKEN: %s\nEDIT_TOKEN: %s\n" % tuple(
        content_tokens
    )
    (source / "qa.md").write_text(document, encoding="utf-8")
    filename_canary = "INEXQA_FILENAME_" + secrets.token_hex(16)
    (source / (filename_canary + ".bin")).write_bytes(b"public skipped attachment\n")
    password = secrets.token_hex(20)
    # The password is part of the binding residue scan. It is supplied to the
    # real masked prompt over xdotool stdin and must never be written into a
    # helper script, argv, report, or isolated profile file.
    primary_tokens = content_tokens + [password, filename_canary]
    entropy_fragments = sorted(
        {
            random_part[:16]
            for token in primary_tokens
            for random_part in (token.rsplit("_", 1)[-1],)
            if len(random_part) >= 16
        }
        | {
            random_part[-16:]
            for token in primary_tokens
            for random_part in (token.rsplit("_", 1)[-1],)
            if len(random_part) >= 16
        }
    )
    tokens = primary_tokens + entropy_fragments
    import_env = fixed_child_environment(root) if artifact_mode else os.environ.copy()
    import_env.pop("SESSION_ID", None)
    import_env["INEX_PASSWORD_STDIN"] = "1"
    import_env.update(
        {
            "TMPDIR": str(isolated_tmp),
            "TMP": str(isolated_tmp),
            "TEMP": str(isolated_tmp),
        }
    )
    import_input = (password + "\n" + password + "\n").encode("utf-8")
    if artifact_mode:
        try:
            imported = release_lifecycle.run_process(
                [inex, "import", source, vault],
                environment=import_env,
                needles=[needle for _label, needle in encoded_needles(tokens)],
                input_data=import_input,
                timeout=30,
            )
        except ReleaseError as error:
            raise QaFailure("packaged vault import failed safely") from error
    else:
        imported = run_checked(
            [str(inex), "import", str(source), str(vault)],
            env=import_env,
            input=import_input,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    if imported.returncode != 0:
        raise QaFailure("vault import failed")
    expected_import_lines = {
        b"import-mode: copy",
        b"markdown-files: 1",
        b"skipped-non-markdown-files: 1",
        b"committed-encrypted-files: 1",
        b"file-parent-sync-not-confirmed: 0",
        b"publish-parent-sync: synced",
        b"source-preserved: yes",
        b"destination: published-new-vault",
        b"result: staged copy import complete",
    }
    if artifact_mode and (
        imported.stderr
        or not expected_import_lines.issubset(set(imported.stdout.splitlines()))
    ):
        raise QaFailure("packaged vault import returned an unexpected output contract")
    import_observation = {
        "exitStatus": imported.returncode,
        "stdoutBytes": len(imported.stdout),
        "stdoutSha256": sha256_bytes(imported.stdout),
        "stderrBytes": len(imported.stderr),
        "stderrSha256": sha256_bytes(imported.stderr),
        "dynamicSensitiveOutput": False,
    }
    if artifact_mode:
        if artifact_snapshot is None or installed_inex_seal is None:
            raise QaFailure("artifact binding inputs disappeared after import")
        verify_binding_inputs(
            artifact_snapshot,
            artifact_snapshot_seals,
            packages / "Inex",
            installed_inex_seal,
            {"inex": inex, "inexd": inexd},
            executable_seals,
            resolved_helpers,
            helper_seals,
            harness_source,
            harness_seals,
        )
    shutil.rmtree(source)
    assert_ciphertext(vault, tokens)

    report = control / "report.jsonl"
    state = control / "state.json"
    write_json(state, {"phase": "initial"})
    bootstrap = control / "bootstrap.txt"
    bootstrap.touch()
    dbus_config: Optional[Path] = None
    if args.full_application_kill_restart:
        dbus_config = control / "dbus-no-activation.conf"
        write_exclusive_member(
            dbus_config,
            private_dbus_config_bytes(runtime / "dbus-session-bus"),
            0o600,
        )

    # Normal Build 4200 mode with a brand-new XDG data directory is the
    # deterministic isolated-profile path. Safe Mode intentionally clears
    # third-party packages at startup and does not reliably hot-load them.
    write_json(
        user / "Preferences.sublime-settings",
        {
            "hot_exit": "disabled",
            "hot_exit_projects": False,
            "remember_open_files": False,
            "update_system_recent_files": False,
        },
    )
    write_json(
        user / "Inex.sublime-settings",
        {
            "vault_path": str(vault),
            # Artifact mode intentionally exercises production's package-owned
            # default resolution to Packages/Inex/bin/inexd.
            "sidecar_path": "" if artifact_mode else str(inexd),
            "zenity_path": str(Path(zenity).resolve()),
            "draft_debounce_ms": 100,
        },
    )
    write_json(
        user / "InexQA.sublime-settings",
        {
            "report_path": str(report),
            "state_path": str(state),
            "plugin_host_crash": args.plugin_host_crash,
            "full_application_kill_restart": args.full_application_kill_restart,
        },
    )
    if not artifact_mode:
        shutil.copytree(
            repo / "editors" / "sublime",
            packages / "Inex",
            ignore=shutil.ignore_patterns("test", "tests", "__pycache__", "*.pyc"),
        )
    qa_package = packages / "InexQA"
    qa_package.mkdir()
    if artifact_mode:
        qa_source = Path(__file__).with_name("InexQA.py")
        verify_physical_file_seal(
            qa_source,
            harness_seals["editors/sublime/test/build4200/InexQA.py"],
            "Build 4200 QA helper",
        )
        write_exclusive_member(
            qa_package / "InexQA.py", qa_source.read_bytes(), 0o600
        )
        python_version_bytes = artifact_entries["sublime"]["Inex/.python-version"][0]
        write_exclusive_member(
            qa_package / ".python-version", python_version_bytes, 0o600
        )
    else:
        shutil.copy2(Path(__file__).with_name("InexQA.py"), qa_package / "InexQA.py")
        shutil.copy2(
            packages / "Inex" / ".python-version", qa_package / ".python-version"
        )

    env = (
        restart_child_environment(root)
        if artifact_mode and args.full_application_kill_restart
        else (fixed_child_environment(root) if artifact_mode else os.environ.copy())
    )
    # This harness and every child emit only the explicit result records below.
    # Some orchestration shells define/echo SESSION_ID themselves; do not pass
    # that unrelated value into any Build 4200 subprocess.
    env.pop("SESSION_ID", None)
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_CACHE_HOME": str(cache),
            "XDG_RUNTIME_DIR": str(runtime),
            "TMPDIR": str(isolated_tmp),
            "TMP": str(isolated_tmp),
            "TEMP": str(isolated_tmp),
        }
    )
    if args.full_application_kill_restart:
        env["GTK_USE_PORTAL"] = "0"
    identity_environment_keys = (
        PROCESS_IDENTITY_ENVIRONMENT_KEYS
        if args.full_application_kill_restart
        else ROOT_ENVIRONMENT_KEYS
    )
    process_environment_binding_values = {
        key: env[key] for key in identity_environment_keys
    }
    root_binding_environment_values = {
        key: env[key] for key in ROOT_ENVIRONMENT_KEYS
    }
    display_number = 120 + (os.getpid() % 70)
    while Path("/tmp/.X11-unix/X%d" % display_number).exists():
        display_number += 1
    display = ":%d" % display_number
    xauthority = control / "Xauthority"
    x11_cookie = secrets.token_hex(16)
    xvfb_process: Optional[subprocess.Popen] = None
    xvfb_snapshot: Optional[ProcessSnapshot] = None
    window_manager_process: Optional[subprocess.Popen] = None
    window_manager_snapshot: Optional[ProcessSnapshot] = None
    sublime_process: Optional[subprocess.Popen] = None
    dbus_pid: Optional[int] = None
    dbus_snapshot: Optional[ProcessSnapshot] = None
    sublime_main_pid: Optional[int] = None
    final_success = False
    flow_complete = False
    minimal_complete = False
    plugin_host_restarted = False
    plugin_host_checked = False
    plugin_host_restart_required = False
    host_dead_plaintext_copyable: Optional[bool] = None
    host_dead_clipboard_read_ok: Optional[bool] = None
    qa_window_id: Optional[str] = None
    crud_folder_created = False
    crud_markdown_created = False
    crud_markdown_renamed = False
    crud_markdown_deleted = False
    packaged_sidecar_observed = not artifact_mode
    packaged_sidecar_match_count = 0
    restart_first_identities: List[Dict[str, object]] = []
    restart_second_identities: List[Dict[str, object]] = []
    restart_killed_session_process_count = 0
    restart_checkpoint_state_seal: Optional[PhysicalFileSeal] = None
    restart_checkpoint_state_binding: Dict[str, object] = {}
    restart_checkpoint_scan_complete = False
    restart_old_identities_dead = False
    restart_application_restarted = False
    restart_preunlock_clean = False
    restart_reopened_fingerprint_matches = False
    restart_normal_close_complete = False
    restart_launch_count = 0
    restart_profile_bindings: List[Dict[str, object]] = []
    restart_installed_tree_digests: List[str] = []
    events: List[str] = []
    helper_records: List[Dict[str, object]] = []
    answered_password_windows: set = set()
    pending_artifact_report: Optional[bytes] = None

    def launch_isolated_dbus() -> Tuple[str, int, ProcessSnapshot]:
        if args.full_application_kill_restart:
            if dbus_config is None:
                raise QaFailure("private no-activation D-Bus config is unavailable")
            arguments = [
                dbus_daemon,
                "--config-file=" + str(dbus_config),
                "--fork",
                "--print-address=1",
                "--print-pid=1",
            ]
        else:
            arguments = [
                dbus_daemon,
                "--session",
                "--fork",
                "--address=unix:path=" + str(runtime / "dbus-session-bus"),
                "--print-address=1",
                "--print-pid=1",
            ]
        result = run_checked(
            arguments,
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) < 2 or not lines[-1].isdigit():
            raise QaFailure("isolated D-Bus session did not return identity")
        pid = int(lines[-1])
        return lines[0], pid, process_snapshot(pid)

    try:
        if args.full_application_kill_restart:
            restart_profile_bindings.append(directory_binding(profile))
            if installed_inex_seal is not None:
                restart_installed_tree_digests.append(
                    physical_tree_report_digest(installed_inex_seal)
                )
        if artifact_mode:
            if artifact_snapshot is None or installed_inex_seal is None:
                raise QaFailure("artifact binding inputs are unavailable before launch")
            verify_binding_inputs(
                artifact_snapshot,
                artifact_snapshot_seals,
                packages / "Inex",
                installed_inex_seal,
                {"inex": inex, "inexd": inexd},
                executable_seals,
                resolved_helpers,
                helper_seals,
                harness_source,
                harness_seals,
            )
        dbus_address, dbus_pid, dbus_snapshot = launch_isolated_dbus()
        env["DBUS_SESSION_BUS_ADDRESS"] = dbus_address

        run_checked(
            [xauth, "-f", str(xauthority), "add", display, ".", x11_cookie],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        env["XAUTHORITY"] = str(xauthority)

        xvfb_process = subprocess.Popen(
            [
                xvfb,
                display,
                "-screen",
                "0",
                "1280x800x24",
                "-nolisten",
                "tcp",
                "-auth",
                str(xauthority),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        xvfb_snapshot = process_snapshot(xvfb_process.pid)
        env["DISPLAY"] = display
        wait_until("Xvfb", lambda: Path("/tmp/.X11-unix/X%d" % display_number).exists(), 5)
        window_manager_process = subprocess.Popen(
            [window_manager, "--sm-disable", "--replace"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        window_manager_snapshot = process_snapshot(window_manager_process.pid)
        time.sleep(0.5)
        if window_manager_process.poll() is not None:
            raise QaFailure("isolated metacity process failed to start")

        def launch_sublime() -> Tuple[subprocess.Popen, int]:
            preexisting_sublime = set(sublime_multiinstance_pids(sublime_binary))
            launcher = subprocess.Popen(
                [
                    str(sublime_binary),
                    "--new-window",
                    "--wait",
                    str(bootstrap),
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )

            def find_sublime_main() -> Optional[int]:
                # Build 4200 reparents the multiinstance process to PID 1 before
                # the --wait launcher returns. Bind discovery to the exact new
                # PID set created after this isolated launch.
                candidates = (
                    set(sublime_multiinstance_pids(sublime_binary))
                    - preexisting_sublime
                )
                return next(iter(candidates)) if len(candidates) == 1 else None

            try:
                wait_until(
                    "Sublime main process", lambda: find_sublime_main() is not None, 10
                )
                main_pid = find_sublime_main()
                if main_pid is None:
                    raise QaFailure("Sublime main process disappeared")
                if os.getsid(main_pid) != os.getsid(launcher.pid):
                    raise QaFailure("Sublime main process escaped its launch session")
                return launcher, main_pid
            except Exception:
                terminate_pid(launcher.pid, 0.2)
                raise

        sublime_process, sublime_main_pid = launch_sublime()
        restart_launch_count = 1
        def isolated_window_ids() -> List[str]:
            # Build 4200 may create a separate initial untitled top-level in a
            # fresh profile. The Quick Panel belongs to the window holding the
            # non-secret bootstrap file, so bind by that unique title instead
            # of a generic Sublime class/name query.
            found = subprocess.run(
                [xdotool, "search", "--onlyvisible", "--name", bootstrap.name],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            if found.returncode != 0:
                return []
            return [line.strip() for line in found.stdout.splitlines() if line.strip()]

        def password_window_ids() -> List[str]:
            found = subprocess.run(
                [
                    xdotool,
                    "search",
                    "--onlyvisible",
                    "--name",
                    "Unlock Inex vault",
                ],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            if found.returncode != 0:
                return []
            return [
                line.strip()
                for line in found.stdout.splitlines()
                if line.strip().isdigit()
            ]

        offset = 0
        deadline = time.monotonic() + FLOW_TIMEOUT_SECONDS * (
            2 if args.full_application_kill_restart else 1
        )
        while time.monotonic() < deadline:
            if sublime_process.poll() is not None:
                raise QaFailure("Sublime launcher exited before QA completion")
            for password_window_id in password_window_ids():
                if (
                    args.full_application_kill_restart
                    and restart_launch_count == 2
                    and not restart_preunlock_clean
                ):
                    # The helper's stable all-view/no-session observation must
                    # be consumed before the runner is allowed to unlock.
                    break
                if password_window_id in answered_password_windows:
                    continue
                run_checked(
                    [
                        xdotool,
                        "windowactivate",
                        "--sync",
                        password_window_id,
                    ],
                    env=env,
                    timeout=5,
                )
                time.sleep(0.3)
                run_checked(
                    [
                        xdotool,
                        "type",
                        "--clearmodifiers",
                        "--delay",
                        "1",
                        "--file",
                        "-",
                    ],
                    env=env,
                    input=password,
                    text=True,
                    timeout=5,
                )
                time.sleep(0.1)
                run_checked(
                    [
                        xdotool,
                        "key",
                        "--clearmodifiers",
                        "Return",
                    ],
                    env=env,
                    timeout=5,
                )
                answered_password_windows.add(password_window_id)
                append_report(
                    report,
                    {"event": "password_prompt_answered", "masked": True},
                )
            offset, records = read_new_reports(report, offset)
            helper_records.extend(records)
            if len(helper_records) > HELPER_REPORT_MAX_RECORDS:
                raise QaFailure("QA helper report exceeded its record ceiling")
            for record in records:
                event = record.get("event")
                if isinstance(event, str):
                    events.append(event)
                if event == "fatal":
                    raise QaFailure("QA helper failed at " + str(record.get("step")))
                if event == "loaded" and not record.get("gate_ok"):
                    raise QaFailure("strict preferences gate failed")
                if event == "opened" and not (
                    record.get("scratch") and record.get("unnamed") and record.get("initial_ok")
                ):
                    raise QaFailure("managed open invariants failed")
                if event == "opened" and artifact_mode:
                    sidecar_pids = packaged_sidecar_pids(
                        inexd, executable_seals["inexd"]
                    )
                    if len(sidecar_pids) != 1:
                        raise QaFailure(
                            "production sidecar resolution did not execute one sealed packaged daemon"
                        )
                    packaged_sidecar_observed = True
                    packaged_sidecar_match_count = 1
                if event == "saved" and not record.get("persisted_shape"):
                    raise QaFailure("encrypted save shape failed")
                if event == "crud_folder_created":
                    if record.get("exists") is not True:
                        raise QaFailure("encrypted folder create was not observed")
                    crud_folder_created = True
                if event == "crud_markdown_created":
                    if not (
                        record.get("clean") is True
                        and record.get("scratch") is True
                        and record.get("unnamed") is True
                        and record.get("empty") is True
                    ):
                        raise QaFailure("encrypted Markdown create invariants failed")
                    crud_markdown_created = True
                if event == "crud_markdown_renamed":
                    if record.get("clean") is not True:
                        raise QaFailure("encrypted Markdown rename invariants failed")
                    crud_markdown_renamed = True
                if event == "crud_markdown_deleted":
                    if record.get("absent") is not True:
                        raise QaFailure("encrypted Markdown delete was not observed")
                    crud_markdown_deleted = True
                if event == "ui" and record.get("action") in (
                    "select_tree",
                    "select_tree_for_plugin_host_crash",
                    "select_tree_after_restart",
                ):
                    wait_until(
                        "isolated Sublime window",
                        lambda: bool(isolated_window_ids()),
                        20,
                    )
                    window_ids = isolated_window_ids()
                    if not window_ids:
                        raise QaFailure("isolated Sublime window disappeared")
                    window_id = window_ids[0]
                    qa_window_id = window_id
                    run_checked(
                        [xdotool, "windowactivate", "--sync", window_id],
                        env=env,
                        timeout=5,
                    )
                    time.sleep(0.6)
                    run_checked(
                        [
                            xdotool,
                            "key",
                            "--clearmodifiers",
                            "Down",
                        ],
                        env=env,
                        timeout=5,
                    )
                    time.sleep(0.15)
                    run_checked(
                        [xdotool, "key", "--clearmodifiers", "Return"],
                        env=env,
                        timeout=5,
                    )
                if event == "ui" and record.get("action") in (
                    "crud_new_folder",
                    "crud_new_markdown",
                    "crud_rename",
                    "crud_delete_confirm",
                ):
                    if qa_window_id is None:
                        raise QaFailure("isolated CRUD window id is unavailable")
                    run_checked(
                        [xdotool, "windowactivate", "--sync", qa_window_id],
                        env=env,
                        timeout=5,
                    )
                    time.sleep(0.3)
                    action = record.get("action")
                    inputs = {
                        "crud_new_folder": "qa-crud",
                        "crud_new_markdown": "qa-crud/new.md",
                        "crud_rename": "qa-crud/renamed.md",
                    }
                    if action in inputs:
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "ctrl+a"],
                            env=env,
                            timeout=5,
                        )
                        run_checked(
                            [
                                xdotool,
                                "type",
                                "--clearmodifiers",
                                "--delay",
                                "1",
                                inputs[action],
                            ],
                            env=env,
                            timeout=5,
                        )
                    else:
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "Home"],
                            env=env,
                            timeout=5,
                        )
                    time.sleep(0.15)
                    run_checked(
                        [xdotool, "key", "--clearmodifiers", "Return"],
                        env=env,
                        timeout=5,
                    )
                if event == "minimal_complete":
                    if not args.plugin_host_crash and record.get("crud_complete") is not True:
                        raise QaFailure("normal completion omitted the CRUD scenario")
                    minimal_complete = True
                if event == "full_application_restart_ready":
                    if not args.full_application_kill_restart:
                        raise QaFailure("unexpected full-application restart scenario")
                    if (
                        record.get("marker") is not True
                        or record.get("state_written") is not True
                        or record.get("logical_path") != "qa.md"
                    ):
                        raise QaFailure("full-application restart checkpoint is invalid")
                    if sublime_main_pid is None or sublime_process is None:
                        raise QaFailure("first Sublime launch identity is unavailable")
                    restart_checkpoint_state_binding = validate_restart_checkpoint_state(
                        state, helper_records, content_tokens
                    )
                    restart_checkpoint_state_seal = capture_physical_file_seal(
                        state, "restart checkpoint state"
                    )
                    restart_first_identities = capture_application_identities(
                        sublime_main_pid,
                        sublime_binary,
                        helper_seals["sublime-text"]
                        if artifact_mode
                        else capture_physical_file_seal(
                            sublime_binary,
                            "Sublime Text Build 4200",
                            require_posix_executable=True,
                        ),
                        restart_plugin_host_path,
                        restart_plugin_host_seal,
                        profile,
                        inexd,
                        executable_seals["inexd"]
                        if artifact_mode
                        else capture_physical_file_seal(
                            inexd,
                            "developer sidecar",
                            require_posix_executable=True,
                        ),
                        process_environment_binding_values,
                    )
                    restart_killed_session_process_count = (
                        kill_verified_application_session(
                            restart_first_identities,
                            sublime_process,
                            root,
                            root_binding_environment_values,
                            tuple(
                                pid
                                for pid in (
                                    window_manager_process.pid
                                    if window_manager_process is not None
                                    else None,
                                    xvfb_process.pid if xvfb_process is not None else None,
                                    dbus_pid,
                                )
                                if pid is not None
                            ),
                        )
                    )
                    restart_old_identities_dead = all(
                        not process_identity_alive(identity)
                        for identity in restart_first_identities
                    )
                    if not restart_old_identities_dead:
                        raise QaFailure("old application identity survived verified SIGKILL")
                    sublime_main_pid = None
                    sublime_process = None
                    if command_pids("plugin_host-3.8", str(profile)):
                        raise QaFailure("old profile plugin host survived verified SIGKILL")
                    if packaged_sidecar_pids(
                        inexd,
                        executable_seals["inexd"]
                        if artifact_mode
                        else capture_physical_file_seal(
                            inexd,
                            "developer sidecar",
                            require_posix_executable=True,
                        ),
                    ):
                        raise QaFailure("old packaged sidecar survived verified SIGKILL")

                    if window_manager_process is not None:
                        if window_manager_snapshot is None:
                            raise QaFailure("window manager identity is unavailable")
                        terminate_process_snapshot(window_manager_snapshot, 0.2)
                        window_manager_process = None
                        window_manager_snapshot = None
                    if xvfb_process is not None:
                        if xvfb_snapshot is None:
                            raise QaFailure("Xvfb identity is unavailable")
                        terminate_process_snapshot(xvfb_snapshot, 0.2)
                        xvfb_process = None
                        xvfb_snapshot = None
                    if dbus_snapshot is not None:
                        terminate_process_snapshot(dbus_snapshot, 0.2)
                        reap_subreaper_process(dbus_snapshot)
                    dbus_pid = None
                    dbus_snapshot = None
                    wait_until(
                        "first-launch X11 socket removal",
                        lambda: not Path(
                            "/tmp/.X11-unix/X%d" % display_number
                        ).exists(),
                        5,
                    )
                    for generated_runtime_path in (
                        xauthority,
                        runtime / "dbus-session-bus",
                    ):
                        try:
                            generated_runtime_path.unlink()
                        except FileNotFoundError:
                            pass
                        except OSError as error:
                            raise QaFailure(
                                "restart checkpoint runtime cleanup failed"
                            ) from error
                    wait_for_no_root_bindings(
                        root, root_binding_environment_values, 5
                    )
                    wait_for_no_root_mounts(root, 5)
                    if scan_for_tokens((root,), tokens):
                        raise QaFailure("plaintext residue existed at restart checkpoint")
                    restart_checkpoint_scan_complete = True
                    if artifact_mode:
                        if artifact_snapshot is None or installed_inex_seal is None:
                            raise QaFailure("artifact binding disappeared at restart")
                        verify_binding_inputs(
                            artifact_snapshot,
                            artifact_snapshot_seals,
                            packages / "Inex",
                            installed_inex_seal,
                            {"inex": inex, "inexd": inexd},
                            executable_seals,
                            resolved_helpers,
                            helper_seals,
                            harness_source,
                            harness_seals,
                        )
                        observed_installed_tree = capture_physical_tree_seal(
                            packages / "Inex", "installed Inex package at restart"
                        )
                        restart_installed_tree_digests.append(
                            physical_tree_report_digest(observed_installed_tree)
                        )
                        if restart_installed_tree_digests[0] != restart_installed_tree_digests[1]:
                            raise QaFailure("installed package tree changed across restart")
                    restart_profile_bindings.append(directory_binding(profile))
                    if restart_profile_bindings[0] != restart_profile_bindings[1]:
                        raise QaFailure("profile directory identity changed across restart")

                    dbus_address, dbus_pid, dbus_snapshot = launch_isolated_dbus()
                    env["DBUS_SESSION_BUS_ADDRESS"] = dbus_address
                    run_checked(
                        [xauth, "-f", str(xauthority), "add", display, ".", x11_cookie],
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=5,
                    )
                    xvfb_process = subprocess.Popen(
                        [
                            xvfb,
                            display,
                            "-screen",
                            "0",
                            "1280x800x24",
                            "-nolisten",
                            "tcp",
                            "-auth",
                            str(xauthority),
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    xvfb_snapshot = process_snapshot(xvfb_process.pid)
                    wait_until(
                        "second Xvfb",
                        lambda: Path(
                            "/tmp/.X11-unix/X%d" % display_number
                        ).exists(),
                        5,
                    )
                    window_manager_process = subprocess.Popen(
                        [window_manager, "--sm-disable", "--replace"],
                        env=env,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                    window_manager_snapshot = process_snapshot(
                        window_manager_process.pid
                    )
                    time.sleep(0.5)
                    if window_manager_process.poll() is not None:
                        raise QaFailure("second metacity process failed to start")
                    answered_password_windows.clear()
                    qa_window_id = None
                    sublime_process, sublime_main_pid = launch_sublime()
                    restart_launch_count = 2
                    restart_application_restarted = True
                    continue
                if event == "restart_preunlock_checked":
                    if not args.full_application_kill_restart:
                        raise QaFailure("unexpected restart pre-unlock checkpoint")
                    if not (
                        record.get("clean") is True
                        and record.get("managed_count") == 0
                        and record.get("client_present") is False
                        and record.get("session_active") is False
                        and record.get("vault_id_present") is False
                        and record.get("vault_path_present") is False
                        and record.get("unlock_in_progress") is False
                        and record.get("pending_plaintext_count") == 0
                        and record.get("handoff_count") == 0
                        and record.get("scrubbing_count") == 0
                        and record.get("fixed_scrub_ack_count") == 0
                        and record.get("orphan_scrub_blocked") is False
                        and record.get("marker_count") == 0
                        and record.get("known_fingerprint_count") == 0
                        and record.get("token_window_match_count") == 0
                        and record.get("stable_duration_ms") == 2000
                    ):
                        raise QaFailure("restart pre-unlock checkpoint is not clean")
                    sidecar_seal_for_check = (
                        executable_seals["inexd"]
                        if artifact_mode
                        else capture_physical_file_seal(
                            inexd,
                            "developer sidecar",
                            require_posix_executable=True,
                        )
                    )
                    if packaged_sidecar_pids(inexd, sidecar_seal_for_check):
                        raise QaFailure("sidecar existed before the second unlock")
                    restart_preunlock_clean = True
                if event == "restart_reopened":
                    if not args.full_application_kill_restart:
                        raise QaFailure("unexpected restart reopen observation")
                    if (
                        record.get("fingerprint_matches") is not True
                        or record.get("logical_path_matches") is not True
                    ):
                        raise QaFailure("restart did not reopen the saved ciphertext")
                    if sublime_main_pid is None:
                        raise QaFailure("second Sublime launch identity is unavailable")
                    restart_second_identities = capture_application_identities(
                        sublime_main_pid,
                        sublime_binary,
                        helper_seals["sublime-text"]
                        if artifact_mode
                        else capture_physical_file_seal(
                            sublime_binary,
                            "Sublime Text Build 4200",
                            require_posix_executable=True,
                        ),
                        restart_plugin_host_path,
                        restart_plugin_host_seal,
                        profile,
                        inexd,
                        executable_seals["inexd"]
                        if artifact_mode
                        else capture_physical_file_seal(
                            inexd,
                            "developer sidecar",
                            require_posix_executable=True,
                        ),
                        process_environment_binding_values,
                    )
                    first_by_role = {
                        identity["role"]: identity
                        for identity in restart_first_identities
                    }
                    if any(
                        identity["startTimeTicks"]
                        <= first_by_role[identity["role"]]["startTimeTicks"]
                        for identity in restart_second_identities
                    ):
                        raise QaFailure("second launch process identity is not newer")
                    packaged_sidecar_match_count = 2
                    restart_reopened_fingerprint_matches = True
                if event == "restart_closed":
                    if (
                        not args.full_application_kill_restart
                        or record.get("normal_close") is not True
                        or record.get("managed_count") != 0
                        or record.get("view_absent") is not True
                    ):
                        raise QaFailure("restart normal-close checkpoint is invalid")
                    restart_normal_close_complete = True
                if event == "plugin_host_crash_ready":
                    if not args.plugin_host_crash:
                        raise QaFailure("unexpected plugin-host crash scenario")
                    if record.get("marker") is not True:
                        raise QaFailure("plugin-host probe marker was not installed")
                    active_window_result = run_checked(
                        [xdotool, "getactivewindow"],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    active_window_id = active_window_result.stdout.strip()
                    if not active_window_id.isdigit():
                        raise QaFailure("isolated active window id is unavailable")
                    hosts = command_pids("plugin_host-3.8", str(profile))
                    if len(hosts) != 1:
                        raise QaFailure(
                            "expected one isolated Python 3.8 plugin host, found %d"
                            % len(hosts)
                        )
                    old_host = hosts[0]
                    os.kill(old_host, signal.SIGKILL)

                    def replacement_host_ready() -> bool:
                        hosts_now = command_pids("plugin_host-3.8", str(profile))
                        return len(hosts_now) == 1 and hosts_now[0] != old_host

                    try:
                        wait_until(
                            "automatic Python 3.8 plugin host restart",
                            replacement_host_ready,
                            2,
                        )
                    except QaFailure:
                        if replacement_host_ready():
                            plugin_host_restarted = True
                            continue
                        # Build 4200 does not automatically restart a killed
                        # plugin host. The official platform recovery is to
                        # restart Sublime Text, so characterize the still-dead
                        # host without pretending that plugin code can run.
                        known_plaintext_fingerprints = {
                            (candidate.get("byte_count"), candidate.get("content_sha256"))
                            for candidate in helper_records
                            if candidate.get("event")
                            in {"opened", "saved", "plugin_host_crash_ready"}
                        }
                        post_crash_active = run_checked(
                            [xdotool, "getactivewindow"],
                            env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True,
                            check=False,
                            timeout=5,
                        )
                        post_crash_window_id = post_crash_active.stdout.strip()
                        if (
                            post_crash_active.returncode == 0
                            and post_crash_window_id.isdigit()
                            and post_crash_window_id != active_window_id
                        ):
                            # Dismiss only an isolated crash notification that
                            # stole focus; never send Return to the document.
                            run_checked(
                                [
                                    xdotool,
                                    "key",
                                    "--window",
                                    post_crash_window_id,
                                    "--clearmodifiers",
                                    "Return",
                                ],
                                env=env,
                                timeout=5,
                            )
                            time.sleep(0.2)
                        run_checked(
                            [
                                xdotool,
                                "windowactivate",
                                "--sync",
                                active_window_id,
                            ],
                            env=env,
                            timeout=5,
                        )
                        run_checked(
                            [
                                xdotool,
                                "mousemove",
                                "--window",
                                active_window_id,
                                "600",
                                "300",
                                "click",
                                "1",
                            ],
                            env=env,
                            timeout=5,
                        )
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "ctrl+a"],
                            env=env,
                            timeout=5,
                        )
                        time.sleep(0.1)
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "ctrl+c"],
                            env=env,
                            timeout=5,
                        )
                        time.sleep(0.2)
                        clipboard_result = run_checked(
                            [xclip, "-selection", "clipboard", "-o"],
                            env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=5,
                        )
                        clipboard_read_ok = clipboard_result.returncode == 0
                        clipboard = (
                            clipboard_result.stdout if clipboard_read_ok else b""
                        )
                        clipboard_digest = hashlib.sha256(clipboard).hexdigest()
                        clipboard_exact = (
                            len(clipboard), clipboard_digest
                        ) in known_plaintext_fingerprints
                        plaintext_copyable = clipboard_exact or any(
                            token.encode("utf-8") in clipboard for token in tokens
                        )
                        selection_channel = "clipboard"
                        if not plaintext_copyable:
                            # A dead plugin host can also prevent key-command
                            # dispatch. Select the short fixture with the
                            # editor's native mouse path; X11 PRIMARY owns a
                            # selection without invoking a plugin command.
                            run_checked(
                                [
                                    xdotool,
                                    "mousemove",
                                    "--window",
                                    active_window_id,
                                    "1000",
                                    "400",
                                    "mousedown",
                                    "1",
                                    "mousemove",
                                    "--window",
                                    active_window_id,
                                    "5",
                                    "65",
                                    "mouseup",
                                    "1",
                                ],
                                env=env,
                                timeout=5,
                            )
                            time.sleep(0.2)
                            primary_result = run_checked(
                                [xclip, "-selection", "primary", "-o"],
                                env=env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                check=False,
                                timeout=5,
                            )
                            primary_read_ok = primary_result.returncode == 0
                            primary = (
                                primary_result.stdout if primary_read_ok else b""
                            )
                            primary_digest = hashlib.sha256(primary).hexdigest()
                            primary_exact = (
                                len(primary), primary_digest
                            ) in known_plaintext_fingerprints
                            primary_copyable = primary_exact or any(
                                token.encode("utf-8") in primary for token in tokens
                            )
                            if primary_read_ok:
                                clipboard = primary
                                clipboard_digest = primary_digest
                                clipboard_read_ok = True
                                selection_channel = "primary"
                            if primary_copyable:
                                plaintext_copyable = True
                                clipboard_exact = primary_exact
                            primary = b""
                        append_report(
                            report,
                            {
                                "event": "plugin_host_dead_clipboard_checked",
                                "byte_count": len(clipboard),
                                "content_sha256": clipboard_digest,
                                "same_length_and_hash": clipboard_exact,
                                "host_dead_plaintext_copyable": plaintext_copyable,
                                "clipboard_read_ok": clipboard_read_ok,
                                "selection_channel": selection_channel,
                            },
                        )
                        clipboard = b""
                        host_dead_plaintext_copyable = plaintext_copyable
                        host_dead_clipboard_read_ok = clipboard_read_ok
                        if not (
                            clipboard_read_ok
                            and clipboard_exact
                            and plaintext_copyable
                        ):
                            raise QaFailure(
                                "plugin-host-dead plaintext copy probe was inconclusive"
                            )
                        time.sleep(0.25)
                        if replacement_host_ready():
                            plugin_host_restarted = True
                        else:
                            plugin_host_restart_required = True
                            append_report(
                                report,
                                {
                                    "event": "plugin_host_restart_required",
                                    "documented_platform_boundary": True,
                                },
                            )
                            flow_complete = True
                    else:
                        plugin_host_restarted = True
                if event == "plugin_host_restart_checked":
                    if not plugin_host_restarted:
                        raise QaFailure("plugin-host restart check arrived out of order")
                    plugin_host_checked = True
                    if record.get("plaintext_survived") is True:
                        raise QaFailure(
                            "plugin_host-3.8 crash left the managed plaintext view intact"
                        )
                    if record.get("orphan_scrubbed") is not True:
                        raise QaFailure(
                            "plugin_host-3.8 restart did not scrub the marked orphan view"
                        )
                if event == "complete":
                    if scenario == "normal" and not minimal_complete:
                        raise QaFailure("completion preceded the minimal-flow close")
                    if scenario == "normal" and not all(
                        (
                            crud_folder_created,
                            crud_markdown_created,
                            crud_markdown_renamed,
                            crud_markdown_deleted,
                        )
                    ):
                        raise QaFailure("completion preceded the CRUD assertions")
                    if (
                        scenario == "plugin-host-crash"
                        and not plugin_host_checked
                        and not plugin_host_restart_required
                    ):
                        raise QaFailure("completion preceded the plugin-host restart check")
                    if scenario == "full-application-kill-restart" and not all(
                        (
                            restart_application_restarted,
                            restart_checkpoint_scan_complete,
                            restart_old_identities_dead,
                            restart_preunlock_clean,
                            restart_reopened_fingerprint_matches,
                            restart_normal_close_complete,
                            bool(restart_first_identities),
                            bool(restart_second_identities),
                        )
                    ):
                        raise QaFailure("completion preceded a restart lifecycle checkpoint")
                    flow_complete = True
                    break
            if flow_complete:
                break
            time.sleep(0.1)
        if not flow_complete:
            raise QaFailure("minimal flow did not complete")

        assert_ciphertext(vault, tokens)
        terminate_sublime_tree(sublime_main_pid, sublime_process, root)
        sublime_main_pid = None
        sublime_process = None
        if window_manager_process is not None:
            if window_manager_snapshot is None:
                raise QaFailure("window manager identity is unavailable")
            terminate_process_snapshot(window_manager_snapshot, 0.2)
            window_manager_process = None
            window_manager_snapshot = None
        if xvfb_process is not None:
            if xvfb_snapshot is None:
                raise QaFailure("Xvfb identity is unavailable")
            terminate_process_snapshot(xvfb_snapshot, 0.2)
            xvfb_process = None
            xvfb_snapshot = None
        if dbus_snapshot is not None:
            terminate_process_snapshot(dbus_snapshot, 0.2)
            reap_subreaper_process(dbus_snapshot)
        dbus_pid = None
        dbus_snapshot = None
        for generated_runtime_path in (xauthority, runtime / "dbus-session-bus"):
            try:
                generated_runtime_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise QaFailure("isolated display or D-Bus residue cleanup failed") from error
        wait_for_no_root_bindings(root, root_binding_environment_values, 5)
        wait_for_no_root_mounts(root, 5)
        offset, final_records = read_new_reports(report, offset)
        helper_records.extend(final_records)
        events.extend(str(record["event"]) for record in final_records)
        if len(helper_records) > HELPER_REPORT_MAX_RECORDS:
            raise QaFailure("QA helper report exceeded its record ceiling")
        helper_report_seal = capture_physical_file_seal(report, "QA helper report")
        if offset != helper_report_seal.metadata.st_size:
            raise QaFailure("QA helper report ended with an incomplete record")
        normalized_helper_records = normalize_helper_records(helper_records, scenario)
        event_counts = {
            event: events.count(event) for event in sorted(set(events))
        }
        normalized_helper_bytes = json.dumps(
            normalized_helper_records,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        summary = {
            "events": events,
            "scenario": scenario,
            "plugin_host_crash": args.plugin_host_crash,
            "full_application_kill_restart": args.full_application_kill_restart,
            "result": (
                "PASS_WITH_DOCUMENTED_BOUNDARY"
                if plugin_host_restart_required
                else "PASS"
            ),
            "root_scan_hits": 0,
            "vault_envelope": "EDRY",
            "crud_complete": (
                scenario == "normal"
                and crud_folder_created
                and crud_markdown_created
                and crud_markdown_renamed
                and crud_markdown_deleted
            ),
        }
        if args.plugin_host_crash:
            summary.update(
                {
                    "plugin_host_restarted": plugin_host_checked,
                    "sublime_restart_required": plugin_host_restart_required,
                    "host_dead_plaintext_copyable": host_dead_plaintext_copyable,
                    "host_dead_clipboard_read_ok": host_dead_clipboard_read_ok,
                }
            )
        if args.full_application_kill_restart:
            summary.update(
                {
                    "application_restarted": restart_application_restarted,
                    "old_process_identities_dead": restart_old_identities_dead,
                    "preunlock_clean": restart_preunlock_clean,
                    "reopened_fingerprint_matches": restart_reopened_fingerprint_matches,
                    "normal_close_complete": restart_normal_close_complete,
                    "launch_count": restart_launch_count,
                }
            )
        write_json(control / "final-result.json", summary)
        hits = scan_for_tokens((root,), tokens)
        if hits:
            raise QaFailure("plaintext residue found: " + ", ".join(hits[:8]))
        if artifact_mode:
            if (
                artifact_snapshot is None
                or installed_inex_seal is None
                or release_version is None
                or platform_name is None
            ):
                raise QaFailure("artifact report inputs are incomplete")
            verify_binding_inputs(
                artifact_snapshot,
                artifact_snapshot_seals,
                packages / "Inex",
                installed_inex_seal,
                {"inex": inex, "inexd": inexd},
                executable_seals,
                resolved_helpers,
                helper_seals,
                harness_source,
                harness_seals,
            )
            verify_harness_state(
                repo,
                harness_source,
                harness_seals,
                recheck_revision=True,
            )
            tree_files = [
                seal_record(name, installed_inex_seal.files[name])
                for name in sorted(installed_inex_seal.files)
            ]
            tree_digest = sha256_bytes(
                json.dumps(
                    tree_files,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            )
            if args.full_application_kill_restart:
                if restart_checkpoint_state_seal is None:
                    raise QaFailure("restart checkpoint state seal is unavailable")
                verify_physical_file_seal(
                    state,
                    restart_checkpoint_state_seal,
                    "restart checkpoint state",
                )
                verify_physical_file_seal(
                    restart_plugin_host_path,
                    restart_plugin_host_seal,
                    "Sublime Text Build 4200 plugin host",
                    require_posix_executable=True,
                )
                scenario_result = {
                    "scenario": scenario,
                    "result": summary["result"],
                    "events": events,
                    "rootScanHits": 0,
                    "vaultEnvelope": "EDRY",
                    "packagedSidecarObserved": packaged_sidecar_observed,
                    "packagedSidecarMatchCount": packaged_sidecar_match_count,
                    "packagedSidecarExeSeal": seal_record(
                        "inexd", executable_seals["inexd"]
                    ),
                    "applicationRestarted": restart_application_restarted,
                    "sameProfileAndInstalledPackage": True,
                    "oldProcessIdentitiesDead": restart_old_identities_dead,
                    "preUnlockClean": restart_preunlock_clean,
                    "reopenedFingerprintMatches": restart_reopened_fingerprint_matches,
                    "normalCloseComplete": restart_normal_close_complete,
                }
            else:
                scenario_result = {
                    "scenario": scenario,
                    "result": summary["result"],
                    "events": events,
                    "rootScanHits": 0,
                    "vaultEnvelope": "EDRY",
                    "crudComplete": summary["crud_complete"],
                    "pluginHostRestarted": (
                        summary.get("plugin_host_restarted")
                        if args.plugin_host_crash
                        else None
                    ),
                    "sublimeRestartRequired": (
                        summary.get("sublime_restart_required")
                        if args.plugin_host_crash
                        else None
                    ),
                    "hostDeadPlaintextCopyable": (
                        summary.get("host_dead_plaintext_copyable")
                        if args.plugin_host_crash
                        else None
                    ),
                    "hostDeadClipboardReadOk": (
                        summary.get("host_dead_clipboard_read_ok")
                        if args.plugin_host_crash
                        else None
                    ),
                    "packagedSidecarObserved": packaged_sidecar_observed,
                    "packagedSidecarMatchCount": packaged_sidecar_match_count,
                    "packagedSidecarExeSeal": seal_record(
                        "inexd", executable_seals["inexd"]
                    ),
                }
            cli_member = next(
                record["memberName"]
                for record in materialized_members
                if record["archiveKind"] == "rust"
            )
            artifact_report: Dict[str, object] = {
                "schemaVersion": 4 if args.full_application_kill_restart else 2,
                "reportType": "inex-sublime-build4200-evidence",
                "reportScope": (
                    RESTART_ARTIFACT_REPORT_SCOPE
                    if args.full_application_kill_restart
                    else ARTIFACT_REPORT_SCOPE
                ),
                "artifactSource": artifact_source,
                "harnessSource": harness_source,
                "harnessFiles": [
                    {"name": name, "sha256": harness_seals[name].sha256}
                    for name in ARTIFACT_HARNESS_FILES
                ],
                "helperReport": {
                    "seal": seal_record("control/report.jsonl", helper_report_seal),
                    "recordCount": len(helper_records),
                    "eventCounts": event_counts,
                    "normalizedSha256": sha256_bytes(normalized_helper_bytes),
                    "normalizedObservations": normalized_helper_records,
                },
                "releaseSetAudit": release_set_audit,
                "packageManifests": package_manifests,
                "releaseVersion": release_version,
                "nativePlatform": platform_name,
                "scenario": scenario,
                "importProcess": import_observation,
                "build4200": {
                    "build": BUILD,
                    "path": str(sublime_binary),
                    "version": version.strip(),
                    "seal": seal_record("sublime-text", helper_seals["sublime-text"]),
                },
                "artifactSetFiles": [
                    seal_record(name, artifact_snapshot_seals[name])
                    for name in sorted(artifact_snapshot_seals)
                ],
                "materializedMembers": sorted(
                    materialized_members,
                    key=lambda record: (record["archiveKind"], record["memberName"]),
                ),
                "installedInexTree": {
                    "directoryCount": len(installed_inex_seal.directories),
                    "fileCount": len(tree_files),
                    "treeSha256": tree_digest,
                    "files": tree_files,
                },
                "packagedExecutables": [
                    {
                        "product": "inex",
                        "memberName": cli_member,
                        "productionResolution": "rust-portable-package",
                        "seal": seal_record("inex", executable_seals["inex"]),
                    },
                    {
                        "product": "inexd",
                        "memberName": "Inex/bin/inexd",
                        "productionResolution": "package-owned-default-empty-setting",
                        "seal": seal_record("inexd", executable_seals["inexd"]),
                    },
                ],
                "tools": [
                    {
                        "name": name,
                        "path": str(resolved_helpers[name]),
                        "version": helper_versions.get(name),
                        "seal": seal_record(name, helper_seals[name]),
                    }
                    for name in sorted(resolved_helpers)
                ],
                "harnessRuntime": {
                    "implementation": host_platform.python_implementation(),
                    "pythonVersion": host_platform.python_version(),
                },
                "childEnvironmentPolicy": {
                    "policy": "fixed-allowlist",
                    "allowedVariables": sorted(
                        restart_child_environment(root)
                        if args.full_application_kill_restart
                        else fixed_child_environment(root)
                    ),
                    "explicitScenarioVariables": [
                        "DBUS_SESSION_BUS_ADDRESS",
                        "DISPLAY",
                        "INEX_PASSWORD_STDIN",
                        "XAUTHORITY",
                    ],
                    "removedCategories": [
                        "GIT",
                        "INEX-nonessential",
                        "LD",
                        "proxy",
                        "PYTHON",
                    ],
                },
                "x11Isolation": {
                    "authentication": "isolated-root-xauthority-cookie",
                    "tcpListening": False,
                    "dbusAddress": "isolated-root-runtime-path",
                    **(
                        {
                            "gtkUsePortal": "0",
                            "dbusServiceActivation": "disabled-private-config",
                        }
                        if args.full_application_kill_restart
                        else {}
                    ),
                },
                "residueScan": {
                    "roots": ["isolated-root"],
                    "excludedRoots": [],
                    "pathScope": "all-relative-path-components",
                    "contentScope": "all-nonlink-regular-files-fail-closed",
                    "encodings": list(SCAN_ENCODINGS),
                    "randomFilenameCanaryScanned": True,
                    "entropyFragmentsScanned": True,
                    "entropyFragmentMinimumCharacters": 16,
                    "hits": 0,
                },
                "scenarioResult": scenario_result,
                "reportProtection": "create-new-posix-mode-0600",
                "rootDeletionVerified": True,
                "notCovered": report_not_covered(
                    scenario, str(summary["result"])
                ),
                "trustAssumptions": list(REPORT_TRUST_ASSUMPTIONS),
            }
            if args.full_application_kill_restart:
                artifact_report["restartLifecycle"] = {
                    "launchCount": restart_launch_count,
                    "sameProfilePath": True,
                    "sameInstalledPackageTree": True,
                    "childSubreaperConfirmed": child_subreaper_confirmed,
                    "processClosurePolicy": {
                        "stablePidfdIdentity": True,
                        "sessionAndDescendantClosure": True,
                        "subreaperAdoptionSweep": True,
                        "rootBindingSources": [
                            "cwd",
                            "environment",
                            "exe",
                            "fd",
                            "root",
                        ],
                        "argvOnlyIsNotBinding": True,
                        "unverifiedRootBoundSurvivors": 0,
                    },
                    "mountPolicy": {
                        "source": "/proc/self/mountinfo",
                        "boundedParser": True,
                        "checkpointRootMounts": 0,
                        "finalRootMounts": 0,
                        "successPathUnmounts": False,
                        "failurePortalUnmount": "exact-dead-fuse.portal-non-lazy-only",
                    },
                    "signalDelivery": "pidfd-per-stable-session-descendant-closure",
                    "killSignal": "SIGKILL",
                    "killedProcessClosureCount": restart_killed_session_process_count,
                    "isolatedEnvironment": process_environment_binding_values,
                    "profileDirectoryBindings": restart_profile_bindings,
                    "installedPackageTreeSha256ByLaunch": restart_installed_tree_digests,
                    "canaryFingerprintSetSha256": restart_checkpoint_state_binding[
                        "tokenFingerprintSetSha256"
                    ],
                    "pluginHostExecutable": {
                        "path": str(restart_plugin_host_path),
                        "seal": seal_record(
                            "plugin-host-3.8", restart_plugin_host_seal
                        ),
                    },
                    "firstLaunchProcessIdentities": restart_first_identities,
                    "oldProcessIdentitiesDead": restart_old_identities_dead,
                    "checkpoint": {
                        "stateSeal": seal_record(
                            "control/state.json", restart_checkpoint_state_seal
                        ),
                        "stateBinding": restart_checkpoint_state_binding,
                        "runtimeAndSocketsStopped": True,
                        "residueScan": {
                            "roots": ["isolated-root-after-sigkill-before-second-launch"],
                            "excludedRoots": [],
                            "pathScope": "all-relative-path-components",
                            "contentScope": "all-nonlink-regular-files-fail-closed",
                            "encodings": list(SCAN_ENCODINGS),
                            "randomFilenameCanaryScanned": True,
                            "entropyFragmentsScanned": True,
                            "entropyFragmentMinimumCharacters": 16,
                            "hits": 0,
                        },
                    },
                    "secondLaunchProcessIdentities": restart_second_identities,
                    "secondLaunchIdentitiesDistinct": True,
                }
            pending_artifact_report = encode_artifact_report(artifact_report)
        print(json.dumps(summary, sort_keys=True), flush=True)
        final_success = True
        return 0
    finally:
        cleanup_failure: Optional[QaFailure] = None
        try:
            terminate_sublime_tree(sublime_main_pid, sublime_process, root)
        except QaFailure as error:
            cleanup_failure = error
        if window_manager_process is not None:
            if window_manager_snapshot is None:
                cleanup_failure = QaFailure("window manager identity is unavailable")
            else:
                terminate_process_snapshot(window_manager_snapshot, 0.2)
        if xvfb_process is not None:
            if xvfb_snapshot is None:
                cleanup_failure = QaFailure("Xvfb identity is unavailable")
            else:
                terminate_process_snapshot(xvfb_snapshot, 0.2)
        if dbus_snapshot is not None:
            terminate_process_snapshot(dbus_snapshot, 0.2)
            reap_subreaper_process(dbus_snapshot)
        if cleanup_failure is None:
            try:
                wait_for_no_root_bindings(
                    root, root_binding_environment_values, 5
                )
            except QaFailure as error:
                cleanup_failure = error
        if cleanup_failure is not None:
            raise cleanup_failure
        if artifact_mode:
            cleanup_active_artifact_root(
                allow_dead_failure_portal_unmount=not final_success
            )
            if final_success:
                if output_path is None or pending_artifact_report is None:
                    raise QaFailure("artifact report was not ready after successful cleanup")
                write_artifact_report(output_path, pending_artifact_report)
                print(
                    "artifact-report-sha256=" + sha256_bytes(pending_artifact_report),
                    flush=True,
                )
        elif args.keep or not final_success:
            print("retained-root=" + str(root), flush=True)
        else:
            shutil.rmtree(root)
            if os.path.lexists(root):
                raise QaFailure("successful isolated root deletion was not verified")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (QaFailure, subprocess.SubprocessError, OSError) as error:
        try:
            cleanup_active_artifact_root(
                allow_dead_failure_portal_unmount=True
            )
        except QaFailure as cleanup_error:
            print(
                "artifact-root-cleanup-failed=" + type(cleanup_error).__name__,
                file=sys.stderr,
                flush=True,
            )
        print("result=FAIL " + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
