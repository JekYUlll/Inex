#!/usr/bin/env python3
"""Rehearse a final Inex artifact through import, backup, restore, and compatibility read."""

from __future__ import annotations

import argparse
import base64
import binascii
from collections.abc import Iterable, Mapping, Sequence
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import platform as host_platform
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata

from audit_release_artifacts import (
    artifact_identity,
    audit_directory,
    parse_checksums,
    read_zip_entries_from_bytes,
    validate_rust,
    validate_sublime,
    validate_vscode,
)
from release_common import (
    MAX_ARCHIVE_TOTAL_BYTES,
    REPOSITORY_ROOT,
    ReleaseError,
    require_regular_file,
    sha256_bytes,
    source_revision,
)


MAX_MARKDOWN_BYTES = 16 * 1024 * 1024
MAX_RPC_FRAME_BYTES = 24 * 1024 * 1024
MAX_RPC_HEADER_BYTES = 8 * 1024
MAX_PROCESS_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_SNAPSHOT_BYTES = 3 * MAX_ARCHIVE_TOTAL_BYTES + 1024 * 1024
RPC_TIMEOUT_SECONDS = 60
SCAN_CHUNK_BYTES = 64 * 1024
FIXED_GIT_DATE = "2000-01-01T00:00:00Z"
FROZEN_V1_LOGICAL_PATH = "2026/07/兼容性.md"
FROZEN_V1_HASHES = {
    "document.md.enc.b64": "3ec89edc86736759fc03c57f5e97e996de3b2325a088285726d3e07828c050d7",
    "expected.json": "cae8df89ebafd4b43ad5d465be2ee8287d098c48eeb11f8aa8da375728584595",
    "vault.json": "0ed664c68d102cf3edb040f09c2c8be53407cd23765e87c3eb755c8e3a443a41",
    "vector.json": "f4234f39a41e959544de8f34c1d7def164200a44a350f0ed146582f036209c99",
}
WINDOWS_REPARSE_POINT = 0x0400
PR_SET_CHILD_SUBREAPER = 36
MAX_DESCENDANT_PROCESSES = 1024
MAX_PROC_CHILDREN_BYTES = 64 * 1024
DESCENDANT_CLEANUP_SECONDS = 10
_LINUX_SUBREAPER_ENABLED = False


def is_link_like(path: Path, metadata: os.stat_result | None = None) -> bool:
    try:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        value = metadata if metadata is not None else path.lstat()
        return bool(getattr(value, "st_file_attributes", 0) & WINDOWS_REPARSE_POINT)
    except OSError:
        return True


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a destructive-to-temporary-storage-only import, password, Git backup, "
            "restore, authenticated byte-comparison, and frozen-v1 compatibility-read drill."
        )
    )
    parser.add_argument("directory", type=Path, help="Audited platform artifact directory")
    parser.add_argument(
        "--fixture-directory",
        type=Path,
        default=REPOSITORY_ROOT / "fixtures" / "v1-fixed",
        help="Committed public frozen-v1 fixture directory",
    )
    return parser.parse_args()


def native_platform() -> str:
    system = host_platform.system().casefold()
    machine = host_platform.machine().casefold()
    architecture = {
        "amd64": "x64",
        "x86_64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(machine)
    operating_system = {"linux": "linux", "windows": "windows"}.get(system)
    if architecture is None or operating_system is None:
        raise ReleaseError("the current host is not a supported native release target")
    return f"{operating_system}-{architecture}"


def strict_base64url_decode(value: str, label: str) -> bytes:
    if re.fullmatch(r"[A-Za-z0-9_-]*", value) is None:
        raise ReleaseError(f"{label} is not canonical unpadded base64url")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except (ValueError, binascii.Error) as error:
        raise ReleaseError(f"{label} is not canonical unpadded base64url") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != value:
        raise ReleaseError(f"{label} is not canonical unpadded base64url")
    return decoded


def sensitive_variants(values: Iterable[bytes]) -> tuple[bytes, ...]:
    variants: set[bytes] = set()
    for value in values:
        if not value:
            raise ReleaseError("a lifecycle secret cannot be empty")
        variants.add(value)
        standard_base64 = base64.b64encode(value)
        url_base64 = base64.urlsafe_b64encode(value)
        variants.update(
            {
                standard_base64,
                standard_base64.rstrip(b"="),
                url_base64,
                url_base64.rstrip(b"="),
            }
        )
        # If a secret is embedded in a larger Base64 stream, its first bytes can
        # share a quartet with one or two preceding bytes.  Retain only complete
        # internal three-byte groups for each possible stream alignment; these
        # produce stable needles independent of the surrounding bytes.
        for preceding_bytes in range(3):
            skipped = (3 - preceding_bytes) % 3
            internal = value[skipped:]
            internal = internal[: len(internal) - len(internal) % 3]
            if len(internal) >= 12:
                variants.add(base64.b64encode(internal))
                variants.add(base64.urlsafe_b64encode(internal))
        variants.add(value.hex().encode("ascii"))
        variants.add(value.hex().upper().encode("ascii"))
        try:
            text = value.decode("utf-8", "strict")
        except UnicodeError:
            continue
        variants.add(text.encode("utf-16-le"))
        variants.add(text.encode("utf-16-be"))
    return tuple(sorted(variants, key=lambda item: (len(item), item)))


def assert_no_sensitive_bytes(data: bytes, needles: Sequence[bytes], label: str) -> None:
    if any(needle in data for needle in needles):
        raise ReleaseError(f"dynamic sensitive data reached {label}")


def file_contains_any(path: Path, needles: Sequence[bytes]) -> bool:
    before = path.lstat()
    if is_link_like(path, before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ReleaseError("a residue-audit file changed identity")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
    overlap_size = max((len(needle) for needle in needles), default=1) - 1
    overlap = b""
    found = False
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not os.path.samestat(before, opened)
        ):
            raise ReleaseError("a residue-audit file changed identity")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(SCAN_CHUNK_BYTES)
                if not chunk:
                    break
                data = overlap + chunk
                if any(needle in data for needle in needles):
                    found = True
                    break
                overlap = data[-overlap_size:] if overlap_size else b""
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        not os.path.samestat(opened, after)
        or opened.st_size != after.st_size
        or opened.st_mtime_ns != after.st_mtime_ns
        or opened.st_ctime_ns != after.st_ctime_ns
    ):
        raise ReleaseError("a residue-audit file changed during scan")
    return found


def iter_regular_files(root: Path) -> Iterable[Path]:
    metadata = root.lstat()
    if is_link_like(root, metadata):
        raise ReleaseError("a residue-audit root cannot be a symbolic link")
    if stat.S_ISREG(metadata.st_mode):
        yield root
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise ReleaseError("a residue-audit root must be a regular file or directory")
    root_device = metadata.st_dev
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        for name in list(directory_names):
            child = current_path / name
            child_metadata = child.lstat()
            if (
                is_link_like(child, child_metadata)
                or not stat.S_ISDIR(child_metadata.st_mode)
                or child_metadata.st_dev != root_device
            ):
                raise ReleaseError("a residue-audit tree contains a non-directory entry")
        for name in file_names:
            child = current_path / name
            child_metadata = child.lstat()
            if (
                is_link_like(child, child_metadata)
                or not stat.S_ISREG(child_metadata.st_mode)
                or child_metadata.st_nlink != 1
                or child_metadata.st_dev != root_device
            ):
                raise ReleaseError("a residue-audit tree contains a non-regular file")
            yield child


def scan_sensitive_path_components(root: Path, needles: Sequence[bytes]) -> list[Path]:
    files = list(iter_regular_files(root))
    relative_names = [root.name]
    if root.is_dir():
        relative_names.extend(directory_manifest(root))
    relative_names.extend(path.relative_to(root).as_posix() for path in files)
    for relative_name in relative_names:
        for component in relative_name.split("/"):
            encoded_component = os.fsencode(component)
            assert_no_sensitive_bytes(
                encoded_component, needles, "an audited disk path component"
            )
            assert_no_sensitive_bytes(
                component.encode("utf-16-le"),
                needles,
                "an audited disk path component",
            )
            assert_no_sensitive_bytes(
                component.encode("utf-16-be"),
                needles,
                "an audited disk path component",
            )
    return files


def scan_for_sensitive_data(roots: Iterable[Path], needles: Sequence[bytes]) -> None:
    for root in roots:
        files = scan_sensitive_path_components(root, needles)
        for path in files:
            if file_contains_any(path, needles):
                raise ReleaseError("dynamic sensitive data reached an audited disk root")


def sha256_file(path: Path) -> str:
    before = path.lstat()
    if is_link_like(path, before) or not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ReleaseError("a hash input is not a single-link regular file")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not os.path.samestat(before, opened)
        ):
            raise ReleaseError("a hash input changed identity")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        not os.path.samestat(opened, after)
        or opened.st_size != after.st_size
        or opened.st_mtime_ns != after.st_mtime_ns
        or opened.st_ctime_ns != after.st_ctime_ns
    ):
        raise ReleaseError("a hash input changed during hashing")
    return digest.hexdigest()


def read_bounded_regular_file(path: Path, limit: int) -> bytes:
    before = path.lstat()
    if (
        is_link_like(path, before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > limit
    ):
        raise ReleaseError("an artifact snapshot file is unsafe or oversized")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
    data = bytearray()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > limit
            or not os.path.samestat(before, opened)
        ):
            raise ReleaseError("an artifact snapshot file changed identity")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(min(1024 * 1024, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise ReleaseError("an artifact snapshot file exceeds its size ceiling")
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        not os.path.samestat(opened, after)
        or opened.st_size != after.st_size
        or opened.st_mtime_ns != after.st_mtime_ns
        or opened.st_ctime_ns != after.st_ctime_ns
    ):
        raise ReleaseError("an artifact snapshot file changed during capture")
    return bytes(data)


def snapshot_regular_tree(root: Path) -> dict[str, str]:
    if is_link_like(root) or not root.is_dir():
        raise ReleaseError("snapshot root must be a non-symlink directory")
    snapshot: dict[str, str] = {}
    for path in iter_regular_files(root):
        relative = path.relative_to(root).as_posix()
        snapshot[relative] = sha256_file(path)
    return snapshot


def directory_manifest(root: Path) -> tuple[str, ...]:
    if is_link_like(root) or not root.is_dir():
        raise ReleaseError("manifest root must be a non-symlink directory")
    root_device = root.lstat().st_dev
    directories = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        directory_names.sort()
        file_names.sort()
        for name in directory_names:
            child = current_path / name
            metadata = child.lstat()
            if (
                is_link_like(child, metadata)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_dev != root_device
            ):
                raise ReleaseError("a backup source contains a non-directory entry")
            directories.append(child.relative_to(root).as_posix())
        for name in file_names:
            child = current_path / name
            metadata = child.lstat()
            if (
                is_link_like(child, metadata)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_dev != root_device
            ):
                raise ReleaseError("a backup source contains a non-regular file")
    return tuple(directories)


def copy_regular_tree(source: Path, destination: Path) -> None:
    source_files = snapshot_regular_tree(source)
    source_directories = directory_manifest(source)
    destination.mkdir(parents=True, exist_ok=False)
    for relative in source_directories:
        (destination / relative).mkdir()
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    for relative in sorted(source_files):
        input_path = source / relative
        output_path = destination / relative
        before = input_path.lstat()
        if (
            is_link_like(input_path, before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ReleaseError("a backup source file changed identity")
        input_fd = os.open(input_path, os.O_RDONLY | no_follow | binary)
        try:
            opened = os.fstat(input_fd)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or not os.path.samestat(before, opened)
            ):
                raise ReleaseError("a backup source file changed identity")
            output_fd = os.open(
                output_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | binary,
                before.st_mode & 0o777,
            )
            try:
                with os.fdopen(input_fd, "rb", closefd=False) as input_handle, os.fdopen(
                    output_fd, "wb", closefd=False
                ) as output_handle:
                    shutil.copyfileobj(input_handle, output_handle, 1024 * 1024)
                    output_handle.flush()
                    os.fsync(output_fd)
            finally:
                os.close(output_fd)
        finally:
            os.close(input_fd)
        after = input_path.lstat()
        if not os.path.samestat(opened, after):
            raise ReleaseError("a backup source file changed during copy")
        if os.name != "nt":
            output_path.chmod(before.st_mode & 0o777)
    if snapshot_regular_tree(source) != source_files:
        raise ReleaseError("a backup source tree changed during copy")
    if directory_manifest(source) != source_directories:
        raise ReleaseError("a backup source directory set changed during copy")
    if snapshot_regular_tree(destination) != source_files:
        raise ReleaseError("a filesystem backup differs from its source")
    if directory_manifest(destination) != source_directories:
        raise ReleaseError("a filesystem backup lost an empty directory")


def copy_bounded_regular_file(source: Path, destination: Path, limit: int) -> int:
    before = source.lstat()
    if (
        is_link_like(source, before)
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > limit
    ):
        raise ReleaseError("release artifact snapshot input is unsafe or oversized")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    input_descriptor = os.open(source, os.O_RDONLY | no_follow | binary)
    try:
        opened = os.fstat(input_descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > limit
            or not os.path.samestat(before, opened)
        ):
            raise ReleaseError("release artifact snapshot input changed identity")
        output_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | binary,
            0o600,
        )
        total = 0
        try:
            with os.fdopen(input_descriptor, "rb", closefd=False) as input_handle, os.fdopen(
                output_descriptor, "wb", closefd=False
            ) as output_handle:
                while True:
                    chunk = input_handle.read(min(1024 * 1024, limit + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limit:
                        raise ReleaseError("release artifact snapshot exceeds its size ceiling")
                    output_handle.write(chunk)
                output_handle.flush()
                os.fsync(output_descriptor)
        finally:
            os.close(output_descriptor)
    finally:
        os.close(input_descriptor)
    after = source.lstat()
    if (
        not os.path.samestat(opened, after)
        or opened.st_size != after.st_size
        or opened.st_mtime_ns != after.st_mtime_ns
        or opened.st_ctime_ns != after.st_ctime_ns
        or total != opened.st_size
    ):
        raise ReleaseError("release artifact snapshot input changed during capture")
    return total


def snapshot_artifact_directory(source: Path, destination: Path) -> None:
    try:
        root_before = source.lstat()
    except OSError as error:
        raise ReleaseError("release artifact directory is unavailable") from error
    if is_link_like(source, root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise ReleaseError("release artifact directory is unsafe")
    try:
        children = sorted(source.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise ReleaseError("release artifact directory is unavailable") from error
    names = {path.name for path in children}
    if (
        len(children) != 4
        or "SHA256SUMS" not in names
        or sum(name.startswith("inex-") for name in names) != 3
    ):
        raise ReleaseError("release artifact directory does not have four bounded files")
    archive_kinds = set()
    declared_total = 0
    for path in children:
        metadata = path.lstat()
        limit = 1024 * 1024 if path.name == "SHA256SUMS" else MAX_ARCHIVE_TOTAL_BYTES
        if (
            is_link_like(path, metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > limit
        ):
            raise ReleaseError("release artifact snapshot input is unsafe or oversized")
        declared_total += metadata.st_size
        if declared_total > MAX_ARTIFACT_SNAPSHOT_BYTES:
            raise ReleaseError("release artifact snapshot exceeds its total size ceiling")
        if path.name != "SHA256SUMS":
            kind, _version, _platform = artifact_identity(path.name)
            archive_kinds.add(kind)
    if archive_kinds != {"rust", "vscode", "sublime"}:
        raise ReleaseError("release artifact snapshot input is incomplete")
    destination.mkdir(parents=True, exist_ok=False)
    captured_total = 0
    for path in children:
        limit = 1024 * 1024 if path.name == "SHA256SUMS" else MAX_ARCHIVE_TOTAL_BYTES
        captured_total += copy_bounded_regular_file(
            path, destination / path.name, limit
        )
        if captured_total > MAX_ARTIFACT_SNAPSHOT_BYTES:
            raise ReleaseError("release artifact snapshot exceeds its total size ceiling")
    try:
        root_after = source.lstat()
        final_names = {path.name for path in source.iterdir()}
    except OSError as error:
        raise ReleaseError("release artifact directory changed during capture") from error
    if (
        is_link_like(source, root_after)
        or not os.path.samestat(root_before, root_after)
        or root_before.st_mtime_ns != root_after.st_mtime_ns
        or root_before.st_ctime_ns != root_after.st_ctime_ns
        or final_names != names
    ):
        raise ReleaseError("release artifact directory changed during capture")


def encrypted_document_hashes(root: Path) -> dict[str, str]:
    hashes = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in root.rglob("*.md.enc")
        if path.is_file() and not is_link_like(path)
    }
    if not hashes:
        raise ReleaseError("lifecycle vault contains no encrypted documents")
    return hashes


def assert_no_plaintext_markdown(root: Path) -> None:
    if any(path.name.casefold().endswith(".md") for path in iter_regular_files(root)):
        raise ReleaseError("a lifecycle vault contains a plaintext Markdown file")


def expected_imported_physical_layout(
    expected: Mapping[str, bytes],
) -> tuple[set[str], set[str]]:
    files = {"vault.json", ".vault-local/mutation.lock"}
    directories = {".vault-local"}
    for logical_path in expected:
        parts = logical_path.split("/")
        files.add(logical_path + ".enc")
        for length in range(1, len(parts)):
            directories.add("/".join(parts[:length]))
    return files, directories


def assert_imported_vault_physical_layout(
    root: Path, expected: Mapping[str, bytes]
) -> None:
    expected_files, expected_directories = expected_imported_physical_layout(expected)
    observed_files = {
        path.relative_to(root).as_posix() for path in iter_regular_files(root)
    }
    observed_directories = set(directory_manifest(root))
    if observed_files != expected_files or observed_directories != expected_directories:
        raise ReleaseError("imported vault physical entries differ from the ciphertext allowlist")
    for relative in sorted(expected_files - {"vault.json", ".vault-local/mutation.lock"}):
        envelope = read_bounded_regular_file(root / relative, MAX_MARKDOWN_BYTES * 2)
        if not envelope.startswith(b"EDRY"):
            raise ReleaseError("imported vault contains a non-EDRY document payload")


def assert_frozen_product_unchanged(
    before: Mapping[str, str], after: Mapping[str, str]
) -> None:
    if any(after.get(path) != digest for path, digest in before.items()):
        raise ReleaseError("final daemon rewrote a frozen-v1 product file")
    runtime_files = set(after) - set(before)
    if runtime_files != {".vault-local/mutation.lock"}:
        raise ReleaseError("final daemon added an unexpected frozen-v1 runtime file")


def _write_regular(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | binary,
            0o600,
        )
    except OSError as error:
        raise ReleaseError("lifecycle fixture path unexpectedly exists or is unsafe") from error
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)


def create_plaintext_source(
    root: Path, canary: bytes, *, max_markdown_bytes: int = MAX_MARKDOWN_BYTES
) -> dict[str, bytes]:
    if max_markdown_bytes < 64 or max_markdown_bytes > MAX_MARKDOWN_BYTES:
        raise ReleaseError("test maximum Markdown size is outside the product bound")
    root.mkdir(parents=True, exist_ok=False)
    unicode_content = (
        b"\xef\xbb\xbf# Unicode lifecycle\r\n"
        + "中文/emoji 🧪/combining e\u0301\n".encode()
        + b"canary="
        + canary
        + b"\r\nend\n"
    )
    maximum_prefix = b"# exact maximum Markdown boundary\ncanary=" + canary + b"\n"
    maximum_content = maximum_prefix + b"x" * (max_markdown_bytes - len(maximum_prefix))
    entries = (
        ("empty.md", "empty.md", b""),
        ("unicode/兼容性.md", "unicode/兼容性.md", unicode_content),
        ("unicode/e\u0301.md", "unicode/é.md", b"decomposed filename\n" + canary + b"\n"),
        ("newlines/mixed.md", "newlines/mixed.md", b"LF\nCRLF\r\nCR\rend\n" + canary),
        ("maximum/boundary.md", "maximum/boundary.md", maximum_content),
    )
    expected: dict[str, bytes] = {}
    for source_name, logical_name, content in entries:
        _write_regular(root / source_name, content)
        canonical = unicodedata.normalize("NFC", logical_name)
        if canonical in expected:
            raise ReleaseError("lifecycle source has a normalized path collision")
        expected[canonical] = content
    _write_regular(root / "skipped-attachment.bin", b"public skipped attachment\n")
    return expected


def assert_plaintext_source_preserved(
    root: Path,
    expected_files: Mapping[str, str],
    expected_directories: Sequence[str],
    path_needles: Sequence[bytes],
) -> None:
    if snapshot_regular_tree(root) != expected_files:
        raise ReleaseError("copy import changed the plaintext source tree")
    if directory_manifest(root) != tuple(expected_directories):
        raise ReleaseError("copy import changed the plaintext source directory set")
    scan_sensitive_path_components(root, path_needles)


def assert_harness_source_unchanged(
    repository_root: Path,
    expected_hashes: Mapping[str, str],
    expected_source: Mapping[str, object],
) -> None:
    final_hashes = {
        name: sha256_file(repository_root / name) for name in expected_hashes
    }
    if final_hashes != expected_hashes:
        raise ReleaseError("release lifecycle harness changed while it was running")
    if source_revision(repository_root) != expected_source:
        raise ReleaseError("release lifecycle source provenance changed while it was running")


def controlled_environment(root: Path) -> dict[str, str]:
    environment: dict[str, str] = {}
    for name in ("PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC"):
        value = os.environ.get(name)
        if value:
            environment[name] = value
    home = root / "home"
    temporary = root / "tmp"
    app_data = root / "appdata" / "roaming"
    local_app_data = root / "appdata" / "local"
    for path in (home, temporary, app_data, local_app_data):
        path.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "HOME": str(home),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"),
            "XDG_STATE_HOME": str(root / "state"),
            "TMP": str(temporary),
            "TEMP": str(temporary),
            "TMPDIR": str(temporary),
            "USERPROFILE": str(home),
            "APPDATA": str(app_data),
            "LOCALAPPDATA": str(local_app_data),
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _argv_bytes(arguments: Sequence[os.PathLike[str] | str]) -> bytes:
    return b"\0".join(os.fsencode(argument) for argument in arguments)


def _reap_adopted_children() -> None:
    if host_platform.system().casefold() != "linux":
        return
    while True:
        try:
            child, _status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if child == 0:
            return


def _linux_direct_children(process_id: int) -> set[int]:
    task_root = Path("/proc") / str(process_id) / "task"
    try:
        tasks = sorted(task_root.iterdir(), key=lambda path: path.name)
    except (FileNotFoundError, ProcessLookupError):
        return set()
    except OSError as error:
        raise ReleaseError("Linux descendant census is unavailable") from error
    if len(tasks) > MAX_DESCENDANT_PROCESSES:
        raise ReleaseError("Linux descendant thread count exceeds the harness ceiling")
    children: set[int] = set()
    for task in tasks:
        try:
            with (task / "children").open("rb", buffering=0) as handle:
                data = handle.read(MAX_PROC_CHILDREN_BYTES + 1)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except OSError as error:
            raise ReleaseError("Linux descendant census could not read procfs") from error
        if len(data) > MAX_PROC_CHILDREN_BYTES:
            raise ReleaseError("Linux descendant census exceeds its byte ceiling")
        for token in data.split():
            if not token.isdigit():
                raise ReleaseError("Linux descendant census returned an invalid PID")
            child = int(token)
            if child <= 1 or child == os.getpid():
                raise ReleaseError("Linux descendant census returned an unsafe PID")
            children.add(child)
            if len(children) > MAX_DESCENDANT_PROCESSES:
                raise ReleaseError("Linux descendant count exceeds the harness ceiling")
    return children


def _linux_descendants(process_id: int) -> set[int]:
    descendants: set[int] = set()
    pending = list(_linux_direct_children(process_id))
    while pending:
        child = pending.pop()
        if child in descendants:
            continue
        descendants.add(child)
        if len(descendants) > MAX_DESCENDANT_PROCESSES:
            raise ReleaseError("Linux descendant count exceeds the harness ceiling")
        pending.extend(_linux_direct_children(child) - descendants)
    return descendants


def _enable_linux_subreaper() -> None:
    global _LINUX_SUBREAPER_ENABLED
    if host_platform.system().casefold() != "linux" or _LINUX_SUBREAPER_ENABLED:
        return
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise ReleaseError("Linux pidfd descendant control is unavailable")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.restype = ctypes.c_int
        result = prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    except (AttributeError, OSError) as error:
        raise ReleaseError("Linux child-subreaper control is unavailable") from error
    if result != 0:
        error_number = ctypes.get_errno()
        raise ReleaseError(
            f"Linux child-subreaper control failed with errno {error_number}"
        )
    proc_children = Path("/proc") / str(os.getpid()) / "task"
    if not proc_children.is_dir():
        raise ReleaseError("Linux procfs descendant control is unavailable")
    _LINUX_SUBREAPER_ENABLED = True


def prepare_process_isolation() -> None:
    if host_platform.system().casefold() != "linux":
        return
    _enable_linux_subreaper()
    _reap_adopted_children()
    if _linux_descendants(os.getpid()):
        raise ReleaseError("lifecycle harness has a pre-existing child process")


def _kill_linux_pid(process_id: int) -> None:
    try:
        descriptor = os.pidfd_open(process_id, 0)
    except ProcessLookupError:
        return
    except OSError as error:
        raise ReleaseError("Linux descendant pidfd could not be opened") from error
    try:
        try:
            signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise ReleaseError("Linux descendant could not be terminated") from error
    finally:
        os.close(descriptor)


def cleanup_process_descendants(process: subprocess.Popen[bytes]) -> None:
    terminate_process(process)
    if host_platform.system().casefold() != "linux":
        return
    deadline = time.monotonic() + DESCENDANT_CLEANUP_SECONDS
    while True:
        _reap_adopted_children()
        descendants = _linux_descendants(os.getpid())
        if not descendants:
            return
        for process_id in descendants:
            _kill_linux_pid(process_id)
        if time.monotonic() >= deadline:
            raise ReleaseError("Linux descendant processes could not be terminated")
        time.sleep(0.01)


class BoundedPipeReader:
    def __init__(
        self,
        stream: io.BufferedReader,
        needles: Sequence[bytes],
        label: str,
    ) -> None:
        self._stream = stream
        self._needles = needles
        self._label = label
        self._data = bytearray()
        self._overflow = False
        self._sensitive = False
        self._error: OSError | None = None
        self._thread = threading.Thread(target=self._read, daemon=True)

    def _read(self) -> None:
        overlap_size = max((len(needle) for needle in self._needles), default=1) - 1
        overlap = b""
        try:
            while True:
                chunk = self._stream.read(SCAN_CHUNK_BYTES)
                if not chunk:
                    break
                combined = overlap + chunk
                if any(needle in combined for needle in self._needles):
                    self._sensitive = True
                overlap = combined[-overlap_size:] if overlap_size else b""
                remaining = MAX_PROCESS_OUTPUT_BYTES - len(self._data)
                if remaining > 0:
                    self._data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self._overflow = True
        except OSError as error:
            self._error = error
        finally:
            try:
                self._stream.close()
            except OSError as error:
                if self._error is None:
                    self._error = error

    def start(self) -> None:
        self._thread.start()

    def finish(self, *, timeout: int = 10) -> bytes:
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            raise ReleaseError(f"{self._label} did not reach EOF")
        if self._error is not None:
            raise ReleaseError(f"{self._label} could not be read") from self._error
        data = bytes(self._data)
        if self._overflow:
            raise ReleaseError(f"{self._label} exceeded the output ceiling")
        if self._sensitive or any(needle in data for needle in self._needles):
            raise ReleaseError(f"dynamic sensitive data reached {self._label}")
        return data


def terminate_process(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        try:
            # start_new_session makes the leader PID the process-group ID.  A
            # descendant can keep the group and inherited pipes alive after the
            # leader exits, so deliberately attempt group cleanup even then.
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()


def finish_pipe_readers(*readers: BoundedPipeReader) -> tuple[bytes, ...]:
    outputs: list[bytes] = []
    first_error: BaseException | None = None
    for reader in readers:
        try:
            outputs.append(reader.finish())
        except BaseException as error:
            outputs.append(b"")
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise first_error
    return tuple(outputs)


def run_process(
    arguments: Sequence[os.PathLike[str] | str],
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
    cwd: Path | None = None,
    input_data: bytes = b"",
    expected_statuses: frozenset[int] = frozenset({0}),
    timeout: int = 180,
) -> subprocess.CompletedProcess[bytes]:
    assert_no_sensitive_bytes(_argv_bytes(arguments), needles, "a child-process argv")
    encoded_environment = b"\0".join(
        os.fsencode(name) + b"=" + os.fsencode(value)
        for name, value in sorted(environment.items())
    )
    assert_no_sensitive_bytes(encoded_environment, needles, "a child-process environment")
    prepare_process_isolation()
    process = subprocess.Popen(
        [os.fspath(argument) for argument in arguments],
        cwd=cwd if cwd is not None else environment["TMPDIR"],
        env=dict(environment),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        terminate_process(process)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired as error:
            raise ReleaseError("a lifecycle child process could not be terminated") from error
        cleanup_process_descendants(process)
        raise ReleaseError("a lifecycle child process did not expose standard streams")
    stdout_reader = BoundedPipeReader(process.stdout, needles, "a child-process stdout")
    stderr_reader = BoundedPipeReader(process.stderr, needles, "a child-process stderr")
    stdout_reader.start()
    stderr_reader.start()
    try:
        process.stdin.write(input_data)
        process.stdin.close()
        process.stdin = None
        status = process.wait(timeout=timeout)
    except (BrokenPipeError, OSError, subprocess.TimeoutExpired) as error:
        terminate_process(process)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired as wait_error:
            raise ReleaseError("a lifecycle child process could not be terminated") from wait_error
        cleanup_process_descendants(process)
        finish_pipe_readers(stdout_reader, stderr_reader)
        raise ReleaseError("a lifecycle child process did not complete safely") from error
    # Remove any descendants that survived a successful leader exit before
    # waiting for inherited output pipes to reach EOF.
    cleanup_process_descendants(process)
    try:
        stdout, stderr = finish_pipe_readers(stdout_reader, stderr_reader)
    except BaseException:
        cleanup_process_descendants(process)
        finish_pipe_readers(stdout_reader, stderr_reader)
        raise
    if status not in expected_statuses:
        raise ReleaseError("a lifecycle child process returned an unexpected status")
    return subprocess.CompletedProcess(
        [os.fspath(argument) for argument in arguments], status, stdout, stderr
    )


def run_cli(
    executable: Path,
    arguments: Sequence[os.PathLike[str] | str],
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
    password_lines: Sequence[bytes] = (),
) -> subprocess.CompletedProcess[bytes]:
    command_environment = dict(environment)
    input_data = b""
    if password_lines:
        command_environment["INEX_PASSWORD_STDIN"] = "1"
        input_data = b"".join(line + b"\n" for line in password_lines)
    return run_process(
        [executable, *arguments],
        environment=command_environment,
        needles=needles,
        input_data=input_data,
    )


def require_stdout_lines(
    result: subprocess.CompletedProcess[bytes], lines: Sequence[bytes], label: str
) -> None:
    observed = set(result.stdout.splitlines())
    missing = [line for line in lines if line not in observed]
    if missing:
        try:
            fixed_line = missing[0].decode("ascii", "strict")
        except UnicodeError as error:
            raise ReleaseError("a lifecycle expected-output contract is not ASCII") from error
        raise ReleaseError(f"{label} omitted fixed result line: {fixed_line}")


def verify_locked_structure(
    executable: Path,
    vault: Path,
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
) -> None:
    result = run_cli(
        executable,
        ["verify", vault],
        environment=environment,
        needles=needles,
    )
    lines = result.stdout.splitlines()
    if (
        result.stderr
        or len(lines) != 10
        or lines[0] != b"verification-mode: locked-structural"
        or lines[1] != b"mutation-lock: acquired"
        or lines[2] != b"pending-ciphertext-transaction: none"
        or lines[3] != b"vault-metadata: structurally-valid-untrusted"
        or re.fullmatch(rb"directories: [0-9]+", lines[4]) is None
        or re.fullmatch(rb"documents: [0-9]+", lines[5]) is None
        or re.fullmatch(rb"weak-kdf-slots: [0-9]+", lines[6]) is None
        or lines[7] != b"authenticated-content: not-performed"
        or lines[8] != b"pending-git-merge-transaction: none"
        or lines[9]
        != b"result: locked structure valid; unlock is required for authenticity"
    ):
        raise ReleaseError("locked structural verification output is not exact")


def capture_audited_artifacts(
    snapshot: Path,
) -> tuple[
    dict[str, dict[str, tuple[bytes, int]]],
    dict[str, str],
    dict[str, object],
    str,
    str,
]:
    validated = audit_directory(snapshot, require_clean_source=True)
    checksums = parse_checksums(snapshot / "SHA256SUMS")
    if set(validated) != set(checksums):
        raise ReleaseError("audited artifact names differ from the captured checksums")
    entries_by_kind: dict[str, dict[str, tuple[bytes, int]]] = {}
    source_identity: dict[str, object] | None = None
    release_version: str | None = None
    release_platform: str | None = None
    validators = {
        "rust": validate_rust,
        "vscode": validate_vscode,
        "sublime": validate_sublime,
    }
    for name in sorted(validated):
        kind, version, platform_name = artifact_identity(name)
        raw = read_bounded_regular_file(snapshot / name, MAX_ARCHIVE_TOTAL_BYTES)
        if sha256_bytes(raw) != checksums[name]:
            raise ReleaseError("captured artifact bytes differ from SHA256SUMS")
        entries = read_zip_entries_from_bytes(raw, name)
        validators[kind](
            entries,
            require_clean_source=True,
            expected_platform=platform_name,
            expected_version=version,
        )
        manifest_name = {
            "rust": f"inex-{version}-{platform_name}/PACKAGE-MANIFEST.json",
            "vscode": "extension/PACKAGE-MANIFEST.json",
            "sublime": "Inex/PACKAGE-MANIFEST.json",
        }[kind]
        try:
            manifest = json.loads(entries[manifest_name][0])
            source = manifest["source"]
        except (KeyError, UnicodeError, json.JSONDecodeError, TypeError) as error:
            raise ReleaseError("captured artifact manifest is unavailable") from error
        if not isinstance(source, dict):
            raise ReleaseError("captured artifact source provenance is invalid")
        if source_identity is None:
            source_identity = source
            release_version = version
            release_platform = platform_name
        elif (
            source != source_identity
            or version != release_version
            or platform_name != release_platform
        ):
            raise ReleaseError("captured artifacts do not share one provenance")
        entries_by_kind[kind] = entries
    if (
        set(entries_by_kind) != {"rust", "vscode", "sublime"}
        or source_identity is None
        or release_version is None
        or release_platform is None
    ):
        raise ReleaseError("captured artifact set is incomplete")
    return (
        entries_by_kind,
        checksums,
        source_identity,
        release_version,
        release_platform,
    )


def extract_packaged_binaries(
    entries: Mapping[str, tuple[bytes, int]], artifact_platform: str, destination: Path
) -> tuple[Path, Path]:
    expected_platform = native_platform()
    if artifact_platform != expected_platform:
        raise ReleaseError("the release artifact does not match the current native host")
    suffix = ".exe" if artifact_platform.startswith("windows-") else ""
    cli_names = [name for name in entries if name.endswith(f"/bin/inex{suffix}")]
    daemon_names = [name for name in entries if name.endswith(f"/bin/inexd{suffix}")]
    if len(cli_names) != 1 or len(daemon_names) != 1:
        raise ReleaseError("the Rust archive executable layout is invalid")
    destination.mkdir(parents=True, exist_ok=False)

    def extract(name: str) -> Path:
        content, mode = entries[name]
        output = destination / Path(name).name
        _write_regular(output, content)
        if os.name != "nt":
            output.chmod(mode)
        return require_regular_file(output, "packaged executable", executable=True)

    return extract(cli_names[0]), extract(daemon_names[0])


def _read_exact(stream: io.BufferedReader, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = stream.read(length - len(data))
        if not chunk:
            raise ReleaseError("packaged daemon truncated an RPC response")
        data.extend(chunk)
    return bytes(data)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError("packaged daemon returned duplicate RPC object keys")
        result[key] = value
    return result


def read_rpc_response(
    stream: io.BufferedReader,
    expected_id: int,
    forbidden_needles: Sequence[bytes] = (),
) -> dict[str, object]:
    header = bytearray()
    while not header.endswith(b"\r\n\r\n"):
        byte = stream.read(1)
        if not byte:
            raise ReleaseError("packaged daemon closed before an RPC response")
        header.extend(byte)
        if len(header) > MAX_RPC_HEADER_BYTES:
            raise ReleaseError("packaged daemon returned an oversized RPC header")
    match = re.fullmatch(rb"Content-Length: ([0-9]+)\r\n\r\n", bytes(header))
    if match is None:
        raise ReleaseError("packaged daemon returned a noncanonical RPC header")
    content_length = int(match.group(1))
    if content_length > MAX_RPC_FRAME_BYTES:
        raise ReleaseError("packaged daemon returned an oversized RPC frame")
    body = _read_exact(stream, content_length)
    assert_no_sensitive_bytes(body, forbidden_needles, "a framed daemon response")
    try:
        text = body.decode("utf-8", "strict")
        response = json.loads(text, object_pairs_hook=_unique_json_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("packaged daemon returned invalid RPC JSON") from error
    if (
        not isinstance(response, dict)
        or response.get("jsonrpc") != "2.0"
        or type(response.get("id")) is not int
        or response.get("id") != expected_id
        or set(response)
        not in (
            {"jsonrpc", "id", "result"},
            {"jsonrpc", "id", "error"},
        )
    ):
        raise ReleaseError("packaged daemon returned a mismatched RPC response")
    return response


class RpcProcess:
    def __init__(
        self,
        executable: Path,
        environment: Mapping[str, str],
        needles: Sequence[bytes],
        response_needles: Sequence[bytes] = (),
    ) -> None:
        assert_no_sensitive_bytes(os.fsencode(executable), needles, "the daemon argv")
        self._needles = needles
        self._response_needles = list(response_needles)
        prepare_process_isolation()
        self._process = subprocess.Popen(
            [str(executable)],
            env=dict(environment),
            cwd=environment["TMPDIR"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
        if (
            self._process.stdin is None
            or self._process.stdout is None
            or self._process.stderr is None
        ):
            terminate_process(self._process)
            try:
                self._process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                raise ReleaseError("packaged daemon process tree could not be terminated") from error
            cleanup_process_descendants(self._process)
            raise ReleaseError("packaged daemon stdio was unavailable")
        self._stderr_reader = BoundedPipeReader(
            self._process.stderr, needles, "daemon stderr"
        )
        self._stderr_reader.start()

    def forbid_response_values(self, values: Iterable[bytes]) -> None:
        for variant in sensitive_variants(values):
            if variant not in self._response_needles:
                self._response_needles.append(variant)

    def call(self, request_id: int, method: str, params: Mapping[str, object]) -> dict[str, object]:
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": dict(params),
        }
        body = json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_RPC_FRAME_BYTES:
            raise ReleaseError("lifecycle RPC request exceeds the protocol limit")
        frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
        try:
            self._process.stdin.write(frame)
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise ReleaseError("packaged daemon rejected an RPC request") from error
        responses: list[dict[str, object]] = []
        errors: list[BaseException] = []

        def read_response() -> None:
            try:
                responses.append(
                    read_rpc_response(
                        self._process.stdout,
                        request_id,
                        self._response_needles,
                    )
                )
            except BaseException as error:
                errors.append(error)

        reader = threading.Thread(target=read_response, daemon=True)
        reader.start()
        reader.join(timeout=RPC_TIMEOUT_SECONDS)
        if reader.is_alive():
            self.abort()
            reader.join(timeout=10)
            raise ReleaseError("packaged daemon timed out during an RPC response")
        if errors:
            raise errors[0]
        if len(responses) != 1:
            raise ReleaseError("packaged daemon response reader lost synchronization")
        return responses[0]

    def finish(self) -> None:
        if self._process.stdin is not None:
            self._process.stdin.close()
            self._process.stdin = None
        stdout_reader = BoundedPipeReader(
            self._process.stdout, self._needles, "daemon trailing stdout"
        )
        stdout_reader.start()
        try:
            status = self._process.wait(timeout=30)
        except subprocess.TimeoutExpired as error:
            self.abort()
            try:
                stdout_reader.finish()
            except ReleaseError:
                pass
            raise ReleaseError("packaged daemon did not exit after shutdown") from error
        cleanup_process_descendants(self._process)
        try:
            stdout_tail, stderr = finish_pipe_readers(
                stdout_reader, self._stderr_reader
            )
        except BaseException:
            terminate_process(self._process)
            finish_pipe_readers(stdout_reader, self._stderr_reader)
            raise
        if status != 0 or stdout_tail or stderr:
            raise ReleaseError("packaged daemon did not shut down cleanly")

    def abort(self) -> None:
        terminate_process(self._process)
        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise ReleaseError("packaged daemon process tree could not be terminated")
        cleanup_process_descendants(self._process)
        self._stderr_reader.finish()
        try:
            self._process.stdout.close()
        except OSError:
            pass


def _rpc_result(
    response: Mapping[str, object], label: str, expected_keys: set[str]
) -> dict[str, object]:
    result = response.get("result")
    if (
        set(response) != {"jsonrpc", "id", "result"}
        or response.get("jsonrpc") != "2.0"
        or not isinstance(result, dict)
        or set(result) != expected_keys
    ):
        raise ReleaseError(f"packaged daemon failed the {label} RPC")
    return result


def _is_canonical_uuid(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        value,
    ) is not None


def require_hello_response(response: Mapping[str, object]) -> None:
    result = _rpc_result(
        response,
        "hello",
        {"server", "serverVersion", "protocolMajor", "capabilities"},
    )
    capabilities = [
        "vault",
        "files",
        "documents",
        "encryptedDrafts",
        "search",
        "authenticatedPing",
    ]
    if (
        result.get("server") != "inexd"
        or not isinstance(result.get("serverVersion"), str)
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?", result["serverVersion"])
        is None
        or type(result.get("protocolMajor")) is not int
        or result.get("protocolMajor") != 1
        or result.get("capabilities") != capabilities
    ):
        raise ReleaseError("packaged daemon returned an invalid hello result")


def require_unlock_response(response: Mapping[str, object]) -> str:
    result = _rpc_result(
        response,
        "unlock",
        {"session", "vaultId", "idleTimeoutMs", "warnings"},
    )
    session = result.get("session")
    warnings = result.get("warnings")
    if (
        not isinstance(session, str)
        or len(strict_base64url_decode(session, "session capability")) != 32
        or not _is_canonical_uuid(result.get("vaultId"))
        or type(result.get("idleTimeoutMs")) is not int
        or result["idleTimeoutMs"] < 0
        or not isinstance(warnings, list)
    ):
        raise ReleaseError("packaged daemon returned an invalid unlock result")
    for warning in warnings:
        if (
            not isinstance(warning, dict)
            or set(warning) != {"name", "slotId"}
            or warning.get("name") != "WEAK_KDF"
            or not _is_canonical_uuid(warning.get("slotId"))
        ):
            raise ReleaseError("packaged daemon returned an invalid unlock warning")
    return session


def require_acknowledgement(response: Mapping[str, object], label: str) -> None:
    result = _rpc_result(response, label, {"ok"})
    if result != {"ok": True}:
        raise ReleaseError(f"packaged daemon returned an invalid {label} acknowledgement")


def require_file_read_result(
    response: Mapping[str, object], logical_path: str
) -> str:
    result = _rpc_result(
        response, "file.read", {"contentBase64", "etag", "metadata"}
    )
    metadata = result.get("metadata")
    if (
        not isinstance(result.get("contentBase64"), str)
        or not isinstance(result.get("etag"), str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", result["etag"]) is None
        or not isinstance(metadata, dict)
        or set(metadata)
        != {"fileId", "logicalPath", "createdAt", "modifiedAt", "flags"}
        or not _is_canonical_uuid(metadata.get("fileId"))
        or metadata.get("logicalPath") != logical_path
        or type(metadata.get("createdAt")) is not int
        or type(metadata.get("modifiedAt")) is not int
        or type(metadata.get("flags")) is not int
        or metadata["createdAt"] < 0
        or metadata["modifiedAt"] < 0
        or metadata["flags"] < 0
    ):
        raise ReleaseError("packaged daemon returned an invalid file.read result")
    return result["contentBase64"]


def expected_tree_entries(expected: Mapping[str, bytes]) -> set[tuple[str, str]]:
    entries: set[tuple[str, str]] = set()
    for logical_path in expected:
        parts = logical_path.split("/")
        entries.add(("file", logical_path))
        for length in range(1, len(parts)):
            entries.add(("directory", "/".join(parts[:length])))
    return entries


def rpc_read_and_compare(
    daemon: Path,
    vault: Path,
    password: bytes,
    expected: Mapping[str, bytes],
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
) -> None:
    rpc = RpcProcess(
        daemon,
        environment,
        needles,
        sensitive_variants((password,)),
    )
    try:
        require_hello_response(
            rpc.call(
                1,
                "system.hello",
                {"client": "release-lifecycle", "clientVersion": "1", "protocolMajor": 1},
            )
        )
        session = require_unlock_response(
            rpc.call(
                2,
                "vault.unlock",
                {"vaultPath": str(vault), "password": password.decode("utf-8", "strict")},
            )
        )
        if isinstance(needles, list):
            needles.extend(
                variant
                for variant in sensitive_variants((session.encode("ascii", "strict"),))
                if variant not in needles
            )
        rpc.forbid_response_values((session.encode("ascii", "strict"),))
        tree = _rpc_result(
            rpc.call(3, "vault.listTree", {"session": session}),
            "vault.listTree",
            {"entries"},
        )
        raw_entries = tree.get("entries")
        if not isinstance(raw_entries, list):
            raise ReleaseError("packaged daemon omitted the logical tree")
        observed_entries: list[tuple[str, str]] = []
        for entry in raw_entries:
            if not isinstance(entry, dict) or set(entry) != {"kind", "logicalPath"}:
                raise ReleaseError("packaged daemon returned an invalid logical tree entry")
            kind = entry.get("kind")
            logical_path = entry.get("logicalPath")
            if kind not in {"file", "directory"} or not isinstance(logical_path, str):
                raise ReleaseError("packaged daemon returned an invalid logical tree entry")
            observed_entries.append((kind, logical_path))
        if (
            len(observed_entries) != len(set(observed_entries))
            or set(observed_entries) != expected_tree_entries(expected)
        ):
            raise ReleaseError("authenticated logical tree differs from the imported source")
        request_id = 4
        for logical_path, expected_bytes in sorted(expected.items()):
            encoded = require_file_read_result(
                rpc.call(
                    request_id,
                    "file.read",
                    {"session": session, "logicalPath": logical_path},
                ),
                logical_path,
            )
            observed = strict_base64url_decode(encoded, "file.read content")
            if observed != expected_bytes:
                raise ReleaseError("restored authenticated plaintext differs from the source")
            request_id += 1
        require_acknowledgement(
            rpc.call(request_id, "vault.lock", {"session": session}), "lock"
        )
        require_acknowledgement(
            rpc.call(request_id + 1, "system.shutdown", {}), "shutdown"
        )
        rpc.finish()
    except BaseException:
        rpc.abort()
        raise


def rpc_require_unlock_failure(
    daemon: Path,
    vault: Path,
    password: bytes,
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
) -> None:
    rpc = RpcProcess(
        daemon,
        environment,
        needles,
        sensitive_variants((password,)),
    )
    try:
        require_hello_response(
            rpc.call(
                1,
                "system.hello",
                {"client": "release-lifecycle", "clientVersion": "1", "protocolMajor": 1},
            )
        )
        failed = rpc.call(
            2,
            "vault.unlock",
            {"vaultPath": str(vault), "password": password.decode("utf-8", "strict")},
        )
        if not is_auth_failed_response(failed):
            raise ReleaseError("retired password unexpectedly unlocked the vault")
        require_acknowledgement(rpc.call(3, "system.shutdown", {}), "shutdown")
        rpc.finish()
    except BaseException:
        rpc.abort()
        raise


def is_auth_failed_response(response: Mapping[str, object]) -> bool:
    error = response.get("error")
    data = error.get("data") if isinstance(error, dict) else None
    return (
        set(response) == {"jsonrpc", "id", "error"}
        and response.get("jsonrpc") == "2.0"
        and type(response.get("id")) is int
        and response.get("id") == 2
        and isinstance(error, dict)
        and set(error) == {"code", "message", "data"}
        and error.get("code") == -32_000
        and error.get("message") == "Authentication failed"
        and isinstance(data, dict)
        and set(data) == {"name"}
        and data.get("name") == "AUTH_FAILED"
    )


def git_command(
    git: Path,
    repository: Path | None,
    arguments: Sequence[os.PathLike[str] | str],
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
    expected_statuses: frozenset[int] = frozenset({0}),
) -> subprocess.CompletedProcess[bytes]:
    prefix: list[os.PathLike[str] | str] = [git]
    if repository is not None:
        prefix.extend(["-C", repository])
    return run_process(
        [*prefix, *arguments],
        environment=environment,
        needles=needles,
        expected_statuses=expected_statuses,
    )


def git_version(
    git: Path, *, environment: Mapping[str, str], needles: Sequence[bytes]
) -> str:
    result = git_command(
        git, None, ["--version"], environment=environment, needles=needles
    )
    try:
        value = result.stdout.decode("ascii", "strict").strip()
    except UnicodeError as error:
        raise ReleaseError("Git returned a non-ASCII version") from error
    match = re.fullmatch(r"git version ([0-9]+)\.([0-9]+)(?:\.[0-9A-Za-z.-]+)?", value)
    if match is None or (int(match.group(1)), int(match.group(2))) < (2, 36):
        raise ReleaseError("Git does not meet the 2.36 release-drill baseline")
    return value.removeprefix("git version ")


def filesystem_type(
    path: Path, *, environment: Mapping[str, str], needles: Sequence[bytes]
) -> str:
    if host_platform.system().casefold() != "linux":
        return "native-windows-unreported"
    stat_path = shutil.which("stat", path=environment.get("PATH"))
    if stat_path is None:
        raise ReleaseError("GNU stat is required to identify the Linux test filesystem")
    stat_executable = Path(stat_path).resolve(strict=True)
    require_regular_file(stat_executable, "GNU stat executable", executable=True)
    result = run_process(
        [stat_executable, "-f", "-c", "%T", path],
        environment=environment,
        needles=needles,
    )
    try:
        value = result.stdout.decode("ascii", "strict").strip()
    except UnicodeError as error:
        raise ReleaseError("filesystem type is not ASCII") from error
    if re.fullmatch(r"[A-Za-z0-9._+/-]+", value) is None:
        raise ReleaseError("filesystem type has an unexpected representation")
    return value


def verify_driver_configuration(
    git: Path,
    repository: Path,
    cli: Path,
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
) -> None:
    result = git_command(
        git,
        repository,
        ["config", "--local", "--get", "merge.inex.driver"],
        environment=environment,
        needles=needles,
    )
    try:
        driver = result.stdout.decode("utf-8", "strict").strip()
    except UnicodeError as error:
        raise ReleaseError("installed Git driver is not UTF-8") from error
    canonical_cli = str(cli.resolve(strict=True))
    if "%" in canonical_cli:
        raise ReleaseError("packaged executable path contains a Git driver placeholder marker")
    if driver != shell_quote(canonical_cli) + " merge-driver":
        raise ReleaseError("installed Git driver is not one canonical absolute command")


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


def assert_single_commit_repository(
    git: Path,
    repository: Path,
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
    expected_head: str | None = None,
) -> str:
    head_result = git_command(
        git,
        repository,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        environment=environment,
        needles=needles,
    )
    try:
        head = head_result.stdout.decode("ascii", "strict").strip()
    except UnicodeError as error:
        raise ReleaseError("Git returned a non-ASCII commit identity") from error
    if (
        re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", head) is None
        or head_result.stderr
        or (expected_head is not None and head != expected_head)
    ):
        raise ReleaseError("Git backup HEAD does not match the single expected commit")

    refs_result = git_command(
        git,
        repository,
        ["for-each-ref", "--format=%(refname)%00%(objectname)"],
        environment=environment,
        needles=needles,
    )
    if refs_result.stderr:
        raise ReleaseError("Git emitted diagnostics while enumerating backup refs")
    refs: dict[str, str] = {}
    try:
        for line in refs_result.stdout.splitlines():
            name_bytes, oid_bytes = line.split(b"\0", 1)
            name = name_bytes.decode("ascii", "strict")
            oid = oid_bytes.decode("ascii", "strict")
            if name in refs:
                raise ReleaseError("Git returned a duplicate backup ref")
            refs[name] = oid
    except (UnicodeError, ValueError) as error:
        raise ReleaseError("Git returned an invalid backup ref listing") from error
    if refs != {"refs/heads/main": head}:
        raise ReleaseError("Git backup contains hidden or unexpected refs")

    count_result = git_command(
        git,
        repository,
        ["rev-list", "--count", "--all"],
        environment=environment,
        needles=needles,
    )
    if count_result.stdout != b"1\n" or count_result.stderr:
        raise ReleaseError("Git backup does not contain exactly one reachable commit")
    fsck_result = git_command(
        git,
        repository,
        ["fsck", "--full", "--strict", "--unreachable", "--no-reflogs"],
        environment=environment,
        needles=needles,
    )
    if fsck_result.stdout or fsck_result.stderr:
        raise ReleaseError("Git backup contains unreachable objects or fsck diagnostics")
    return head


def create_and_restore_git_backup(
    git: Path,
    cli: Path,
    vault: Path,
    bundle: Path,
    restored: Path,
    *,
    environment: Mapping[str, str],
    needles: Sequence[bytes],
) -> str:
    if os.path.lexists(vault / ".git"):
        raise ReleaseError("imported vault already contains a Git repository")
    hooks = bundle.parent / "empty-hooks"
    hooks.mkdir()
    git_command(
        git,
        None,
        ["init", "--initial-branch=main", vault],
        environment=environment,
        needles=needles,
    )
    installed = run_cli(
        cli,
        ["git", "install-driver", vault],
        environment=environment,
        needles=needles,
    )
    require_stdout_lines(
        installed,
        [b"git-config-scope: repository-local", b"local-config-verified: yes"],
        "Git driver installation",
    )
    verify_driver_configuration(
        git, vault, cli, environment=environment, needles=needles
    )
    git_command(git, vault, ["add", "--all"], environment=environment, needles=needles)
    commit_environment = dict(environment)
    commit_environment.update(
        {
            "GIT_AUTHOR_NAME": "Inex Release Drill",
            "GIT_AUTHOR_EMAIL": "release-drill@invalid.example",
            "GIT_COMMITTER_NAME": "Inex Release Drill",
            "GIT_COMMITTER_EMAIL": "release-drill@invalid.example",
            "GIT_AUTHOR_DATE": FIXED_GIT_DATE,
            "GIT_COMMITTER_DATE": FIXED_GIT_DATE,
        }
    )
    git_command(
        git,
        vault,
        ["-c", f"core.hooksPath={hooks}", "-c", "commit.gpgSign=false", "commit", "-m", "release lifecycle drill"],
        environment=commit_environment,
        needles=needles,
    )
    status = git_command(
        git, vault, ["status", "--porcelain=v1"], environment=environment, needles=needles
    )
    if status.stdout:
        raise ReleaseError("imported vault is dirty after its backup commit")
    source_head = assert_single_commit_repository(
        git,
        vault,
        environment=environment,
        needles=needles,
    )
    git_command(
        git,
        vault,
        ["bundle", "create", bundle, "--all"],
        environment=environment,
        needles=needles,
    )
    git_command(
        git,
        vault,
        ["bundle", "verify", bundle],
        environment=environment,
        needles=needles,
    )
    git_command(
        git,
        None,
        ["clone", "--no-local", "--branch", "main", bundle, restored],
        environment=environment,
        needles=needles,
    )
    absent = git_command(
        git,
        restored,
        ["config", "--local", "--get", "merge.inex.driver"],
        environment=environment,
        needles=needles,
        expected_statuses=frozenset({1}),
    )
    if absent.stdout or absent.stderr:
        raise ReleaseError("fresh restore unexpectedly inherited local Git driver state")
    git_command(
        git,
        restored,
        ["remote", "remove", "origin"],
        environment=environment,
        needles=needles,
    )
    assert_single_commit_repository(
        git,
        restored,
        environment=environment,
        needles=needles,
        expected_head=source_head,
    )
    reinstalled = run_cli(
        cli,
        ["git", "install-driver", restored],
        environment=environment,
        needles=needles,
    )
    require_stdout_lines(
        reinstalled,
        [b"git-config-scope: repository-local", b"local-config-verified: yes"],
        "restored Git driver installation",
    )
    verify_driver_configuration(
        git, restored, cli, environment=environment, needles=needles
    )
    restored_status = git_command(
        git,
        restored,
        ["status", "--porcelain=v1"],
        environment=environment,
        needles=needles,
    )
    if restored_status.stdout:
        raise ReleaseError("restored vault changed while reinstalling the local driver")
    assert_single_commit_repository(
        git,
        restored,
        environment=environment,
        needles=needles,
        expected_head=source_head,
    )
    return source_head


FROZEN_V1_MAX_ENTRIES = 4
FROZEN_V1_FILE_LIMITS = {
    "document.md.enc.b64": 32 * 1024 * 1024,
    "expected.json": 1024 * 1024,
    "vault.json": 1024 * 1024,
    "vector.json": 1024 * 1024,
}
FROZEN_V1_MAX_TOTAL_BYTES = 33 * 1024 * 1024


def capture_frozen_v1_fixture(source: Path) -> dict[str, bytes]:
    expected_names = tuple(sorted(FROZEN_V1_HASHES))
    if set(FROZEN_V1_FILE_LIMITS) != set(FROZEN_V1_HASHES):
        raise ReleaseError("frozen-v1 capture limits do not match the reviewed vector")
    try:
        root_before = source.lstat()
    except OSError as error:
        raise ReleaseError("frozen-v1 fixture directory is unavailable") from error
    if is_link_like(source, root_before) or not stat.S_ISDIR(root_before.st_mode):
        raise ReleaseError("frozen-v1 fixture root is unsafe")
    try:
        children = sorted(source.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise ReleaseError("frozen-v1 fixture directory is unavailable") from error
    observed_names = tuple(path.name for path in children)
    if len(children) != FROZEN_V1_MAX_ENTRIES or observed_names != expected_names:
        raise ReleaseError("frozen-v1 fixture must contain exactly four reviewed files")

    declared_total = 0
    for path in children:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise ReleaseError("frozen-v1 fixture entry is unavailable") from error
        limit = FROZEN_V1_FILE_LIMITS[path.name]
        if (
            is_link_like(path, metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_dev != root_before.st_dev
            or metadata.st_size > limit
        ):
            raise ReleaseError("frozen-v1 fixture entry is unsafe or oversized")
        declared_total += metadata.st_size
        if declared_total > FROZEN_V1_MAX_TOTAL_BYTES:
            raise ReleaseError("frozen-v1 fixture exceeds its total size ceiling")

    captured = {
        path.name: read_bounded_regular_file(path, FROZEN_V1_FILE_LIMITS[path.name])
        for path in children
    }
    if sum(len(content) for content in captured.values()) > FROZEN_V1_MAX_TOTAL_BYTES:
        raise ReleaseError("frozen-v1 fixture exceeds its total size ceiling")
    try:
        root_after = source.lstat()
        final_names = tuple(sorted(path.name for path in source.iterdir()))
    except OSError as error:
        raise ReleaseError("frozen-v1 fixture changed during capture") from error
    if (
        is_link_like(source, root_after)
        or not stat.S_ISDIR(root_after.st_mode)
        or not os.path.samestat(root_before, root_after)
        or root_before.st_mtime_ns != root_after.st_mtime_ns
        or root_before.st_ctime_ns != root_after.st_ctime_ns
        or final_names != expected_names
    ):
        raise ReleaseError("frozen-v1 fixture changed during capture")
    captured_hashes = {
        name: sha256_bytes(content) for name, content in captured.items()
    }
    if captured_hashes != FROZEN_V1_HASHES:
        raise ReleaseError("frozen-v1 fixture identity differs from the reviewed vector")
    return captured


def prepare_frozen_v1_fixture(source: Path, destination: Path) -> tuple[bytes, dict[str, bytes]]:
    captured = capture_frozen_v1_fixture(source)
    try:
        vector = json.loads(captured["vector.json"].decode("utf-8"))
        encoded_document = captured["document.md.enc.b64"].decode("ascii").strip()
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("frozen-v1 fixture is unreadable") from error
    if not isinstance(vector, dict):
        raise ReleaseError("frozen-v1 vector is not an object")
    password = vector.get("passwordUtf8")
    logical_path = vector.get("logicalPath")
    plaintext = vector.get("plaintextBase64Url")
    if not all(isinstance(value, str) for value in (password, logical_path, plaintext)):
        raise ReleaseError("frozen-v1 vector omits required strings")
    if logical_path != FROZEN_V1_LOGICAL_PATH:
        raise ReleaseError("frozen-v1 vector has an unexpected logical path")
    password_bytes = password.encode("utf-8")
    envelope = strict_base64url_decode(encoded_document, "frozen-v1 EDRY envelope")
    plaintext_bytes = strict_base64url_decode(plaintext, "frozen-v1 plaintext")
    destination.mkdir(parents=True, exist_ok=False)
    _write_regular(destination / "vault.json", captured["vault.json"])
    physical = destination / "2026" / "07" / "兼容性.md.enc"
    _write_regular(physical, envelope)
    return password_bytes, {logical_path: plaintext_bytes}


class EvidenceDirectory:
    def __init__(self) -> None:
        self.path: Path | None = None

    def __enter__(self) -> Path:
        self.path = Path(tempfile.mkdtemp(prefix="inex-release-lifecycle-"))
        if os.name != "nt":
            self.path.chmod(0o700)
        return self.path

    def __exit__(self, exception_type: object, _exception: object, _traceback: object) -> None:
        if self.path is None:
            return
        if exception_type is None:
            shutil.rmtree(self.path)
        else:
            print(
                f"drill_release_lifecycle: failure evidence retained at {self.path}",
                file=sys.stderr,
            )


def run_lifecycle_drill(artifact_directory: Path, fixture_directory: Path) -> dict[str, object]:
    if os.name == "nt":
        raise ReleaseError(
            "native Windows lifecycle evidence requires Job Object and NTFS ADS coverage"
        )
    artifact_directory = artifact_directory.resolve(strict=True)
    fixture_directory = fixture_directory.resolve(strict=True)
    harness_source = source_revision(REPOSITORY_ROOT)
    if harness_source.get("dirtySourceTree") is not False:
        raise ReleaseError("release lifecycle evidence requires a clean harness source tree")
    harness_hashes = {
        "scripts/audit_release_artifacts.py": sha256_file(
            REPOSITORY_ROOT / "scripts" / "audit_release_artifacts.py"
        ),
        "scripts/drill_release_lifecycle.py": sha256_file(Path(__file__).resolve(strict=True)),
        "scripts/release_common.py": sha256_file(
            REPOSITORY_ROOT / "scripts" / "release_common.py"
        ),
        "scripts/tests/test_release_artifacts.py": sha256_file(
            REPOSITORY_ROOT / "scripts" / "tests" / "test_release_artifacts.py"
        ),
        "scripts/tests/test_release_lifecycle.py": sha256_file(
            REPOSITORY_ROOT / "scripts" / "tests" / "test_release_lifecycle.py"
        ),
    }
    with EvidenceDirectory() as temporary:
        artifact_snapshot = temporary / "artifact-snapshot"
        snapshot_artifact_directory(artifact_directory, artifact_snapshot)
        (
            artifact_entries,
            artifact_hashes,
            artifact_source,
            release_version,
            platform_name,
        ) = capture_audited_artifacts(artifact_snapshot)
        environment = controlled_environment(temporary / "environment")
        cli, daemon = extract_packaged_binaries(
            artifact_entries["rust"], platform_name, temporary / "packaged-bin"
        )
        relocated_cli, relocated_daemon = extract_packaged_binaries(
            artifact_entries["rust"], platform_name, temporary / "relocated-bin"
        )
        old_password = ("old-" + secrets.token_urlsafe(32)).encode("ascii")
        new_password = ("new-" + secrets.token_urlsafe(32)).encode("ascii")
        canary = ("INEX_LIFECYCLE_" + secrets.token_hex(24)).encode("ascii")
        needles = list(sensitive_variants((old_password, new_password, canary)))

        source = temporary / "plaintext-source"
        expected = create_plaintext_source(source, canary)
        source_before = snapshot_regular_tree(source)
        source_directories_before = directory_manifest(source)
        vault = temporary / "imported-vault"

        dry_run = run_cli(
            cli,
            ["import", source, vault, "--dry-run"],
            environment=environment,
            needles=needles,
        )
        require_stdout_lines(
            dry_run,
            [
                b"import-mode: dry-run",
                b"markdown-files: 5",
                b"skipped-non-markdown-files: 1",
                b"source-preserved: yes",
                b"import-writes: none",
                b"destination-created: no",
            ],
            "copy-import dry-run",
        )
        if vault.exists():
            raise ReleaseError("copy-import dry-run created its destination")

        imported = run_cli(
            cli,
            ["import", source, vault],
            environment=environment,
            needles=needles,
            password_lines=(old_password, old_password),
        )
        require_stdout_lines(
            imported,
            [
                b"import-mode: copy",
                b"committed-encrypted-files: 5",
                b"file-parent-sync-not-confirmed: 0",
                b"publish-parent-sync: synced",
                b"source-preserved: yes",
                b"destination: published-new-vault",
                b"result: staged copy import complete",
            ],
            "copy import",
        )
        assert_imported_vault_physical_layout(vault, expected)
        verify_locked_structure(
            cli, vault, environment=environment, needles=needles
        )
        assert_no_plaintext_markdown(vault)
        rpc_read_and_compare(
            daemon,
            vault,
            old_password,
            expected,
            environment=environment,
            needles=needles,
        )

        historical = temporary / "historical-password-backup"
        edry_before_password_change = encrypted_document_hashes(vault)
        metadata_before_password_change = (vault / "vault.json").read_bytes()
        copy_regular_tree(vault, historical)

        changed = run_cli(
            cli,
            ["password", "change", vault],
            environment=environment,
            needles=needles,
            password_lines=(old_password, new_password, new_password),
        )
        require_stdout_lines(
            changed,
            [
                b"password changed",
                b"new-slot-parent-sync: ParentSyncStatus::Synced",
                b"old-slot-removal-parent-sync: ParentSyncStatus::Synced",
            ],
            "password change",
        )
        if encrypted_document_hashes(vault) != edry_before_password_change:
            raise ReleaseError("password change rewrote an EDRY document")
        if (vault / "vault.json").read_bytes() == metadata_before_password_change:
            raise ReleaseError("password change did not replace vault metadata")
        rpc_require_unlock_failure(
            daemon,
            vault,
            old_password,
            environment=environment,
            needles=needles,
        )
        rpc_read_and_compare(
            daemon,
            historical,
            old_password,
            expected,
            environment=environment,
            needles=needles,
        )
        rpc_read_and_compare(
            daemon,
            vault,
            new_password,
            expected,
            environment=environment,
            needles=needles,
        )
        assert_imported_vault_physical_layout(vault, expected)

        git_path = shutil.which("git", path=environment.get("PATH"))
        if git_path is None:
            raise ReleaseError("Git is required for the lifecycle backup drill")
        git = Path(git_path).resolve(strict=True)
        require_regular_file(git, "Git executable", executable=True)
        git_version_value = git_version(
            git, environment=environment, needles=needles
        )
        filesystem_type_value = filesystem_type(
            temporary, environment=environment, needles=needles
        )
        bundle = temporary / "vault-backup.bundle"
        restored = temporary / "restored-vault"
        backup_head = create_and_restore_git_backup(
            git,
            cli,
            vault,
            bundle,
            restored,
            environment=environment,
            needles=needles,
        )
        verify_locked_structure(
            cli, restored, environment=environment, needles=needles
        )
        assert_no_plaintext_markdown(restored)
        rpc_read_and_compare(
            daemon,
            restored,
            new_password,
            expected,
            environment=environment,
            needles=needles,
        )

        filesystem_backup = temporary / "vault-filesystem-backup"
        filesystem_restored = temporary / "filesystem-restored-vault"
        copy_regular_tree(vault, filesystem_backup)
        copy_regular_tree(filesystem_backup, filesystem_restored)
        assert_single_commit_repository(
            git,
            filesystem_restored,
            environment=environment,
            needles=needles,
            expected_head=backup_head,
        )
        verify_driver_configuration(
            git,
            filesystem_restored,
            cli,
            environment=environment,
            needles=needles,
        )
        snapshot_driver = run_cli(
            relocated_cli,
            ["git", "install-driver", filesystem_restored],
            environment=environment,
            needles=needles,
        )
        require_stdout_lines(
            snapshot_driver,
            [b"git-config-scope: repository-local", b"local-config-verified: yes"],
            "filesystem-restore Git driver installation",
        )
        verify_driver_configuration(
            git,
            filesystem_restored,
            relocated_cli,
            environment=environment,
            needles=needles,
        )
        snapshot_status = git_command(
            git,
            filesystem_restored,
            ["status", "--porcelain=v1"],
            environment=environment,
            needles=needles,
        )
        if snapshot_status.stdout:
            raise ReleaseError("filesystem restore changed while reinstalling the local driver")
        assert_single_commit_repository(
            git,
            filesystem_restored,
            environment=environment,
            needles=needles,
            expected_head=backup_head,
        )
        verify_locked_structure(
            relocated_cli,
            filesystem_restored,
            environment=environment,
            needles=needles,
        )
        assert_no_plaintext_markdown(filesystem_restored)
        rpc_read_and_compare(
            relocated_daemon,
            filesystem_restored,
            new_password,
            expected,
            environment=environment,
            needles=needles,
        )

        frozen = temporary / "frozen-v1"
        fixture_password, fixture_expected = prepare_frozen_v1_fixture(
            fixture_directory, frozen
        )
        for variant in sensitive_variants(
            (fixture_password, *fixture_expected.values())
        ):
            if variant not in needles:
                needles.append(variant)
        frozen_before = snapshot_regular_tree(frozen)
        frozen_directories_before = set(directory_manifest(frozen))
        rpc_read_and_compare(
            daemon,
            frozen,
            fixture_password,
            fixture_expected,
            environment=environment,
            needles=needles,
        )
        frozen_after = snapshot_regular_tree(frozen)
        assert_frozen_product_unchanged(frozen_before, frozen_after)
        if set(directory_manifest(frozen)) != frozen_directories_before | {".vault-local"}:
            raise ReleaseError("final daemon added unexpected frozen-v1 directories")

        canary_needles = set(sensitive_variants((canary,)))
        source_path_needles = [
            needle for needle in needles if needle not in canary_needles
        ]
        assert_plaintext_source_preserved(
            source,
            source_before,
            source_directories_before,
            source_path_needles,
        )
        staging = list(temporary.glob(".inex-import-staging-*"))
        if staging:
            raise ReleaseError("successful copy import left a staging sibling")
        residue_scan_roots = [path for path in temporary.iterdir() if path != source]
        scan_for_sensitive_data(residue_scan_roots, needles)
        assert_harness_source_unchanged(
            REPOSITORY_ROOT,
            harness_hashes,
            harness_source,
        )

        return {
            "artifactSource": artifact_source,
            "auditedArtifactCount": len(artifact_hashes),
            "auditedArtifacts": [
                {"name": name, "sha256": artifact_hashes[name]}
                for name in sorted(artifact_hashes)
            ],
            "authenticatedExpectedBodies": len(expected),
            "cleanRegularFileTreeCopyRestoreVerified": True,
            "covered": [
                "copy-import-normal-path",
                "password-rewrap-and-historical-metadata-scope",
                "authenticated-expected-tree-and-body-comparison",
                "git-bundle-clone-and-fsck",
                "clean-regular-file-tree-copy-restore",
                "frozen-v1-compatibility-read",
                "sensitive-residue-scan-outside-designated-plaintext-source",
                "linux-subreaper-procfs-pidfd-descendant-cleanup",
                "clean-harness-provenance-recheck",
            ],
            "sensitiveResidueHitsOutsideDesignatedPlaintextSource": 0,
            "residueContentScanExcludedRoots": ["plaintext-source"],
            "designatedPlaintextSourcePathComponentsScanned": True,
            "driverRelocationVerified": True,
            "fixtureFiles": [
                {"name": name, "sha256": FROZEN_V1_HASHES[name]}
                for name in sorted(FROZEN_V1_HASHES)
            ],
            "frozenV1CompatibilityRead": True,
            "frozenV1ProductBytesUnchanged": True,
            "filesystemType": filesystem_type_value,
            "gitBundleVerified": True,
            "gitVersion": git_version_value,
            "linuxDescendantControl": "subreaper-procfs-pidfd",
            "harnessFiles": [
                {"name": name, "sha256": harness_hashes[name]}
                for name in sorted(harness_hashes)
            ],
            "harnessSource": harness_source,
            "markdownFiles": len(expected),
            "maxMarkdownBytes": MAX_MARKDOWN_BYTES,
            "nativePlatform": platform_name,
            "nativeRuntime": {
                "machine": host_platform.machine(),
                "release": host_platform.release(),
                "system": host_platform.system(),
            },
            "notCovered": [
                "adversarial-same-user-release-host-writer",
                "artifact-signing-and-publication",
                "fault-state-preservation-and-power-loss",
                "hosted-ci-execution",
                "independent-legal-review",
                "two-version-upgrade-and-rollback",
                "native-platforms-other-than-this-report",
                "editor-persistent-profile-residue",
                "independent-build-attestation-for-generated-inputs",
            ],
            "importedVaultPhysicalAllowlistVerified": True,
            "pythonVersion": host_platform.python_version(),
            "releaseLifecycleDrill": "passed",
            "reportScope": "lifecycle-only-non-release-approval",
            "releaseVersion": release_version,
            "restoredDriverReinstalled": True,
            "sourceHashesUnchanged": True,
            "sourceDirectorySetUnchanged": True,
            "historicalPasswordScopeVerified": True,
            "trustAssumptions": [
                "exclusive-quiescent-standalone-release-checkout",
                "no-same-principal-writer-from-process-start-through-evidence-capture",
                "trusted-immutable-toolchain-generated-inputs-and-artifact-directory",
            ],
        }


def main() -> int:
    arguments = parse_arguments()
    result = run_lifecycle_drill(arguments.directory, arguments.fixture_directory)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ReleaseError,
        OSError,
        UnicodeError,
        subprocess.SubprocessError,
        ValueError,
    ) as error:
        print(f"drill_release_lifecycle: {error}", file=sys.stderr)
        raise SystemExit(1) from None
