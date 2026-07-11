#!/usr/bin/env python3
"""Shared, dependency-free helpers for deterministic Inex release artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import shutil
import stat
import struct
import subprocess
import tarfile
import threading
import time
import tomllib
from typing import Any, Collection, Iterable, Mapping
import unicodedata
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
MAX_SOURCE_TRACKED_FILES = 16 * 1024
MAX_SOURCE_FILE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_SOURCE_GIT_LISTING_BYTES = 64 * 1024 * 1024
MAX_SOURCE_GIT_SMALL_OUTPUT_BYTES = 64 * 1024
MAX_SOURCE_GIT_STDERR_BYTES = 1024 * 1024
MAX_SOURCE_GIT_METADATA_BYTES = 1024 * 1024
MAX_SOURCE_UNTRACKED_IGNORE_FILES = 1024
MAX_SOURCE_GIT_ARGUMENT_BYTES = 32 * 1024
SOURCE_GIT_TIMEOUT_SECONDS = 60
WINDOWS_REPARSE_POINT = 0x0400

PLATFORMS: dict[str, dict[str, str]] = {
    "linux-x64": {
        "binary_suffix": "",
        "vscode_target": "linux-x64",
        "vscode_runtime": "linux-x64",
    },
    "linux-arm64": {
        "binary_suffix": "",
        "vscode_target": "linux-arm64",
        "vscode_runtime": "linux-arm64",
    },
    "windows-x64": {
        "binary_suffix": ".exe",
        "vscode_target": "win32-x64",
        "vscode_runtime": "win32-x64",
    },
    "windows-arm64": {
        "binary_suffix": ".exe",
        "vscode_target": "win32-arm64",
        "vscode_runtime": "win32-arm64",
    },
}


class ReleaseError(RuntimeError):
    """A release input or artifact violated a fail-closed invariant."""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_regular_file(path: Path, label: str, *, executable: bool = False) -> Path:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseError(f"{label} is unavailable: {path}") from error
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise ReleaseError(f"{label} must be a non-symlink regular file: {path}")
    if executable and os.name != "nt" and metadata.st_mode & 0o111 == 0:
        raise ReleaseError(f"{label} is not executable: {path}")
    return path


def _elf_c_string(data: bytes, offset: int, limit: int, label: str) -> str:
    if offset < 0 or offset >= len(data) or limit < offset or limit > len(data):
        raise ReleaseError(f"{label} ELF string offset is invalid")
    end = data.find(b"\0", offset, limit)
    if end < 0:
        raise ReleaseError(f"{label} ELF string is not terminated")
    try:
        return data[offset:end].decode("utf-8", "strict")
    except UnicodeError as error:
        raise ReleaseError(f"{label} ELF string is not UTF-8") from error


def _validate_linux_elf(data: bytes, platform: str, label: str) -> None:
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ReleaseError(f"{label} is not a 64-bit little-endian ELF executable")
    try:
        header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    except struct.error as error:
        raise ReleaseError(f"{label} has a truncated ELF header") from error
    machine = header[1]
    program_offset = header[4]
    program_entry_size = header[8]
    program_count = header[9]
    expected_machine, expected_interpreter = {
        "linux-x64": (0x3E, "/lib64/ld-linux-x86-64.so.2"),
        "linux-arm64": (0xB7, "/lib/ld-linux-aarch64.so.1"),
    }[platform]
    if header[0] not in {2, 3}:
        raise ReleaseError(f"{label} ELF type is not executable")
    if machine != expected_machine:
        raise ReleaseError(f"{label} ELF architecture does not match {platform}")
    if program_entry_size < 56 or program_count < 1 or program_count > 512:
        raise ReleaseError(f"{label} has an invalid ELF program-header table")
    if program_offset + program_entry_size * program_count > len(data):
        raise ReleaseError(f"{label} has a truncated ELF program-header table")

    program_headers = []
    interpreter = None
    dynamic_region = None
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        try:
            program = struct.unpack_from("<IIQQQQQQ", data, offset)
        except struct.error as error:
            raise ReleaseError(f"{label} has a malformed ELF program header") from error
        program_headers.append(program)
        kind, _flags, file_offset, _virtual, _physical, file_size, _memory_size, _align = program
        if file_offset + file_size > len(data):
            raise ReleaseError(f"{label} ELF segment exceeds the file")
        if kind == 3:
            interpreter = _elf_c_string(
                data, file_offset, file_offset + file_size, label
            )
        elif kind == 2:
            dynamic_region = (file_offset, file_size)
    if interpreter != expected_interpreter:
        raise ReleaseError(
            f"{label} uses a non-portable ELF interpreter: {interpreter or 'missing'}"
        )
    if dynamic_region is None:
        return
    dynamic_offset, dynamic_size = dynamic_region
    if dynamic_size % 16 != 0:
        raise ReleaseError(f"{label} has a malformed ELF dynamic table")
    string_table_virtual = None
    string_table_size = None
    path_offsets = []
    needed_offsets = []
    for offset in range(dynamic_offset, dynamic_offset + dynamic_size, 16):
        tag, value = struct.unpack_from("<QQ", data, offset)
        if tag == 0:
            break
        if tag == 5:
            string_table_virtual = value
        elif tag == 10:
            string_table_size = value
        elif tag in {15, 29}:
            path_offsets.append(value)
        elif tag == 1:
            needed_offsets.append(value)
    if not path_offsets and not needed_offsets:
        return
    if string_table_virtual is None or string_table_size is None:
        raise ReleaseError(f"{label} ELF dynamic strings are unavailable")
    string_table_file = None
    for program in program_headers:
        kind, _flags, file_offset, virtual, _physical, file_size, _memory_size, _align = program
        if kind == 1 and virtual <= string_table_virtual < virtual + file_size:
            string_table_file = file_offset + (string_table_virtual - virtual)
            break
    if string_table_file is None or string_table_file + string_table_size > len(data):
        raise ReleaseError(f"{label} ELF dynamic string table is invalid")
    string_limit = string_table_file + string_table_size
    for relative in path_offsets:
        path_value = _elf_c_string(data, string_table_file + relative, string_limit, label)
        for component in path_value.split(":"):
            if component in {"$ORIGIN", "${ORIGIN}"}:
                continue
            prefix = next(
                (value for value in ("$ORIGIN/", "${ORIGIN}/") if component.startswith(value)),
                None,
            )
            if prefix is None or any(
                part in {"", ".", ".."} for part in component[len(prefix) :].split("/")
            ):
                raise ReleaseError(f"{label} has a non-relocatable ELF RPATH/RUNPATH")
    for relative in needed_offsets:
        library = _elf_c_string(data, string_table_file + relative, string_limit, label)
        if library.casefold().startswith("libsodium.so"):
            raise ReleaseError(f"{label} dynamically links libsodium")


def _validate_windows_pe(data: bytes, platform: str, label: str) -> None:
    if len(data) < 64 or data[:2] != b"MZ":
        raise ReleaseError(f"{label} is not a Windows PE executable")
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error as error:
        raise ReleaseError(f"{label} has a truncated DOS header") from error
    if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise ReleaseError(f"{label} has an invalid Windows PE header")
    try:
        (
            machine,
            section_count,
            _timestamp,
            _symbols_offset,
            _symbol_count,
            optional_size,
            characteristics,
        ) = struct.unpack_from("<HHIIIHH", data, pe_offset + 4)
    except struct.error as error:
        raise ReleaseError(f"{label} has a truncated Windows COFF header") from error
    expected_machine = {"windows-x64": 0x8664, "windows-arm64": 0xAA64}[platform]
    if machine != expected_machine:
        raise ReleaseError(f"{label} PE architecture does not match {platform}")
    if characteristics & 0x0002 == 0 or characteristics & 0x2000:
        raise ReleaseError(f"{label} PE image is not a non-DLL executable")
    if section_count < 1 or section_count > 96:
        raise ReleaseError(f"{label} has an invalid PE section count")

    optional_offset = pe_offset + 24
    if optional_size < 128 or optional_size > 4096:
        raise ReleaseError(f"{label} has an invalid PE32+ optional-header size")
    if optional_offset + optional_size > len(data):
        raise ReleaseError(f"{label} has a truncated PE32+ optional header")
    try:
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        entry_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
        size_of_image = struct.unpack_from("<I", data, optional_offset + 56)[0]
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 60)[0]
        subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
        directory_count = struct.unpack_from("<I", data, optional_offset + 108)[0]
    except struct.error as error:
        raise ReleaseError(f"{label} has a malformed PE32+ optional header") from error
    if magic != 0x20B:
        raise ReleaseError(f"{label} is not a PE32+ image")
    if entry_rva == 0 or size_of_image == 0 or subsystem == 0:
        raise ReleaseError(f"{label} has invalid PE32+ executable metadata")
    if size_of_headers < optional_offset + optional_size or size_of_headers > len(data):
        raise ReleaseError(f"{label} has an invalid PE header extent")
    if directory_count < 2 or directory_count > 32:
        raise ReleaseError(f"{label} has an invalid PE data-directory count")
    if 112 + directory_count * 8 > optional_size:
        raise ReleaseError(f"{label} has a truncated PE data-directory table")

    section_offset = optional_offset + optional_size
    if section_offset + section_count * 40 > len(data):
        raise ReleaseError(f"{label} has a truncated PE section table")
    if size_of_headers < section_offset + section_count * 40:
        raise ReleaseError(f"{label} PE headers do not cover the section table")
    sections: list[tuple[int, int, int, int, int]] = []
    raw_ranges: list[tuple[int, int]] = []
    for index in range(section_count):
        offset = section_offset + index * 40
        try:
            virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
                "<IIII", data, offset + 8
            )
            section_flags = struct.unpack_from("<I", data, offset + 36)[0]
        except struct.error as error:
            raise ReleaseError(f"{label} has a malformed PE section header") from error
        if virtual_address == 0 or max(virtual_size, raw_size) == 0:
            raise ReleaseError(f"{label} has an empty PE section")
        if virtual_address + max(virtual_size, raw_size) > size_of_image:
            raise ReleaseError(f"{label} PE section exceeds the image")
        if raw_size:
            if raw_offset < size_of_headers or raw_offset + raw_size > len(data):
                raise ReleaseError(f"{label} PE section exceeds the file")
            raw_range = (raw_offset, raw_offset + raw_size)
            if any(raw_range[0] < end and start < raw_range[1] for start, end in raw_ranges):
                raise ReleaseError(f"{label} has overlapping PE section data")
            raw_ranges.append(raw_range)
        sections.append(
            (virtual_address, max(virtual_size, raw_size), raw_offset, raw_size, section_flags)
        )

    def map_rva(rva: int, size: int, purpose: str) -> int:
        if size < 1 or rva + size > 0x1_0000_0000:
            raise ReleaseError(f"{label} has an invalid PE {purpose} range")
        for virtual, span, raw_offset, raw_size, _flags in sections:
            if virtual <= rva and rva + size <= virtual + span:
                relative = rva - virtual
                if relative + size > raw_size:
                    break
                return raw_offset + relative
        raise ReleaseError(f"{label} PE {purpose} is outside section data")

    entry_section = next(
        (
            section
            for section in sections
            if section[0] <= entry_rva < section[0] + section[1]
        ),
        None,
    )
    if entry_section is None or entry_section[4] & 0x2000_0000 == 0:
        raise ReleaseError(f"{label} PE entry point is not in an executable section")

    import_rva, import_size = struct.unpack_from("<II", data, optional_offset + 120)
    if import_rva == 0 or import_size < 40:
        raise ReleaseError(f"{label} has no bounded PE import table")
    import_offset = map_rva(import_rva, import_size, "import table")
    import_limit = import_offset + import_size
    imported_libraries: list[str] = []
    terminated = False
    for descriptor_offset in range(import_offset, import_limit - 19, 20):
        descriptor = struct.unpack_from("<IIIII", data, descriptor_offset)
        if descriptor == (0, 0, 0, 0, 0):
            terminated = True
            break
        name_rva = descriptor[3]
        if name_rva == 0 or descriptor[4] == 0:
            raise ReleaseError(f"{label} has a malformed PE import descriptor")
        name_offset = map_rva(name_rva, 1, "import name")
        name_limit = None
        for virtual, span, raw_offset, raw_size, _flags in sections:
            if virtual <= name_rva < virtual + span:
                relative = name_rva - virtual
                if relative < raw_size:
                    name_limit = min(raw_offset + raw_size, name_offset + 4096)
                break
        if name_limit is None:
            raise ReleaseError(f"{label} PE import name is outside section data")
        name_end = data.find(b"\0", name_offset, name_limit)
        if name_end < 0:
            raise ReleaseError(f"{label} has an unterminated PE import name")
        try:
            library = data[name_offset:name_end].decode("ascii", "strict")
        except UnicodeError as error:
            raise ReleaseError(f"{label} has a non-ASCII PE import name") from error
        if not library or any(character in "/\\:" for character in library):
            raise ReleaseError(f"{label} has an invalid PE import name")
        imported_libraries.append(library)
    if not terminated or not imported_libraries:
        raise ReleaseError(f"{label} PE import table is not terminated")
    if any(
        library.casefold().startswith("libsodium")
        and library.casefold().endswith(".dll")
        for library in imported_libraries
    ):
        raise ReleaseError(f"{label} dynamically links libsodium")


def validate_native_binary(data: bytes, platform: str, label: str) -> None:
    if platform.startswith("linux-"):
        _validate_linux_elf(data, platform, label)
    elif platform.startswith("windows-"):
        _validate_windows_pe(data, platform, label)
    else:
        raise ReleaseError(f"unsupported binary platform: {platform}")


def read_json(path: Path) -> Any:
    require_regular_file(path, "JSON input")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"invalid JSON input: {path}") from error


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    path.write_text(encoded, encoding="utf-8", newline="\n")


def safe_archive_name(name: str) -> str:
    if not name or "\\" in name or name.startswith("/"):
        raise ReleaseError(f"unsafe archive member name: {name!r}")
    path = PurePosixPath(name)
    if path.as_posix() != name or any(
        component in {"", ".", ".."}
        or ":" in component
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in component)
        for component in path.parts
    ):
        raise ReleaseError(f"unsafe archive member name: {name!r}")
    return path.as_posix()


_WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "conin$",
    "conout$",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
    *(f"com{index}" for index in "¹²³"),
    *(f"lpt{index}" for index in "¹²³"),
}
_WINDOWS_FORBIDDEN_CHARACTERS = frozenset('<>"|?*')
_CANONICAL_REPOSITORY = "https://github.com/JekYUlll/Inex"
_CANONICAL_REMOTES = {
    _CANONICAL_REPOSITORY,
    _CANONICAL_REPOSITORY + ".git",
    "git@github.com:JekYUlll/Inex.git",
    "ssh://git@github.com/JekYUlll/Inex.git",
}


def portable_archive_key(name: str) -> str:
    """Return the Windows-portable, case-insensitive identity of a member path."""

    normalized = safe_archive_name(name)
    key_parts = []
    for component in PurePosixPath(normalized).parts:
        if component.endswith((" ", ".")) or any(
            character in _WINDOWS_FORBIDDEN_CHARACTERS for character in component
        ):
            raise ReleaseError(f"archive member is not portable to Windows: {name!r}")
        canonical = unicodedata.normalize("NFC", component).casefold()
        if canonical.split(".", 1)[0] in _WINDOWS_RESERVED_NAMES:
            raise ReleaseError(f"archive member uses a reserved Windows name: {name!r}")
        key_parts.append(canonical)
    return "/".join(key_parts)


def register_archive_member(
    seen: dict[str, tuple[str, bool]], name: str, *, is_directory: bool
) -> None:
    """Reject extraction collisions across case, Unicode, and file/directory prefixes."""

    key = portable_archive_key(name)
    existing = seen.get(key)
    if existing is not None:
        raise ReleaseError(
            f"archive members collide on portable filesystems: {existing[0]!r} and {name!r}"
        )
    for existing_key, (existing_name, existing_directory) in seen.items():
        if existing_key.startswith(key + "/") and not is_directory:
            raise ReleaseError(
                f"archive file/directory paths collide: {name!r} and {existing_name!r}"
            )
        if key.startswith(existing_key + "/") and not existing_directory:
            raise ReleaseError(
                f"archive file/directory paths collide: {existing_name!r} and {name!r}"
            )
    seen[key] = (name, is_directory)


def zip_member_name(information: zipfile.ZipInfo) -> tuple[str, bool]:
    """Validate a ZIP member's path and Unix/DOS file type."""

    is_directory = information.is_dir()
    raw_name = information.filename[:-1] if is_directory else information.filename
    name = safe_archive_name(raw_name)
    mode = information.external_attr >> 16
    file_type = stat.S_IFMT(mode)
    if mode & 0o7000:
        raise ReleaseError(f"archive member has privileged permission bits: {name}")
    allowed = {0, stat.S_IFDIR if is_directory else stat.S_IFREG}
    if file_type not in allowed:
        if file_type == stat.S_IFLNK:
            raise ReleaseError(f"archive member is a symbolic link: {name}")
        raise ReleaseError(f"archive member has a non-regular file type: {name}")
    dos_directory = bool(information.external_attr & 0x10)
    if dos_directory and not is_directory:
        raise ReleaseError(f"archive member has inconsistent DOS attributes: {name}")
    if information.create_system == 0 and is_directory and not dos_directory:
        raise ReleaseError(f"archive member has inconsistent DOS attributes: {name}")
    return name, is_directory


def write_reproducible_zip(
    output: Path,
    entries: Mapping[str, tuple[bytes, int]],
) -> None:
    """Write sorted entries with fixed metadata and Unix permission bits."""

    if not entries or len(entries) > MAX_ARCHIVE_MEMBERS:
        raise ReleaseError("archive has an invalid member count")
    seen: dict[str, tuple[str, bool]] = {}
    total = 0
    for raw_name, (data, mode) in entries.items():
        name = safe_archive_name(raw_name)
        register_archive_member(seen, name, is_directory=False)
        if mode & ~0o777:
            raise ReleaseError(f"archive member has invalid permission bits: {name}")
        if len(data) > MAX_ARCHIVE_MEMBER_BYTES:
            raise ReleaseError(f"archive member is too large: {name}")
        total += len(data)
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise ReleaseError("archive exceeds the release size ceiling")

    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=False,
        ) as archive:
            for raw_name in sorted(entries):
                name = safe_archive_name(raw_name)
                data, mode = entries[raw_name]
                information = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
                information.create_system = 3
                information.compress_type = zipfile.ZIP_DEFLATED
                information.external_attr = (stat.S_IFREG | mode) << 16
                information.flag_bits |= 0x800
                archive.writestr(information, data)
        os.replace(temporary, output)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def normalize_zip(path: Path) -> None:
    """Normalize a VSIX produced by pinned vsce without changing its contents."""

    require_regular_file(path, "VSIX")
    entries: dict[str, tuple[bytes, int]] = {}
    seen: dict[str, tuple[str, bool]] = {}
    total = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            if not archive.infolist() or len(archive.infolist()) > MAX_ARCHIVE_MEMBERS:
                raise ReleaseError("VSIX has an invalid member count")
            for information in archive.infolist():
                name, is_directory = zip_member_name(information)
                register_archive_member(seen, name, is_directory=is_directory)
                mode = (information.external_attr >> 16) & 0o777777
                if information.flag_bits & 0x1:
                    raise ReleaseError(f"VSIX contains an encrypted member: {name}")
                if is_directory:
                    continue
                if name in entries:
                    raise ReleaseError(f"duplicate VSIX member: {name}")
                if information.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    raise ReleaseError(f"VSIX member exceeds the size ceiling: {name}")
                permission_mode = mode & 0o777
                if permission_mode == 0:
                    permission_mode = 0o644
                data = archive.read(information)
                if len(data) != information.file_size:
                    raise ReleaseError(f"VSIX member size changed while reading: {name}")
                total += len(data)
                if total > MAX_ARCHIVE_TOTAL_BYTES:
                    raise ReleaseError("VSIX exceeds the release size ceiling")
                entries[name] = (data, permission_mode)
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseError(f"invalid VSIX: {path}") from error
    write_reproducible_zip(path, entries)


def files_as_entries(
    files: Mapping[str, tuple[Path, int]],
) -> dict[str, tuple[bytes, int]]:
    entries: dict[str, tuple[bytes, int]] = {}
    for archive_name, (source, mode) in files.items():
        require_regular_file(source, f"package input {archive_name}")
        entries[safe_archive_name(archive_name)] = (source.read_bytes(), mode)
    return entries


def _git_blob_oid(path: Path, algorithm: str, tree_mode: str) -> tuple[str, int]:
    try:
        before = path.lstat()
    except OSError as error:
        raise ReleaseError("clean source is missing a tracked file") from error
    if (
        path.is_symlink()
        or getattr(before, "st_file_attributes", 0) & WINDOWS_REPARSE_POINT
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > MAX_SOURCE_FILE_BYTES
    ):
        raise ReleaseError("clean source contains an unsafe or oversized tracked file")
    if before.st_mode & 0o7000 or (
        os.name != "nt"
        and bool(before.st_mode & stat.S_IXUSR) != (tree_mode == "100755")
    ):
        raise ReleaseError("clean source tracked-file mode does not match the HEAD tree")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_size > MAX_SOURCE_FILE_BYTES
            or opened.st_mode != before.st_mode
            or not os.path.samestat(before, opened)
        ):
            raise ReleaseError("clean source tracked-file identity changed")
        digest = hashlib.new(algorithm)
        digest.update(f"blob {opened.st_size}\0".encode("ascii"))
        total = 0
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SOURCE_FILE_BYTES:
                    raise ReleaseError("clean source tracked file exceeds its size ceiling")
                digest.update(chunk)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as error:
        raise ReleaseError("clean source tracked file disappeared") from error
    if (
        not os.path.samestat(opened, after)
        or total != opened.st_size
        or opened.st_mode != after.st_mode
        or opened.st_size != after.st_size
        or opened.st_mtime_ns != after.st_mtime_ns
        or opened.st_ctime_ns != after.st_ctime_ns
    ):
        raise ReleaseError("clean source tracked file changed during hashing")
    return digest.hexdigest(), total


def _parse_normal_index_paths(raw: str) -> set[str]:
    paths: set[str] = set()
    records = [record for record in raw.split("\0") if record]
    if len(records) > MAX_SOURCE_TRACKED_FILES:
        raise ReleaseError("source index exceeds the tracked-file ceiling")
    for record in records:
        if len(record) < 3 or record[1] != " " or record[0] != "H":
            raise ReleaseError("source index contains special or non-normal flags")
        path = record[2:]
        if path in paths:
            raise ReleaseError("source index repeats a tracked path")
        paths.add(path)
    return paths


def _verify_clean_head_tree(
    repository_root: Path,
    commit: str,
    object_format: str,
    index_paths: set[str],
    tree_output: str,
) -> None:
    if object_format not in {"sha1", "sha256"}:
        raise ReleaseError("source repository uses an unsupported object format")
    expected_oid_length = {"sha1": 40, "sha256": 64}[object_format]
    tree_paths: set[str] = set()
    portable_files: set[str] = set()
    portable_directories: set[str] = set()
    total_bytes = 0
    records = [record for record in tree_output.split("\0") if record]
    if not records or len(records) > MAX_SOURCE_TRACKED_FILES:
        raise ReleaseError("source HEAD tree has an invalid tracked-file count")
    for record in records:
        try:
            metadata, path_text = record.split("\t", 1)
            mode, kind, expected_oid = metadata.split(" ", 2)
        except ValueError as error:
            raise ReleaseError("source HEAD tree listing is malformed") from error
        path = PurePosixPath(path_text)
        try:
            portable_path = portable_archive_key(path_text)
        except ReleaseError as error:
            raise ReleaseError("source HEAD tree contains an unsafe tracked path") from error
        portable_parts = portable_path.split("/")
        portable_parents = {
            "/".join(portable_parts[:index])
            for index in range(1, len(portable_parts))
        }
        if (
            mode not in {"100644", "100755"}
            or kind != "blob"
            or len(expected_oid) != expected_oid_length
            or any(character not in "0123456789abcdef" for character in expected_oid)
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} for part in path.parts)
            or path_text in tree_paths
            or portable_path in portable_files
            or portable_path in portable_directories
            or any(parent in portable_files for parent in portable_parents)
        ):
            raise ReleaseError("source HEAD tree contains an unsafe tracked entry")
        tree_paths.add(path_text)
        portable_files.add(portable_path)
        portable_directories.update(portable_parents)
        observed_oid, size = _git_blob_oid(
            repository_root.joinpath(*path.parts), object_format, mode
        )
        total_bytes += size
        if total_bytes > MAX_SOURCE_TOTAL_BYTES:
            raise ReleaseError("source HEAD tree exceeds the tracked-byte ceiling")
        if observed_oid != expected_oid:
            raise ReleaseError(
                f"clean source bytes do not match commit {commit[:12]}"
            )
    if tree_paths != index_paths:
        raise ReleaseError("source index paths do not match the HEAD tree")


class _BoundedGitStreamReader:
    def __init__(
        self,
        stream: Any,
        limit: int,
        failure_event: threading.Event,
    ) -> None:
        self._stream = stream
        self._limit = limit
        self._failure_event = failure_event
        self._data = bytearray()
        self.overflow = False
        self.error: OSError | None = None
        self.thread = threading.Thread(target=self._read, daemon=True)

    def _read(self) -> None:
        try:
            while True:
                chunk = self._stream.read(64 * 1024)
                if not chunk:
                    break
                remaining = self._limit - len(self._data)
                if remaining > 0:
                    self._data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    self.overflow = True
                    self._failure_event.set()
        except OSError as error:
            self.error = error
            self._failure_event.set()
        finally:
            try:
                self._stream.close()
            except OSError as error:
                if self.error is None:
                    self.error = error
                    self._failure_event.set()

    def start(self) -> None:
        self.thread.start()

    def finish(self) -> bytes:
        self.thread.join(timeout=10)
        if self.thread.is_alive():
            raise ReleaseError("source provenance Git output did not reach EOF")
        if self.error is not None:
            raise ReleaseError("source provenance Git output could not be read") from self.error
        if self.overflow:
            raise ReleaseError("source provenance Git output exceeds its byte ceiling")
        return bytes(self._data)


def _terminate_git_process(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    elif process.poll() is None:
        process.kill()


def _run_bounded_git(
    git_executable: Path,
    repository_root: Path,
    environment: Mapping[str, str],
    arguments: tuple[str, ...],
    *,
    stdout_limit: int,
    allowed_statuses: Collection[int] = (0,),
) -> str:
    file_mode = "false" if os.name == "nt" else "true"
    process = subprocess.Popen(
        [
            str(git_executable),
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.ignoreCase=false",
            "-c",
            "core.precomposeUnicode=false",
            "-c",
            f"core.fileMode={file_mode}",
            "-c",
            f"core.excludesFile={os.devnull}",
            "-c",
            f"core.attributesFile={os.devnull}",
            "-c",
            "core.quotePath=false",
            "-c",
            "gc.auto=0",
            "-c",
            "maintenance.auto=false",
            *arguments,
        ],
        cwd=repository_root,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=os.name != "nt",
    )
    if process.stdout is None or process.stderr is None:
        _terminate_git_process(process)
        raise ReleaseError("source provenance Git streams are unavailable")
    failure_event = threading.Event()
    stdout_reader = _BoundedGitStreamReader(
        process.stdout, stdout_limit, failure_event
    )
    stderr_reader = _BoundedGitStreamReader(
        process.stderr, MAX_SOURCE_GIT_STDERR_BYTES, failure_event
    )
    stdout_reader.start()
    stderr_reader.start()
    deadline = time.monotonic() + SOURCE_GIT_TIMEOUT_SECONDS
    failed = False
    while process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or failure_event.wait(timeout=min(0.05, remaining)):
            failed = True
            _terminate_git_process(process)
            break
    try:
        status = process.wait(timeout=10)
    except subprocess.TimeoutExpired as error:
        _terminate_git_process(process)
        raise ReleaseError("source provenance Git process could not be terminated") from error
    outputs: list[bytes] = []
    first_reader_error: BaseException | None = None
    for reader in (stdout_reader, stderr_reader):
        try:
            outputs.append(reader.finish())
        except BaseException as error:
            outputs.append(b"")
            if first_reader_error is None:
                first_reader_error = error
    if first_reader_error is not None:
        _terminate_git_process(process)
        raise first_reader_error
    stdout, stderr = outputs
    if failed:
        raise ReleaseError("source provenance Git command exceeded its safety bounds")
    if status not in allowed_statuses or stderr:
        raise ReleaseError("source provenance Git command failed")
    try:
        return stdout.decode("utf-8", "strict")
    except UnicodeError as error:
        raise ReleaseError("source provenance Git output is not UTF-8") from error


def _provenance_path_identity(path: Path, *, directory: bool) -> tuple[int, ...]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ReleaseError("source provenance path is unavailable") from error
    if (
        path.is_symlink()
        or getattr(metadata, "st_file_attributes", 0) & WINDOWS_REPARSE_POINT
        or (directory and not stat.S_ISDIR(metadata.st_mode))
        or (not directory and not stat.S_ISREG(metadata.st_mode))
        or (not directory and metadata.st_nlink != 1)
    ):
        raise ReleaseError("source provenance path has an unsafe identity")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _single_git_line(output: str, label: str) -> str:
    if not output.endswith("\n") or output.count("\n") != 1 or "\0" in output:
        raise ReleaseError(f"source provenance {label} output is malformed")
    value = output[:-1]
    if not value:
        raise ReleaseError(f"source provenance {label} output is empty")
    return value


def _direct_provenance_path(
    output: str,
    expected: Path,
    *,
    directory: bool,
    label: str,
) -> tuple[Path, tuple[int, ...]]:
    candidate = Path(_single_git_line(output, label))
    if not candidate.is_absolute():
        raise ReleaseError(f"source provenance {label} path is not absolute")
    lexical = Path(os.path.abspath(candidate))
    try:
        resolved = lexical.resolve(strict=True)
    except OSError as error:
        raise ReleaseError(f"source provenance {label} path is unavailable") from error
    if lexical != expected or resolved != lexical:
        raise ReleaseError(f"source provenance {label} path is indirect or unexpected")
    return lexical, _provenance_path_identity(lexical, directory=directory)


def _validated_local_git_config(raw: str) -> tuple[str, str]:
    if not raw or not raw.endswith("\0"):
        raise ReleaseError("source repository local Git configuration is malformed")
    records = raw[:-1].split("\0")
    origins: list[str] = []
    allowed_exact_keys = {
        "core.bare",
        "core.autocrlf",
        "core.checkstat",
        "core.filemode",
        "core.ignorecase",
        "core.logallrefupdates",
        "core.fscache",
        "core.longpaths",
        "core.precomposeunicode",
        "core.protecthfs",
        "core.protectntfs",
        "core.repositoryformatversion",
        "core.symlinks",
        "core.trustctime",
        "extensions.objectformat",
        "gc.auto",
        "remote.origin.fetch",
        "remote.origin.url",
        "user.email",
        "user.name",
    }
    for record in records:
        key, separator, value = record.partition("\n")
        if not separator or not key:
            raise ReleaseError("source repository local Git configuration is malformed")
        normalized = key.casefold()
        branch_key = normalized.startswith("branch.") and normalized.rsplit(
            ".", 1
        )[-1] in {"merge", "remote"}
        if normalized not in allowed_exact_keys and not branch_key:
            raise ReleaseError("source repository has unsafe local Git configuration")
        if normalized == "gc.auto" and value != "0":
            raise ReleaseError("source repository has unsafe local Git configuration")
        if normalized == "core.autocrlf" and value.casefold() != "false":
            raise ReleaseError("source repository has unsafe local Git configuration")
        if normalized == "remote.origin.url":
            origins.append(value)
    if len(origins) != 1 or not origins[0]:
        raise ReleaseError("source repository must have exactly one local origin URL")
    return origins[0], raw


def _validated_info_exclude(path: Path) -> tuple[tuple[int, ...], str]:
    identity = _provenance_path_identity(path, directory=False)
    if identity[4] > MAX_SOURCE_GIT_METADATA_BYTES:
        raise ReleaseError("source repository private exclude file is oversized")
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ReleaseError("source repository private exclude file is unreadable") from error
    if (
        len(data) != identity[4]
        or _provenance_path_identity(path, directory=False) != identity
    ):
        raise ReleaseError("source repository private exclude file changed during reading")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError as error:
        raise ReleaseError("source repository private exclude file is not UTF-8") from error
    if any(
        line.strip() and not line.startswith("#")
        for line in text.splitlines()
    ):
        raise ReleaseError("source repository private exclude patterns are not allowed")
    return identity, sha256_bytes(data)


def source_revision(repository_root: Path) -> dict[str, Any]:
    try:
        repository_root = repository_root.resolve(strict=True)
    except OSError as error:
        raise ReleaseError("source repository root is unavailable") from error
    root_identity = _provenance_path_identity(repository_root, directory=True)
    git_environment = {
        name: value for name, value in os.environ.items() if not name.startswith("GIT_")
    }
    git_environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    git_lookup = shutil.which("git", path=git_environment.get("PATH"))
    if git_lookup is None:
        raise ReleaseError("source provenance Git executable is unavailable")
    try:
        git_executable = Path(git_lookup).resolve(strict=True)
    except OSError as error:
        raise ReleaseError("source provenance Git executable is unavailable") from error
    git_executable_identity = _provenance_path_identity(
        git_executable, directory=False
    )

    def git(
        *arguments: str,
        stdout_limit: int = MAX_SOURCE_GIT_SMALL_OUTPUT_BYTES,
        allowed_statuses: Collection[int] = (0,),
    ) -> str:
        return _run_bounded_git(
            git_executable,
            repository_root,
            git_environment,
            arguments,
            stdout_limit=stdout_limit,
            allowed_statuses=allowed_statuses,
        )

    expected_git_directory = repository_root / ".git"
    expected_index_path = expected_git_directory / "index"

    def repository_layout() -> tuple[object, ...]:
        top_level, top_level_identity = _direct_provenance_path(
            git("rev-parse", "--show-toplevel"),
            repository_root,
            directory=True,
            label="worktree root",
        )
        git_directory, git_directory_identity = _direct_provenance_path(
            git("rev-parse", "--absolute-git-dir"),
            expected_git_directory,
            directory=True,
            label="Git directory",
        )
        common_directory, common_directory_identity = _direct_provenance_path(
            git("rev-parse", "--path-format=absolute", "--git-common-dir"),
            expected_git_directory,
            directory=True,
            label="Git common directory",
        )
        index_path, index_identity = _direct_provenance_path(
            git("rev-parse", "--path-format=absolute", "--git-path", "index"),
            expected_index_path,
            directory=False,
            label="Git index",
        )
        objects_path, objects_identity = _direct_provenance_path(
            git("rev-parse", "--path-format=absolute", "--git-path", "objects"),
            expected_git_directory / "objects",
            directory=True,
            label="Git object directory",
        )
        object_info_path, object_info_identity = _direct_provenance_path(
            f"{expected_git_directory / 'objects' / 'info'}\n",
            expected_git_directory / "objects" / "info",
            directory=True,
            label="Git object info directory",
        )
        config_path, config_identity = _direct_provenance_path(
            f"{expected_git_directory / 'config'}\n",
            expected_git_directory / "config",
            directory=False,
            label="Git config",
        )
        head_path, head_identity = _direct_provenance_path(
            f"{expected_git_directory / 'HEAD'}\n",
            expected_git_directory / "HEAD",
            directory=False,
            label="Git HEAD",
        )
        info_exclude_path, info_exclude_path_identity = _direct_provenance_path(
            f"{expected_git_directory / 'info' / 'exclude'}\n",
            expected_git_directory / "info" / "exclude",
            directory=False,
            label="Git private exclude file",
        )
        info_exclude_identity, info_exclude_digest = _validated_info_exclude(
            info_exclude_path
        )
        if info_exclude_identity != info_exclude_path_identity:
            raise ReleaseError("source repository private exclude identity changed")
        for unsupported in (
            expected_git_directory / "worktrees",
            expected_git_directory / "config.worktree",
        ):
            if unsupported.exists() or unsupported.is_symlink():
                raise ReleaseError(
                    "source provenance requires a standalone checkout without worktree state"
                )
        private_attributes = expected_git_directory / "info" / "attributes"
        if private_attributes.exists() or private_attributes.is_symlink():
            raise ReleaseError(
                "source provenance does not allow private Git attributes"
            )
        for alternate in (
            expected_git_directory / "objects" / "info" / "alternates",
            expected_git_directory / "objects" / "info" / "http-alternates",
        ):
            if alternate.exists() or alternate.is_symlink():
                raise ReleaseError(
                    "source provenance requires a standalone object database without alternates"
                )
        if any(expected_git_directory.glob("sharedindex.*")):
            raise ReleaseError("source provenance does not allow a split Git index")
        return (
            top_level,
            top_level_identity,
            git_directory,
            git_directory_identity,
            common_directory,
            common_directory_identity,
            index_path,
            index_identity,
            objects_path,
            objects_identity,
            object_info_path,
            object_info_identity,
            config_path,
            config_identity,
            head_path,
            head_identity,
            info_exclude_path,
            info_exclude_identity,
            info_exclude_digest,
        )

    def local_configuration() -> tuple[str, str]:
        raw = git(
            "config",
            "--local",
            "--no-includes",
            "--null",
            "--list",
            stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES,
        )
        remote, snapshot = _validated_local_git_config(raw)
        effective_remote = _single_git_line(
            git("remote", "get-url", "--all", "origin"),
            "effective origin",
        )
        if effective_remote != remote:
            raise ReleaseError("Git effective origin does not match its local origin URL")
        return remote, snapshot

    def untracked_ignore_snapshot() -> tuple[str, ...]:
        raw = git(
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
            "--",
            ":(icase,glob)**/.gitignore",
            stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES,
        )
        if raw and not raw.endswith("\0"):
            raise ReleaseError("source repository ignore-file listing is malformed")
        paths = tuple(raw[:-1].split("\0")) if raw else ()
        if any(not record for record in paths):
            raise ReleaseError("source repository ignore-file listing is malformed")
        if len(paths) > MAX_SOURCE_UNTRACKED_IGNORE_FILES:
            raise ReleaseError("source repository has too many untracked ignore files")
        if len(set(paths)) != len(paths):
            raise ReleaseError("source repository repeats an untracked ignore path")
        parents: set[str] = set()
        for path_text in paths:
            portable_archive_key(path_text)
            path = PurePosixPath(path_text)
            if path.name.casefold() != ".gitignore":
                raise ReleaseError("source repository returned an invalid ignore path")
            parent = path.parent.as_posix()
            if parent == ".":
                raise ReleaseError(
                    "source repository has an untracked ignore file outside an ignored directory"
                )
            parents.add(parent)

        matched_parents: set[str] = set()
        chunk: list[str] = []
        chunk_bytes = 0

        def check_chunk() -> None:
            nonlocal chunk, chunk_bytes
            if not chunk:
                return
            output = git(
                "check-ignore",
                "--no-index",
                "--",
                *chunk,
                stdout_limit=MAX_SOURCE_GIT_SMALL_OUTPUT_BYTES,
                allowed_statuses=(0, 1),
            )
            records = output.splitlines()
            if output != "".join(f"{record}\n" for record in records):
                raise ReleaseError("source repository ignore output is malformed")
            matched_parents.update(records)
            chunk = []
            chunk_bytes = 0

        for parent in sorted(parents):
            encoded_size = len(parent.encode("utf-8")) + 1
            if encoded_size > MAX_SOURCE_GIT_ARGUMENT_BYTES:
                raise ReleaseError("source repository ignore path is oversized")
            if chunk and chunk_bytes + encoded_size > MAX_SOURCE_GIT_ARGUMENT_BYTES:
                check_chunk()
            chunk.append(parent)
            chunk_bytes += encoded_size
        check_chunk()
        if matched_parents != parents:
            raise ReleaseError(
                "source repository has an untracked ignore file outside an ignored directory"
            )
        return tuple(sorted(paths))

    try:
        layout = repository_layout()
        if layout[1] != root_identity:
            raise ReleaseError("source repository root identity changed")
        commit = _single_git_line(
            git("rev-parse", "--verify", "HEAD^{commit}"), "commit"
        )
        remote, local_config = local_configuration()
        untracked_ignore_files = untracked_ignore_snapshot()
        object_format = _single_git_line(
            git("rev-parse", "--show-object-format"), "object format"
        )
        if object_format not in {"sha1", "sha256"}:
            raise ReleaseError("source repository uses an unsupported object format")
        replace_refs = git(
            "for-each-ref", "--format=%(refname)", "refs/replace/"
        )
        if replace_refs:
            raise ReleaseError("source repository contains replacement object refs")
        index_flags = git(
            "ls-files", "-v", "-z", stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES
        )
        index_paths = _parse_normal_index_paths(index_flags)
        status = git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=all",
            stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES,
        )
        dirty = bool(status)
        if not dirty:
            tree_output = git(
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                commit,
                stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES,
            )
            _verify_clean_head_tree(
                repository_root,
                commit,
                object_format,
                index_paths,
                tree_output,
            )
        final_commit = _single_git_line(
            git("rev-parse", "--verify", "HEAD^{commit}"), "final commit"
        )
        final_remote, final_local_config = local_configuration()
        final_untracked_ignore_files = untracked_ignore_snapshot()
        final_replace_refs = git(
            "for-each-ref", "--format=%(refname)", "refs/replace/"
        )
        final_index_flags = git(
            "ls-files", "-v", "-z", stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES
        )
        final_status = git(
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=all",
            stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES,
        )
        if not dirty:
            final_index_paths = _parse_normal_index_paths(final_index_flags)
            final_tree_output = git(
                "ls-tree",
                "-r",
                "-z",
                "--full-tree",
                final_commit,
                stdout_limit=MAX_SOURCE_GIT_LISTING_BYTES,
            )
            if final_tree_output != tree_output:
                raise ReleaseError("source HEAD tree changed during provenance verification")
            _verify_clean_head_tree(
                repository_root,
                final_commit,
                object_format,
                final_index_paths,
                final_tree_output,
            )
        final_layout = repository_layout()
    except (OSError, UnicodeError, ValueError) as error:
        raise ReleaseError("could not identify the source revision") from error
    expected_commit_length = {"sha1": 40, "sha256": 64}[object_format]
    if len(commit) != expected_commit_length or any(
        character not in "0123456789abcdef" for character in commit
    ):
        raise ReleaseError("Git returned an invalid source revision")
    if remote not in _CANONICAL_REMOTES:
        raise ReleaseError("Git origin is not the canonical Inex repository")
    if (
        final_commit != commit
        or final_remote != remote
        or final_local_config != local_config
        or final_untracked_ignore_files != untracked_ignore_files
        or final_layout != layout
        or _provenance_path_identity(repository_root, directory=True) != root_identity
        or _provenance_path_identity(git_executable, directory=False)
        != git_executable_identity
        or final_replace_refs != replace_refs
        or final_index_flags != index_flags
        or final_status != status
    ):
        raise ReleaseError("source revision changed during provenance verification")
    return {
        "commit": commit,
        "dirtySourceTree": dirty,
        "repository": _CANONICAL_REPOSITORY,
    }


def package_manifest(
    *,
    kind: str,
    platform: str,
    version: str,
    repository_root: Path,
    entries: Mapping[str, tuple[bytes, int]],
    install_format: str,
) -> bytes:
    files = [
        {
            "path": name,
            "sha256": sha256_bytes(entries[name][0]),
            "size": len(entries[name][0]),
        }
        for name in sorted(entries)
    ]
    manifest = {
        "schemaVersion": 1,
        "package": kind,
        "platform": platform,
        "version": version,
        "installFormat": install_format,
        "source": source_revision(repository_root),
        "files": files,
    }
    return (json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _native_locked_metadata(repository_root: Path) -> dict[str, Any]:
    environment = os.environ.copy()
    environment["CARGO_NET_OFFLINE"] = "true"
    try:
        version_result = subprocess.run(
            ["rustc", "-vV"],
            cwd=repository_root,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        host_lines = [
            line.removeprefix("host: ")
            for line in version_result.stdout.splitlines()
            if line.startswith("host: ")
        ]
        if len(host_lines) != 1 or not host_lines[0]:
            raise ReleaseError("rustc did not report one native host target")
        result = subprocess.run(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--locked",
                "--offline",
                "--filter-platform",
                host_lines[0],
            ],
            cwd=repository_root,
            env=environment,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        metadata = json.loads(result.stdout)
    except (OSError, UnicodeError, json.JSONDecodeError, subprocess.CalledProcessError) as error:
        raise ReleaseError("could not resolve the native locked Cargo graph") from error
    if not isinstance(metadata, dict) or not isinstance(metadata.get("resolve"), dict):
        raise ReleaseError("Cargo metadata omitted its resolved native graph")
    return metadata


def _native_resolved_packages(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    resolve = metadata["resolve"]
    nodes = {
        node.get("id"): node
        for node in resolve.get("nodes", [])
        if isinstance(node, dict) and isinstance(node.get("id"), str)
    }
    reachable = set()
    pending = list(metadata.get("workspace_members", []))
    while pending:
        package_id = pending.pop()
        if package_id in reachable:
            continue
        node = nodes.get(package_id)
        if node is None:
            raise ReleaseError("resolved Cargo graph references an unknown package")
        reachable.add(package_id)
        for dependency in node.get("deps", []):
            if not isinstance(dependency, dict):
                raise ReleaseError("resolved Cargo graph contains an invalid dependency")
            kinds = dependency.get("dep_kinds", [])
            if not isinstance(kinds, list):
                raise ReleaseError("resolved Cargo dependency kinds are invalid")
            if kinds and all(
                isinstance(kind, dict) and kind.get("kind") == "dev" for kind in kinds
            ):
                continue
            dependency_id = dependency.get("pkg")
            if not isinstance(dependency_id, str):
                raise ReleaseError("resolved Cargo dependency has no package id")
            pending.append(dependency_id)

    packages = []
    for package in metadata.get("packages", []):
        if (
            isinstance(package, dict)
            and package.get("id") in reachable
            and package.get("source") is not None
        ):
            packages.append(package)
    return packages


def generate_license_inventory(repository_root: Path, version: str) -> bytes:
    """Generate a deterministic resolved-Cargo license inventory.

    The VS Code bundle has no shipped npm runtime dependency: Node built-ins and
    the `vscode` host API remain external. Build/test/package tools are therefore
    deliberately absent from the distributed-component list.
    """

    try:
        metadata = _native_locked_metadata(repository_root)
        lock = tomllib.loads((repository_root / "Cargo.lock").read_text(encoding="utf-8"))
    except (
        OSError,
        UnicodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise ReleaseError("could not build the locked dependency license inventory") from error

    checksums: dict[tuple[str, str], str] = {}
    for package in lock.get("package", []):
        checksum = package.get("checksum")
        if isinstance(checksum, str):
            checksums[(str(package.get("name")), str(package.get("version")))] = checksum

    components = []
    for package in _native_resolved_packages(metadata):
        name = package.get("name")
        package_version = package.get("version")
        license_expression = package.get("license")
        if not all(isinstance(value, str) and value for value in (name, package_version)):
            raise ReleaseError("Cargo metadata contains an invalid package identity")
        if not isinstance(license_expression, str) or not license_expression:
            raise ReleaseError(f"dependency has no declared license: {name} {package_version}")
        component = {
            "ecosystem": "cargo",
            "name": name,
            "version": package_version,
            "license": license_expression,
            "source": "crates.io",
        }
        checksum = checksums.get((name, package_version))
        if checksum is not None:
            component["checksum"] = f"sha256:{checksum}"
        components.append(component)
    components.sort(key=lambda item: (item["name"], item["version"]))

    inventory = {
        "schemaVersion": 1,
        "project": {
            "name": "Inex",
            "version": version,
            "license": "GPL-3.0-only",
            "repository": "https://github.com/JekYUlll/Inex",
        },
        "scope": {
            "rust": "locked normal/build Cargo packages reachable for the native package target",
            "vscodeRuntime": "no shipped npm runtime dependencies; vscode and Node built-ins are host-provided",
            "sublimeRuntime": "Python standard library and Sublime host API only",
            "buildTools": "not shipped and intentionally excluded",
        },
        "components": components,
        "bundledNativeLibraries": [
            {
                "name": "libsodium",
                "version": "1.0.22",
                "license": "ISC",
                "source": "bundled by libsodium-sys-stable 1.24.0",
            }
        ],
    }
    return (json.dumps(inventory, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _is_license_filename(name: str) -> bool:
    lowered = name.casefold()
    for stem in ("copying", "licence", "license", "notice", "unlicense"):
        if lowered == stem or lowered.startswith(stem + ".") or lowered.startswith(stem + "-"):
            return True
    return False


def generate_license_materials(
    repository_root: Path, version: str
) -> tuple[bytes, dict[str, tuple[bytes, int]]]:
    """Return the inventory and complete dependency license/notice files."""

    inventory = json.loads(generate_license_inventory(repository_root, version))
    metadata = _native_locked_metadata(repository_root)

    texts: dict[str, tuple[bytes, int]] = {}
    references: dict[tuple[str, str], list[str]] = {}
    libsodium_package_directory: Path | None = None
    for package in _native_resolved_packages(metadata):
        name = package.get("name")
        package_version = package.get("version")
        manifest_path = package.get("manifest_path")
        if not all(
            isinstance(value, str) and value for value in (name, package_version, manifest_path)
        ):
            raise ReleaseError("Cargo metadata contains an invalid licensed package")
        package_directory = Path(manifest_path).parent
        if name == "libsodium-sys-stable" and package_version == "1.24.0":
            libsodium_package_directory = package_directory
        candidates = []
        try:
            for candidate in package_directory.iterdir():
                if _is_license_filename(candidate.name):
                    candidates.append(candidate)
        except OSError as error:
            raise ReleaseError(f"could not inspect licenses for {name} {package_version}") from error
        selected = []
        for candidate in sorted(candidates, key=lambda path: path.name.casefold()):
            metadata_entry = candidate.lstat()
            if candidate.is_symlink() or not stat.S_ISREG(metadata_entry.st_mode):
                continue
            data = candidate.read_bytes()
            if not data or len(data) > 2 * 1024 * 1024:
                raise ReleaseError(f"dependency license text has an invalid size: {candidate}")
            archive_name = safe_archive_name(
                f"THIRD_PARTY_LICENSE_TEXTS/cargo/{name}-{package_version}/{candidate.name}"
            )
            if archive_name in texts:
                raise ReleaseError(f"duplicate dependency license destination: {archive_name}")
            texts[archive_name] = (data, 0o644)
            selected.append(archive_name)
        if not selected:
            raise ReleaseError(f"dependency has no distributable license text: {name} {package_version}")
        references[(name, package_version)] = selected

    native_license_path = "THIRD_PARTY_LICENSE_TEXTS/native/libsodium-1.0.22/LICENSE"
    if libsodium_package_directory is None:
        raise ReleaseError("locked graph omits libsodium-sys-stable 1.24.0")
    source_archive = libsodium_package_directory / "LATEST.tar.gz"
    require_regular_file(source_archive, "bundled libsodium source archive")
    try:
        with tarfile.open(source_archive, "r:gz") as archive:
            matches = [
                member
                for member in archive.getmembers()
                if member.isfile() and member.name.endswith("/LICENSE")
            ]
            if len(matches) != 1 or matches[0].size <= 0 or matches[0].size > 2 * 1024 * 1024:
                raise ReleaseError("bundled libsodium archive has an invalid license layout")
            extracted = archive.extractfile(matches[0])
            if extracted is None:
                raise ReleaseError("bundled libsodium license could not be read")
            texts[native_license_path] = (extracted.read(), 0o644)
    except (OSError, tarfile.TarError) as error:
        raise ReleaseError("could not read bundled libsodium license text") from error

    components = inventory.get("components")
    if not isinstance(components, list):
        raise ReleaseError("generated dependency inventory has no components")
    for component in components:
        key = (component.get("name"), component.get("version"))
        component["licenseFiles"] = references.get(key)
        if not component["licenseFiles"]:
            raise ReleaseError(f"license text mapping is missing for {key[0]} {key[1]}")
    native = inventory.get("bundledNativeLibraries")
    if not isinstance(native, list) or len(native) != 1:
        raise ReleaseError("generated native license inventory is invalid")
    native[0]["licenseFiles"] = [native_license_path]

    encoded = (
        json.dumps(inventory, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    return encoded, texts


def write_sha256sums(output_directory: Path, artifacts: Iterable[Path]) -> Path:
    paths = sorted((path.resolve() for path in artifacts), key=lambda path: path.name)
    lines = []
    for path in paths:
        require_regular_file(path, "release artifact")
        if path.parent != output_directory.resolve():
            raise ReleaseError("checksum inputs must be direct children of the output directory")
        if "\n" in path.name or "\r" in path.name:
            raise ReleaseError("artifact name contains a line break")
        lines.append(f"{sha256_file(path)}  {path.name}\n")
    checksum_path = output_directory / "SHA256SUMS"
    checksum_path.write_text("".join(lines), encoding="ascii", newline="\n")
    return checksum_path
