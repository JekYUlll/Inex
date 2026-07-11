#!/usr/bin/env python3
"""Shared, dependency-free helpers for deterministic Inex release artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import struct
import subprocess
import tarfile
import tomllib
from typing import Any, Iterable, Mapping
import unicodedata
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
MAX_ARCHIVE_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096

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


def source_revision(repository_root: Path) -> dict[str, Any]:
    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", *arguments],
            cwd=repository_root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
        return result.stdout.strip()

    try:
        commit = git("rev-parse", "HEAD")
        dirty = bool(git("status", "--porcelain=v1", "--untracked-files=all"))
        remote = git("remote", "get-url", "origin")
    except (OSError, subprocess.CalledProcessError, UnicodeError) as error:
        raise ReleaseError("could not identify the source revision") from error
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise ReleaseError("Git returned an invalid source revision")
    if remote not in _CANONICAL_REMOTES:
        raise ReleaseError("Git origin is not the canonical Inex repository")
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
