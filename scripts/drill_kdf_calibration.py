#!/usr/bin/env python3
"""Capture three native packaged Argon2id calibration observations."""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import platform as host_platform
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping, Sequence
from typing import Callable

import audit_release_artifacts as artifact_audit
import drill_release_lifecycle as lifecycle
from release_common import (
    PLATFORMS,
    REPOSITORY_ROOT,
    ReleaseError,
    portable_archive_key,
    sha256_bytes,
    source_revision,
)


ATTEMPT_COUNT = 3
PROCESS_TIMEOUT_SECONDS = 120
PROCESS_OUTPUT_LIMIT_BYTES = lifecycle.MAX_PROCESS_OUTPUT_BYTES
HARNESS_PYTHON_IMPLEMENTATION = "CPython"
HARNESS_PYTHON_VERSION = "3.13.14"
KDF_REPORT_SCHEMA = "inex-kdf-calibration-v1"
KDF_HARNESS_FILES = (
    "scripts/audit_release_artifacts.py",
    "scripts/drill_kdf_calibration.py",
    "scripts/drill_release_lifecycle.py",
    "scripts/release_common.py",
    "scripts/tests/test_drill_kdf_calibration.py",
    "scripts/tests/test_release_artifacts.py",
    "scripts/tests/test_release_lifecycle.py",
)
REPORT_SCOPE = (
    "native-packaged-public-dummy-calibration-observation-only-non-sla"
)
REPORT_NOT_COVERED = (
    "end-to-end-create-import-or-unlock-latency",
    "per-candidate-calibration-trace",
    "same-process-subsequent-vault-creation-parameter-use",
    "platforms-other-than-this-report",
    "windows-suspended-before-job-assignment-job-empty-verification-and-ntfs-ads-closure",
    "independent-build-attestation-and-release-publication",
)
REPORT_TRUST_ASSUMPTIONS = (
    "trusted-native-host-clock-kernel-python-and-harness",
    "exclusive-quiescent-artifact-directory-during-bounded-snapshot",
    "no-same-principal-harness-writer-during-evidence-capture",
)
CALIBRATION_LINE_FIELDS = (
    ("kdf-calibration-info-schema", "schema"),
    ("product", "product"),
    ("version", "version"),
    ("rust-target", "rustTarget"),
    ("rust-debug-assertions", "rustDebugAssertions"),
    ("algorithm", "algorithm"),
    ("measurement-input", "measurementInput"),
    ("cache-scope", "cacheScope"),
    ("sample-mode", "sampleMode"),
    ("min-ops-limit", "minOpsLimit"),
    ("max-ops-limit", "maxOpsLimit"),
    ("selected-ops-limit", "selectedOpsLimit"),
    ("mem-limit-bytes", "memLimitBytes"),
    ("parallelism", "parallelism"),
    ("target-min-ns", "targetMinNs"),
    ("target-max-ns", "targetMaxNs"),
    ("selected-observed-ns", "selectedObservedNs"),
    ("measurement-count", "measurementCount"),
    ("outcome", "outcome"),
    ("end-to-end-sla", "endToEndSla"),
)
CALIBRATION_OBSERVATION_FIELDS = frozenset(
    json_name for _line_name, json_name in CALIBRATION_LINE_FIELDS
)
CALIBRATION_RUNTIME_FIELDS = (
    "schema",
    "product",
    "version",
    "rustTarget",
    "rustDebugAssertions",
    "algorithm",
    "measurementInput",
    "cacheScope",
    "sampleMode",
    "minOpsLimit",
    "maxOpsLimit",
    "memLimitBytes",
    "parallelism",
    "targetMinNs",
    "targetMaxNs",
    "endToEndSla",
)
CALIBRATION_OUTCOMES = frozenset(
    {
        "target-window",
        "minimum-above-window",
        "interior-above-window",
        "maximum-above-window",
        "maximum-below-window",
    }
)


@dataclass(frozen=True)
class ProcessCapture:
    stdout: bytes
    resource_observation: dict[str, object] | None


@dataclass(frozen=True)
class _PhysicalFileSeal:
    metadata: os.stat_result
    sha256: str


WINDOWS_EVIDENCE_BOUNDARY_ERROR = (
    "Windows KDF evidence is fail-closed because suspended-before-Job assignment, "
    "Job-empty verification, and NTFS ADS closure are not implemented"
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run 2 packaged runtime probes plus exactly 3 fresh packaged Inex "
            "calibration attempts and write canonical, platform-protected native "
            "Argon2id calibration evidence."
        )
    )
    parser.add_argument("directory", type=Path, help="Strict four-file artifact directory")
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="New external JSON report path with platform-accurate protection",
    )
    return parser.parse_args()


def _require_supported_harness_runtime() -> None:
    if (
        host_platform.python_implementation() != HARNESS_PYTHON_IMPLEMENTATION
        or host_platform.python_version() != HARNESS_PYTHON_VERSION
    ):
        raise ReleaseError(
            "KDF calibration evidence requires exact CPython 3.13.14"
        )


def _metadata_signature(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _capture_physical_file_seal(
    path: Path,
    label: str,
    *,
    strip_posix_write_bits: bool = False,
    require_posix_executable: bool = False,
) -> _PhysicalFileSeal:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    descriptor = -1
    try:
        before = path.lstat()
        if (
            lifecycle.is_link_like(path, before)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ReleaseError(
                f"{label} is not a non-link single-link regular file"
            )
        descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not os.path.samestat(before, opened)
        ):
            raise ReleaseError(f"{label} changed physical identity while opening")
        if require_posix_executable and os.name != "nt":
            if stat.S_IMODE(opened.st_mode) & 0o111 == 0:
                raise ReleaseError(f"{label} is not executable")
            if strip_posix_write_bits:
                os.fchmod(descriptor, stat.S_IMODE(opened.st_mode) & ~0o222)
                opened = os.fstat(descriptor)
            if stat.S_IMODE(opened.st_mode) & 0o222:
                raise ReleaseError(f"{label} retains a POSIX write bit")

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
            raise ReleaseError(f"{label} changed while its identity was captured")
        return _PhysicalFileSeal(metadata=after_path, sha256=digest.hexdigest())
    except OSError as error:
        raise ReleaseError(f"{label} physical identity is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _verify_physical_file_seal(
    path: Path,
    seal: _PhysicalFileSeal,
    label: str,
    *,
    require_posix_executable: bool = False,
) -> None:
    observed = _capture_physical_file_seal(
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
        raise ReleaseError(f"{label} changed physical identity or contents")


def _snapshot_file_paths(root: Path) -> dict[str, Path]:
    try:
        root_metadata = root.lstat()
        paths = sorted(root.iterdir(), key=lambda path: path.name)
    except OSError as error:
        raise ReleaseError("the four-file artifact snapshot is unavailable") from error
    if (
        lifecycle.is_link_like(root, root_metadata)
        or not stat.S_ISDIR(root_metadata.st_mode)
        or len(paths) != 4
        or len({path.name for path in paths}) != 4
    ):
        raise ReleaseError("the artifact snapshot is not exactly four direct files")
    return {path.name: path for path in paths}


def _capture_artifact_snapshot_seals(
    root: Path,
) -> dict[str, _PhysicalFileSeal]:
    return {
        name: _capture_physical_file_seal(path, f"artifact snapshot file {name}")
        for name, path in _snapshot_file_paths(root).items()
    }


def _verify_execution_inputs(
    executable_paths: Mapping[str, Path],
    executable_seals: Mapping[str, _PhysicalFileSeal],
    artifact_snapshot: Path,
    artifact_seals: Mapping[str, _PhysicalFileSeal],
) -> None:
    if set(executable_paths) != {"inex", "inexd"} or set(executable_seals) != {
        "inex",
        "inexd",
    }:
        raise ReleaseError("the packaged executable seal set is invalid")
    for product in ("inex", "inexd"):
        _verify_physical_file_seal(
            executable_paths[product],
            executable_seals[product],
            f"packaged {product} executable",
            require_posix_executable=True,
        )
    snapshot_paths = _snapshot_file_paths(artifact_snapshot)
    if set(snapshot_paths) != set(artifact_seals):
        raise ReleaseError("the four-file artifact snapshot changed its file set")
    for name, seal in artifact_seals.items():
        _verify_physical_file_seal(
            snapshot_paths[name], seal, f"artifact snapshot file {name}"
        )


def _canonical_uint(value: str, label: str) -> int:
    if re.fullmatch(r"(?:0|[1-9][0-9]*)", value) is None:
        raise ReleaseError(f"KDF calibration report has invalid {label}")
    parsed = int(value)
    if parsed > (1 << 64) - 1:
        raise ReleaseError(f"KDF calibration report exceeds the {label} ceiling")
    return parsed


def _expected_runtime_identity(version: str, platform_name: str) -> dict[str, object]:
    try:
        rust_target = PLATFORMS[platform_name]["rust_target"]
    except KeyError as error:
        raise ReleaseError("KDF calibration report has an unsupported platform") from error
    return {
        "schema": KDF_REPORT_SCHEMA,
        "product": "inex",
        "version": version,
        "rustTarget": rust_target,
        "rustDebugAssertions": False,
        "algorithm": "argon2id13",
        "measurementInput": "inex-public-dummy-v1",
        "cacheScope": "process",
        "sampleMode": "single-per-candidate",
        "minOpsLimit": 3,
        "maxOpsLimit": 20,
        "memLimitBytes": 64 * 1024 * 1024,
        "parallelism": 1,
        "targetMinNs": 250_000_000,
        "targetMaxNs": 750_000_000,
        "endToEndSla": False,
    }


def validate_calibration_observation(
    observation: object, *, expected_version: str, expected_platform: str
) -> None:
    if not isinstance(observation, dict) or set(observation) != CALIBRATION_OBSERVATION_FIELDS:
        raise ReleaseError("KDF calibration report has an invalid field schema")
    expected_identity = _expected_runtime_identity(expected_version, expected_platform)
    if any(observation.get(field) != value for field, value in expected_identity.items()):
        raise ReleaseError("KDF calibration report has a mismatched runtime identity")

    numeric_fields = (
        "minOpsLimit",
        "maxOpsLimit",
        "selectedOpsLimit",
        "memLimitBytes",
        "parallelism",
        "targetMinNs",
        "targetMaxNs",
        "selectedObservedNs",
        "measurementCount",
    )
    if any(
        not isinstance(observation.get(field), int)
        or isinstance(observation.get(field), bool)
        for field in numeric_fields
    ):
        raise ReleaseError("KDF calibration report has a non-integer measurement")

    min_ops = observation["minOpsLimit"]
    max_ops = observation["maxOpsLimit"]
    selected_ops = observation["selectedOpsLimit"]
    target_min = observation["targetMinNs"]
    target_max = observation["targetMaxNs"]
    selected_observed = observation["selectedObservedNs"]
    measurement_count = observation["measurementCount"]
    outcome = observation.get("outcome")
    if (
        not min_ops <= selected_ops <= max_ops
        or not 1 <= measurement_count <= 6
        or not 0 < selected_observed <= PROCESS_TIMEOUT_SECONDS * 1_000_000_000
        or outcome not in CALIBRATION_OUTCOMES
    ):
        raise ReleaseError("KDF calibration report has invalid selected evidence")
    if outcome == "target-window":
        valid_outcome = target_min <= selected_observed <= target_max
    elif outcome == "minimum-above-window":
        valid_outcome = (
            selected_ops == min_ops
            and selected_observed > target_max
            and measurement_count == 1
        )
    elif outcome == "interior-above-window":
        valid_outcome = (
            min_ops < selected_ops < max_ops
            and selected_observed > target_max
            and measurement_count >= 2
        )
    elif outcome == "maximum-above-window":
        valid_outcome = (
            selected_ops == max_ops
            and selected_observed > target_max
            and measurement_count == 6
        )
    else:
        valid_outcome = (
            selected_ops == max_ops
            and selected_observed < target_min
            and measurement_count == 6
        )
    if not valid_outcome:
        raise ReleaseError("KDF calibration report outcome contradicts its selected evidence")


def parse_calibration_report(
    data: bytes, *, expected_version: str, expected_platform: str
) -> dict[str, object]:
    if (
        not data
        or len(data) > PROCESS_OUTPUT_LIMIT_BYTES
        or not data.endswith(b"\n")
        or data.endswith(b"\n\n")
        or b"\r" in data
    ):
        raise ReleaseError("packaged KDF calibration output is not exact bounded LF text")
    try:
        text = data.decode("ascii", "strict")
    except UnicodeError as error:
        raise ReleaseError("packaged KDF calibration output is not strict ASCII") from error
    lines = text[:-1].split("\n")
    if len(lines) != len(CALIBRATION_LINE_FIELDS):
        raise ReleaseError("packaged KDF calibration output does not have exactly 20 lines")

    raw_values: dict[str, str] = {}
    for line, (line_name, json_name) in zip(lines, CALIBRATION_LINE_FIELDS, strict=True):
        prefix = f"{line_name}: "
        if not line.startswith(prefix) or not line[len(prefix) :]:
            raise ReleaseError("packaged KDF calibration output has a mismatched line schema")
        raw_values[json_name] = line[len(prefix) :]

    numeric_fields = {
        "minOpsLimit",
        "maxOpsLimit",
        "selectedOpsLimit",
        "memLimitBytes",
        "parallelism",
        "targetMinNs",
        "targetMaxNs",
        "selectedObservedNs",
        "measurementCount",
    }
    observation: dict[str, object] = {}
    for _line_name, field in CALIBRATION_LINE_FIELDS:
        value = raw_values[field]
        if field in numeric_fields:
            observation[field] = _canonical_uint(value, field)
        elif field in {"rustDebugAssertions", "endToEndSla"}:
            if value not in {"true", "false"}:
                raise ReleaseError("KDF calibration report has an invalid boolean")
            observation[field] = value == "true"
        else:
            observation[field] = value
    validate_calibration_observation(
        observation,
        expected_version=expected_version,
        expected_platform=expected_platform,
    )
    return observation


RUNTIME_INFO_LINE_FIELDS = (
    ("runtime-info-schema", "schema"),
    ("product", "product"),
    ("version", "version"),
    ("rust-target", "rustTarget"),
    ("rust-debug-assertions", "rustDebugAssertions"),
    ("libsodium-version", "libsodiumVersion"),
    ("libsodium-library-major", "libsodiumLibraryMajor"),
    ("libsodium-library-minor", "libsodiumLibraryMinor"),
    ("libsodium-minimal", "libsodiumMinimal"),
)


def expected_runtime_info(
    product: str, version: str, platform_name: str
) -> dict[str, object]:
    if product not in {"inex", "inexd"} or platform_name not in PLATFORMS:
        raise ReleaseError("runtime-info expectation has an unsupported identity")
    return {
        "schema": "inex-runtime-v1",
        "product": product,
        "version": version,
        "rustTarget": PLATFORMS[platform_name]["rust_target"],
        "rustDebugAssertions": False,
        "libsodiumVersion": "1.0.22",
        "libsodiumLibraryMajor": 26,
        "libsodiumLibraryMinor": 4,
        "libsodiumMinimal": False,
    }


def parse_runtime_info(
    data: bytes, *, product: str, version: str, platform_name: str
) -> dict[str, object]:
    if (
        not data
        or len(data) > PROCESS_OUTPUT_LIMIT_BYTES
        or not data.endswith(b"\n")
        or data.endswith(b"\n\n")
        or b"\r" in data
    ):
        raise ReleaseError("packaged runtime-info output is not exact bounded LF text")
    try:
        text = data.decode("ascii", "strict")
    except UnicodeError as error:
        raise ReleaseError("packaged runtime-info output is not strict ASCII") from error
    lines = text[:-1].split("\n")
    if len(lines) != len(RUNTIME_INFO_LINE_FIELDS):
        raise ReleaseError("packaged runtime-info output does not have exactly nine lines")
    values: dict[str, object] = {}
    for line, (line_name, field) in zip(lines, RUNTIME_INFO_LINE_FIELDS, strict=True):
        prefix = f"{line_name}: "
        if not line.startswith(prefix) or not line[len(prefix) :]:
            raise ReleaseError("packaged runtime-info output has a mismatched line schema")
        raw = line[len(prefix) :]
        if field in {"libsodiumLibraryMajor", "libsodiumLibraryMinor"}:
            values[field] = _canonical_uint(raw, field)
        elif field in {"rustDebugAssertions", "libsodiumMinimal"}:
            if raw not in {"true", "false"}:
                raise ReleaseError("packaged runtime-info output has an invalid boolean")
            values[field] = raw == "true"
        else:
            values[field] = raw
    if values != expected_runtime_info(product, version, platform_name):
        raise ReleaseError("packaged runtime-info output has a mismatched exact identity")
    return values


def _physical_memory_bytes() -> int:
    if os.name == "nt":
        class MemoryStatus(ctypes.Structure):
            _fields_ = (
                ("length", ctypes.c_ulong),
                ("memory_load", ctypes.c_ulong),
                ("total_physical", ctypes.c_ulonglong),
                ("available_physical", ctypes.c_ulonglong),
                ("total_page_file", ctypes.c_ulonglong),
                ("available_page_file", ctypes.c_ulonglong),
                ("total_virtual", ctypes.c_ulonglong),
                ("available_virtual", ctypes.c_ulonglong),
                ("available_extended_virtual", ctypes.c_ulonglong),
            )

        status = MemoryStatus()
        status.length = ctypes.sizeof(status)
        try:
            succeeded = ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status))
        except (AttributeError, OSError) as error:
            raise ReleaseError("native physical-memory observation is unavailable") from error
        if not succeeded:
            raise ReleaseError("native physical-memory observation failed")
        memory_bytes = int(status.total_physical)
    else:
        try:
            pages = os.sysconf("SC_PHYS_PAGES")
            page_size = os.sysconf("SC_PAGE_SIZE")
        except (AttributeError, OSError, ValueError) as error:
            raise ReleaseError("native physical-memory observation is unavailable") from error
        memory_bytes = pages * page_size
    if not 64 * 1024 * 1024 <= memory_bytes <= (1 << 64) - 1:
        raise ReleaseError("native physical-memory observation is outside safe bounds")
    return memory_bytes


def host_resource_observation() -> dict[str, int]:
    logical_processors = os.cpu_count()
    if (
        not isinstance(logical_processors, int)
        or isinstance(logical_processors, bool)
        or not 1 <= logical_processors <= 1_048_576
    ):
        raise ReleaseError("native logical-processor observation is unavailable")
    return {
        "logicalProcessorCount": logical_processors,
        "physicalMemoryBytes": _physical_memory_bytes(),
    }


def _bounded_host_text(value: str, label: str, *, maximum: int = 256) -> str:
    normalized = " ".join(value.split())
    if (
        not normalized
        or len(normalized) > maximum
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in normalized)
    ):
        raise ReleaseError(f"native {label} observation is unavailable or unsafe")
    return normalized


def _linux_cpu_descriptor() -> str | None:
    path = Path("/proc/cpuinfo")
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
    except OSError:
        return None
    try:
        data = os.read(descriptor, 1024 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(data) > 1024 * 1024:
        raise ReleaseError("native CPU descriptor exceeds its byte ceiling")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError as error:
        raise ReleaseError("native CPU descriptor is not UTF-8") from error
    records: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        key = name.strip().casefold()
        if key in {"model name", "hardware"} and key not in records and value.strip():
            records[key] = value.strip()
    return records.get("model name") or records.get("hardware")


def host_identity_observation() -> dict[str, str]:
    system = _bounded_host_text(host_platform.system(), "operating-system", maximum=64)
    kernel_release = _bounded_host_text(host_platform.release(), "kernel-release")
    architecture = _bounded_host_text(host_platform.machine(), "architecture", maximum=64)
    cpu_descriptor: str | None = None
    if system.casefold() == "linux":
        cpu_descriptor = _linux_cpu_descriptor()
    elif os.name == "nt":
        cpu_descriptor = os.environ.get("PROCESSOR_IDENTIFIER")
    if not cpu_descriptor:
        cpu_descriptor = host_platform.processor()
    if not cpu_descriptor:
        cpu_descriptor = f"architecture-only:{architecture}"
    return {
        "operatingSystem": system,
        "kernelRelease": kernel_release,
        "architecture": architecture,
        "cpuDescriptor": _bounded_host_text(cpu_descriptor, "CPU-descriptor"),
    }


def _capture_harness_state() -> tuple[dict[str, object], dict[str, str]]:
    harness_source = source_revision(REPOSITORY_ROOT)
    if harness_source.get("dirtySourceTree") is not False:
        raise ReleaseError("KDF calibration evidence requires a clean harness source tree")
    harness_hashes = {
        name: lifecycle.sha256_file(REPOSITORY_ROOT / name) for name in KDF_HARNESS_FILES
    }
    return harness_source, harness_hashes


def _private_environment(root: Path) -> tuple[dict[str, str], Path]:
    environment = lifecycle.controlled_environment(root / "environment")
    cwd = root / "cwd"
    cwd.mkdir(parents=True, exist_ok=False)
    return environment, cwd


class _IoCounters(ctypes.Structure):
    _fields_ = (
        ("read_operation_count", ctypes.c_ulonglong),
        ("write_operation_count", ctypes.c_ulonglong),
        ("other_operation_count", ctypes.c_ulonglong),
        ("read_transfer_count", ctypes.c_ulonglong),
        ("write_transfer_count", ctypes.c_ulonglong),
        ("other_transfer_count", ctypes.c_ulonglong),
    )


class _JobBasicLimitInformation(ctypes.Structure):
    _fields_ = (
        ("per_process_user_time_limit", ctypes.c_longlong),
        ("per_job_user_time_limit", ctypes.c_longlong),
        ("limit_flags", wintypes.DWORD),
        ("minimum_working_set_size", ctypes.c_size_t),
        ("maximum_working_set_size", ctypes.c_size_t),
        ("active_process_limit", wintypes.DWORD),
        ("affinity", ctypes.c_size_t),
        ("priority_class", wintypes.DWORD),
        ("scheduling_class", wintypes.DWORD),
    )


class _JobExtendedLimitInformation(ctypes.Structure):
    _fields_ = (
        ("basic_limit_information", _JobBasicLimitInformation),
        ("io_info", _IoCounters),
        ("process_memory_limit", ctypes.c_size_t),
        ("job_memory_limit", ctypes.c_size_t),
        ("peak_process_memory_used", ctypes.c_size_t),
        ("peak_job_memory_used", ctypes.c_size_t),
    )


class _ProcessMemoryCountersEx(ctypes.Structure):
    _fields_ = (
        ("cb", wintypes.DWORD),
        ("page_fault_count", wintypes.DWORD),
        ("peak_working_set_size", ctypes.c_size_t),
        ("working_set_size", ctypes.c_size_t),
        ("quota_peak_paged_pool_usage", ctypes.c_size_t),
        ("quota_paged_pool_usage", ctypes.c_size_t),
        ("quota_peak_non_paged_pool_usage", ctypes.c_size_t),
        ("quota_non_paged_pool_usage", ctypes.c_size_t),
        ("pagefile_usage", ctypes.c_size_t),
        ("peak_pagefile_usage", ctypes.c_size_t),
        ("private_usage", ctypes.c_size_t),
    )


class _WindowsJob:
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self) -> None:
        if os.name != "nt":
            raise ReleaseError("Windows Job Object requested on a non-Windows host")
        kernel32 = ctypes.windll.kernel32
        kernel32.CreateJobObjectW.argtypes = (ctypes.c_void_p, wintypes.LPCWSTR)
        kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        kernel32.SetInformationJobObject.argtypes = (
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        )
        kernel32.SetInformationJobObject.restype = wintypes.BOOL
        kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
        kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        self._kernel32 = kernel32
        self._handle = kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise ReleaseError("Windows KDF process Job Object creation failed")
        information = _JobExtendedLimitInformation()
        information.basic_limit_information.limit_flags = (
            self.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        )
        if not kernel32.SetInformationJobObject(
            self._handle,
            self.JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            self.close()
            raise ReleaseError("Windows KDF process Job Object limit setup failed")

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        process_handle = getattr(process, "_handle", None)
        if process_handle is None or not self._kernel32.AssignProcessToJobObject(
            self._handle, wintypes.HANDLE(int(process_handle))
        ):
            raise ReleaseError("Windows KDF process could not enter the kill-on-close Job Object")

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def _linux_process_memory_sample(process_id: int) -> dict[str, int] | None:
    path = Path("/proc") / str(process_id) / "status"
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, os.O_RDONLY | no_follow | binary)
    except (FileNotFoundError, ProcessLookupError):
        return None
    except OSError as error:
        raise ReleaseError("Linux KDF process memory observation is unavailable") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise ReleaseError("Linux KDF process status is not a regular procfs entry")
        data = os.read(descriptor, 128 * 1024 + 1)
    finally:
        os.close(descriptor)
    if len(data) > 128 * 1024:
        raise ReleaseError("Linux KDF process status exceeds its byte ceiling")
    # A child can exit after poll() but before /proc is read. Linux retains a
    # zombie status entry without the Vm* counters; it is not a usable sample,
    # but also is not evidence that a running process omitted required data.
    if re.search(rb"^State:\s+Z", data, re.MULTILINE) is not None:
        return None
    fields = {
        "vmHwmBytes": b"VmHWM",
        "vmPeakBytes": b"VmPeak",
        "vmRssBytes": b"VmRSS",
        "vmSizeBytes": b"VmSize",
    }
    result: dict[str, int] = {}
    for output_name, proc_name in fields.items():
        match = re.search(rb"^" + proc_name + rb":\s+([0-9]+) kB$", data, re.MULTILINE)
        if match is None:
            raise ReleaseError("Linux KDF process status omits required memory counters")
        value = int(match.group(1)) * 1024
        if value < 0 or value > (1 << 64) - 1:
            raise ReleaseError("Linux KDF process memory counter is outside safe bounds")
        result[output_name] = value
    return result


def _windows_process_memory_sample(process: subprocess.Popen[bytes]) -> dict[str, int]:
    if os.name != "nt":
        raise ReleaseError("Windows process counters requested on a non-Windows host")
    psapi = ctypes.windll.psapi
    psapi.GetProcessMemoryInfo.argtypes = (
        wintypes.HANDLE,
        ctypes.POINTER(_ProcessMemoryCountersEx),
        wintypes.DWORD,
    )
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = _ProcessMemoryCountersEx()
    counters.cb = ctypes.sizeof(counters)
    process_handle = getattr(process, "_handle", None)
    if process_handle is None or not psapi.GetProcessMemoryInfo(
        wintypes.HANDLE(int(process_handle)),
        ctypes.byref(counters),
        ctypes.sizeof(counters),
    ):
        raise ReleaseError("Windows KDF process memory observation failed")
    return {
        "peakWorkingSetBytes": int(counters.peak_working_set_size),
        "workingSetBytes": int(counters.working_set_size),
        "peakPagefileUsageBytes": int(counters.peak_pagefile_usage),
        "privateUsageBytes": int(counters.private_usage),
    }


def _finish_resource_observation(
    samples: Sequence[Mapping[str, int]], platform_name: str
) -> dict[str, object]:
    if not samples:
        raise ReleaseError("KDF process exited before one external resource observation")
    if platform_name.startswith("linux-"):
        observation: dict[str, object] = {
            "source": "linux-proc-status-poll",
            "sampleCount": len(samples),
            "vmHwmBytes": max(sample["vmHwmBytes"] for sample in samples),
            "vmPeakBytes": max(sample["vmPeakBytes"] for sample in samples),
            "maxPolledVmRssBytes": max(sample["vmRssBytes"] for sample in samples),
            "maxPolledVmSizeBytes": max(sample["vmSizeBytes"] for sample in samples),
        }
    elif platform_name.startswith("windows-"):
        observation = {
            "source": "windows-process-memory-counters-ex-poll",
            "sampleCount": len(samples),
            "peakWorkingSetBytes": max(sample["peakWorkingSetBytes"] for sample in samples),
            "peakPagefileUsageBytes": max(
                sample["peakPagefileUsageBytes"] for sample in samples
            ),
            "maxPolledWorkingSetBytes": max(
                sample["workingSetBytes"] for sample in samples
            ),
            "maxPolledPrivateUsageBytes": max(
                sample["privateUsageBytes"] for sample in samples
            ),
            "killOnCloseJobObject": True,
        }
    else:
        raise ReleaseError("KDF resource observation has an unsupported platform")
    return observation


def _cleanup_bounded_process(
    process: subprocess.Popen[bytes], job: _WindowsJob | None
) -> None:
    if job is not None:
        job.close()
        if process.poll() is None:
            process.kill()
        return
    lifecycle.cleanup_process_descendants(process)


def run_bounded_packaged_process(
    executable: Path,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    timeout: int,
    observe_resources: bool,
    platform_name: str,
) -> ProcessCapture:
    lifecycle.prepare_process_isolation()
    job = _WindowsJob() if os.name == "nt" else None
    process: subprocess.Popen[bytes] | None = None
    stdout_reader: lifecycle.BoundedPipeReader | None = None
    stderr_reader: lifecycle.BoundedPipeReader | None = None
    readers_finished = False
    try:
        process = subprocess.Popen(
            [os.fspath(executable), *arguments],
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=os.name != "nt",
        )
        if job is not None:
            job.assign(process)
        if process.stdout is None or process.stderr is None:
            raise ReleaseError("a packaged process did not expose output streams")
        stdout_reader = lifecycle.BoundedPipeReader(
            process.stdout, (), "packaged process stdout"
        )
        stderr_reader = lifecycle.BoundedPipeReader(
            process.stderr, (), "packaged process stderr"
        )
        stdout_reader.start()
        stderr_reader.start()
        samples: list[dict[str, int]] = []
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if observe_resources:
                sample = (
                    _windows_process_memory_sample(process)
                    if platform_name.startswith("windows-")
                    else _linux_process_memory_sample(process.pid)
                )
                if sample is not None:
                    samples.append(sample)
            if time.monotonic() >= deadline:
                raise ReleaseError("a packaged process exceeded the operational timeout")
            time.sleep(0.01)
        status = process.wait(timeout=10)
        _cleanup_bounded_process(process, job)
        readers_finished = True
        stdout, stderr = lifecycle.finish_pipe_readers(stdout_reader, stderr_reader)
        if status != 0:
            raise ReleaseError("a packaged process returned a nonzero status")
        if stderr:
            raise ReleaseError("a packaged process wrote unexpected stderr")
        resource_observation = (
            _finish_resource_observation(samples, platform_name)
            if observe_resources
            else None
        )
        return ProcessCapture(stdout=stdout, resource_observation=resource_observation)
    except BaseException:
        if process is not None:
            try:
                _cleanup_bounded_process(process, job)
            except BaseException:
                pass
            try:
                process.wait(timeout=10)
            except BaseException:
                try:
                    lifecycle.terminate_process(process)
                except BaseException:
                    pass
            if (
                stdout_reader is not None
                and stderr_reader is not None
                and not readers_finished
            ):
                readers_finished = True
                try:
                    lifecycle.finish_pipe_readers(stdout_reader, stderr_reader)
                except BaseException:
                    pass
        raise
    finally:
        if job is not None:
            job.close()


def run_calibration_process(
    executable: Path,
    *,
    environment: Mapping[str, str],
    cwd: Path,
    timeout: int,
    platform_name: str,
) -> ProcessCapture:
    return run_bounded_packaged_process(
        executable,
        ("kdf-calibration-info",),
        environment=environment,
        cwd=cwd,
        timeout=timeout,
        observe_resources=True,
        platform_name=platform_name,
    )


def run_runtime_probe_process(
    executable: Path,
    arguments: Sequence[str],
    *,
    environment: Mapping[str, str],
    cwd: Path,
    timeout: int,
    platform_name: str,
) -> ProcessCapture:
    return run_bounded_packaged_process(
        executable,
        arguments,
        environment=environment,
        cwd=cwd,
        timeout=timeout,
        observe_resources=False,
        platform_name=platform_name,
    )


def _validate_source(value: object, label: str) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"commit", "dirtySourceTree", "repository"}
        or value.get("dirtySourceTree") is not False
        or value.get("repository") != "https://github.com/JekYUlll/Inex"
        or not isinstance(value.get("commit"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value["commit"]) is None
    ):
        raise ReleaseError(f"KDF evidence has invalid {label}")


def _validate_file_records(
    value: object, label: str, *, expected_names: Sequence[str]
) -> None:
    if not isinstance(value, list) or len(value) != len(expected_names):
        raise ReleaseError(f"KDF evidence has an invalid {label} count")
    names: list[str] = []
    for record in value:
        if (
            not isinstance(record, dict)
            or set(record) != {"name", "sha256"}
            or not isinstance(record.get("name"), str)
            or not isinstance(record.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
        ):
            raise ReleaseError(f"KDF evidence has an invalid {label} record")
        names.append(record["name"])
    if names != list(expected_names):
        raise ReleaseError(f"KDF evidence has an invalid {label} file set")


def validate_process_resource_observation(value: object, platform_name: str) -> None:
    if not isinstance(value, dict):
        raise ReleaseError("KDF evidence has no process resource observation")
    if platform_name.startswith("linux-"):
        expected_fields = {
            "source",
            "sampleCount",
            "vmHwmBytes",
            "vmPeakBytes",
            "maxPolledVmRssBytes",
            "maxPolledVmSizeBytes",
        }
        if value.get("source") != "linux-proc-status-poll":
            raise ReleaseError("KDF evidence has an invalid Linux resource source")
        numeric_fields = expected_fields - {"source"}
    elif platform_name.startswith("windows-"):
        expected_fields = {
            "source",
            "sampleCount",
            "peakWorkingSetBytes",
            "peakPagefileUsageBytes",
            "maxPolledWorkingSetBytes",
            "maxPolledPrivateUsageBytes",
            "killOnCloseJobObject",
        }
        if (
            value.get("source") != "windows-process-memory-counters-ex-poll"
            or value.get("killOnCloseJobObject") is not True
        ):
            raise ReleaseError("KDF evidence has an invalid Windows resource boundary")
        numeric_fields = expected_fields - {"source", "killOnCloseJobObject"}
    else:
        raise ReleaseError("KDF evidence has an unsupported resource platform")
    if set(value) != expected_fields or any(
        not isinstance(value.get(field), int)
        or isinstance(value.get(field), bool)
        or value[field] <= 0
        or value[field] > (1 << 64) - 1
        for field in numeric_fields
    ):
        raise ReleaseError("KDF evidence has invalid process resource counters")


def expected_report_protection(platform_name: str) -> dict[str, object]:
    if platform_name.startswith("linux-"):
        return {
            "scheme": "posix-mode",
            "mode": "0600",
            "verifiedNonSymlinkSingleLinkRegularFile": True,
        }
    if platform_name.startswith("windows-"):
        return {
            "scheme": "windows-create-new-inherited-parent-dacl",
            "createNew": True,
            "verifiedNonReparseRegularFile": True,
            "parentDirectoryAclBoundary": (
                "caller-supplied-private-directory-required-not-independently-audited"
            ),
        }
    raise ReleaseError("KDF evidence has an unsupported report-protection platform")


def validate_evidence_report(report: dict[str, object]) -> None:
    if set(report) != {
        "schemaVersion",
        "reportType",
        "reportScope",
        "artifactSource",
        "harnessSource",
        "harnessFiles",
        "releaseSetAudit",
        "artifactSetFileCount",
        "auditedArtifactCount",
        "auditedArtifacts",
        "checksumManifest",
        "releaseVersion",
        "nativePlatform",
        "packagedExecutables",
        "runtimeProbes",
        "calibrationRuntimeIdentity",
        "hostIdentity",
        "hostResources",
        "harnessRuntime",
        "operationalTimeoutSeconds",
        "processOutputLimitBytes",
        "attemptCount",
        "retryCount",
        "attempts",
        "freshProcessPerAttempt",
        "stdinMode",
        "privateEnvironmentPerAttempt",
        "privateEnvironmentResidueEntries",
        "selectedObservationScope",
        "endToEndSla",
        "reportProtection",
        "nativeKdfCalibrationEvidence",
        "notCovered",
        "trustAssumptions",
    }:
        raise ReleaseError("KDF evidence report has an invalid root schema")
    if (
        report.get("schemaVersion") != 1
        or isinstance(report.get("schemaVersion"), bool)
        or report.get("reportType") != "inex-kdf-calibration-evidence"
        or report.get("reportScope") != REPORT_SCOPE
        or report.get("nativeKdfCalibrationEvidence") != "passed"
        or report.get("notCovered") != list(REPORT_NOT_COVERED)
        or report.get("trustAssumptions") != list(REPORT_TRUST_ASSUMPTIONS)
        or report.get("artifactSetFileCount") != 4
        or report.get("auditedArtifactCount") != 3
        or report.get("operationalTimeoutSeconds") != PROCESS_TIMEOUT_SECONDS
        or report.get("processOutputLimitBytes") != PROCESS_OUTPUT_LIMIT_BYTES
        or report.get("attemptCount") != ATTEMPT_COUNT
        or report.get("retryCount") != 0
        or report.get("freshProcessPerAttempt") is not True
        or report.get("stdinMode") != "null"
        or report.get("privateEnvironmentPerAttempt") is not True
        or report.get("privateEnvironmentResidueEntries") != 0
        or isinstance(report.get("privateEnvironmentResidueEntries"), bool)
        or report.get("selectedObservationScope")
        != "validation-possible-libsodium-init-secure-allocation-and-argon2id-before-key-drop"
        or report.get("endToEndSla") is not False
    ):
        raise ReleaseError("KDF evidence report has invalid fixed scope metadata")
    if isinstance(report.get("nativePlatform"), str) and report[
        "nativePlatform"
    ].startswith("windows-"):
        raise ReleaseError(WINDOWS_EVIDENCE_BOUNDARY_ERROR)
    _validate_source(report.get("artifactSource"), "artifact source")
    _validate_source(report.get("harnessSource"), "harness source")

    release_set_audit = report.get("releaseSetAudit")
    if not isinstance(release_set_audit, dict):
        raise ReleaseError("KDF evidence has no nested release-set audit")
    artifact_audit.validate_release_set_report(release_set_audit)
    release_version = report.get("releaseVersion")
    platform_name = report.get("nativePlatform")
    if (
        not isinstance(release_version, str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", release_version)
        is None
        or not isinstance(platform_name, str)
        or platform_name not in PLATFORMS
        or release_set_audit.get("releaseVersion") != release_version
        or release_set_audit.get("platform") != platform_name
        or release_set_audit.get("source") != report.get("artifactSource")
    ):
        raise ReleaseError("KDF evidence has a mismatched release identity")

    release_artifacts = release_set_audit.get("artifacts")
    audited_artifacts = report.get("auditedArtifacts")
    if not isinstance(release_artifacts, list):
        raise ReleaseError("KDF evidence has invalid release-set artifacts")
    expected_artifacts = [
        {"name": record["name"], "sha256": record["sha256"]}
        for record in release_artifacts
    ]
    if audited_artifacts != expected_artifacts:
        raise ReleaseError("KDF evidence artifact hashes differ from the strict audit")
    artifact_names = [record["name"] for record in expected_artifacts]
    _validate_file_records(
        audited_artifacts, "artifact", expected_names=artifact_names
    )
    _validate_file_records(
        report.get("harnessFiles"),
        "harness",
        expected_names=KDF_HARNESS_FILES,
    )
    checksum_manifest = report.get("checksumManifest")
    if (
        not isinstance(checksum_manifest, dict)
        or set(checksum_manifest) != {"name", "sha256"}
        or checksum_manifest.get("name") != "SHA256SUMS"
        or not isinstance(checksum_manifest.get("sha256"), str)
        or re.fullmatch(r"[0-9a-f]{64}", checksum_manifest["sha256"]) is None
    ):
        raise ReleaseError("KDF evidence has an invalid checksum-manifest identity")

    rust_artifacts = [
        record
        for record in expected_artifacts
        if artifact_audit.artifact_identity(record["name"])[0] == "rust"
    ]
    suffix = PLATFORMS[platform_name]["binary_suffix"]
    packaged_executables = report.get("packagedExecutables")
    runtime_probes = report.get("runtimeProbes")
    if (
        len(rust_artifacts) != 1
        or not isinstance(packaged_executables, list)
        or len(packaged_executables) != 2
        or not isinstance(runtime_probes, list)
        or len(runtime_probes) != 2
    ):
        raise ReleaseError("KDF evidence has an invalid packaged runtime set")
    expected_products = ("inex", "inexd")
    expected_arguments = (("runtime-info",), ("--runtime-info",))
    for product, arguments, executable, probe in zip(
        expected_products,
        expected_arguments,
        packaged_executables,
        runtime_probes,
        strict=True,
    ):
        expected_member = (
            f"inex-{release_version}-{platform_name}/bin/{product}{suffix}"
        )
        if (
            not isinstance(executable, dict)
            or set(executable)
            != {"product", "archiveName", "archiveSha256", "memberName", "sha256"}
            or executable.get("product") != product
            or executable.get("archiveName") != rust_artifacts[0]["name"]
            or executable.get("archiveSha256") != rust_artifacts[0]["sha256"]
            or executable.get("memberName") != expected_member
            or not isinstance(executable.get("sha256"), str)
            or re.fullmatch(r"[0-9a-f]{64}", executable["sha256"]) is None
        ):
            raise ReleaseError("KDF evidence executable differs from the audited Rust archive")
        shared_digest_field = {
            "inex": "sharedCliSha256",
            "inexd": "sharedSidecarSha256",
        }[product]
        if executable["sha256"] != release_set_audit.get(shared_digest_field):
            raise ReleaseError(
                f"KDF evidence {product} differs from its shared release identity"
            )
        if (
            not isinstance(probe, dict)
            or set(probe)
            != {
                "product",
                "arguments",
                "exitStatus",
                "privateEnvironmentResidueEntries",
                "runtimeInfo",
            }
            or probe.get("product") != product
            or probe.get("arguments") != list(arguments)
            or probe.get("exitStatus") != 0
            or isinstance(probe.get("exitStatus"), bool)
            or probe.get("privateEnvironmentResidueEntries") != 0
            or isinstance(probe.get("privateEnvironmentResidueEntries"), bool)
            or probe.get("runtimeInfo")
            != expected_runtime_info(product, release_version, platform_name)
        ):
            raise ReleaseError("KDF evidence has an invalid exact runtime-info probe")

    runtime_identity = report.get("calibrationRuntimeIdentity")
    expected_runtime = _expected_runtime_identity(release_version, platform_name)
    if runtime_identity != expected_runtime:
        raise ReleaseError("KDF evidence has an invalid calibration runtime identity")
    attempts = report.get("attempts")
    if not isinstance(attempts, list) or len(attempts) != ATTEMPT_COUNT:
        raise ReleaseError("KDF evidence does not contain exactly three attempts")
    for ordinal, attempt in enumerate(attempts, start=1):
        if (
            not isinstance(attempt, dict)
            or set(attempt)
            != {
                "ordinal",
                "exitStatus",
                "privateEnvironmentResidueEntries",
                "calibrationReport",
                "processResourceObservation",
            }
            or attempt.get("ordinal") != ordinal
            or isinstance(attempt.get("ordinal"), bool)
            or attempt.get("exitStatus") != 0
            or isinstance(attempt.get("exitStatus"), bool)
            or attempt.get("privateEnvironmentResidueEntries") != 0
            or isinstance(attempt.get("privateEnvironmentResidueEntries"), bool)
        ):
            raise ReleaseError("KDF evidence has an invalid ordinal attempt record")
        validate_calibration_observation(
            attempt.get("calibrationReport"),
            expected_version=release_version,
            expected_platform=platform_name,
        )
        observation = attempt["calibrationReport"]
        if any(
            observation[field] != runtime_identity[field]
            for field in CALIBRATION_RUNTIME_FIELDS
        ):
            raise ReleaseError("KDF evidence attempts do not share one runtime identity")
        validate_process_resource_observation(
            attempt.get("processResourceObservation"), platform_name
        )

    host_identity = report.get("hostIdentity")
    if (
        not isinstance(host_identity, dict)
        or set(host_identity)
        != {"operatingSystem", "kernelRelease", "architecture", "cpuDescriptor"}
        or any(
            not isinstance(host_identity.get(field), str)
            or not host_identity[field]
            or len(host_identity[field])
            > (64 if field in {"operatingSystem", "architecture"} else 256)
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in host_identity[field]
            )
            for field in host_identity
        )
    ):
        raise ReleaseError("KDF evidence has invalid privacy-safe host identity")
    expected_system = "linux" if platform_name.startswith("linux-") else "windows"
    architecture_aliases = (
        {"amd64", "x86_64"}
        if platform_name.endswith("x64")
        else {"aarch64", "arm64"}
    )
    if (
        host_identity["operatingSystem"].casefold() != expected_system
        or host_identity["architecture"].casefold() not in architecture_aliases
    ):
        raise ReleaseError("KDF evidence host identity differs from the native platform")
    host_resources = report.get("hostResources")
    if (
        not isinstance(host_resources, dict)
        or set(host_resources) != {"logicalProcessorCount", "physicalMemoryBytes"}
        or any(
            not isinstance(host_resources.get(field), int)
            or isinstance(host_resources.get(field), bool)
            for field in host_resources
        )
        or not 1 <= host_resources["logicalProcessorCount"] <= 1_048_576
        or not 64 * 1024 * 1024 <= host_resources["physicalMemoryBytes"] <= (1 << 64) - 1
    ):
        raise ReleaseError("KDF evidence has invalid privacy-safe host resources")
    harness_runtime = report.get("harnessRuntime")
    if harness_runtime != {
        "implementation": HARNESS_PYTHON_IMPLEMENTATION,
        "pythonVersion": HARNESS_PYTHON_VERSION,
    }:
        raise ReleaseError("KDF evidence has an invalid harness runtime identity")
    if report.get("reportProtection") != expected_report_protection(platform_name):
        raise ReleaseError("KDF evidence has an invalid platform report-protection claim")


def encode_evidence_report(report: dict[str, object]) -> bytes:
    validate_evidence_report(report)
    return (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def run_kdf_calibration_drill(
    artifact_directory: Path,
    *,
    process_runner: Callable[..., ProcessCapture] | None = None,
    runtime_probe_runner: Callable[..., ProcessCapture] | None = None,
    resource_observer: Callable[[], dict[str, int]] | None = None,
    identity_observer: Callable[[], dict[str, str]] | None = None,
) -> tuple[dict[str, object], bytes]:
    if os.name == "nt":
        raise ReleaseError(WINDOWS_EVIDENCE_BOUNDARY_ERROR)
    _require_supported_harness_runtime()
    artifact_directory = artifact_directory.resolve(strict=True)
    harness_source, harness_hashes = _capture_harness_state()
    runner = run_calibration_process if process_runner is None else process_runner
    probe_runner = (
        run_runtime_probe_process if runtime_probe_runner is None else runtime_probe_runner
    )
    observe_resources = (
        host_resource_observation if resource_observer is None else resource_observer
    )
    observe_identity = (
        host_identity_observation if identity_observer is None else identity_observer
    )

    with tempfile.TemporaryDirectory(prefix="inex-kdf-calibration-") as temporary_name:
        temporary = Path(temporary_name)
        if os.name != "nt":
            temporary.chmod(0o700)
        artifact_snapshot = temporary / "artifact-snapshot"
        lifecycle.snapshot_artifact_directory(artifact_directory, artifact_snapshot)
        artifact_seals = _capture_artifact_snapshot_seals(artifact_snapshot)
        (
            artifact_entries,
            artifact_hashes,
            artifact_source,
            release_version,
            platform_name,
            release_set_audit,
        ) = lifecycle.capture_audited_artifacts(artifact_snapshot)
        expected_snapshot_names = {*artifact_hashes, "SHA256SUMS"}
        if set(artifact_seals) != expected_snapshot_names:
            raise ReleaseError(
                "the initial four-file artifact snapshot differs from the strict audit"
            )
        snapshot_paths = _snapshot_file_paths(artifact_snapshot)
        for name, seal in artifact_seals.items():
            _verify_physical_file_seal(
                snapshot_paths[name], seal, f"artifact snapshot file {name}"
            )
        if platform_name != lifecycle.native_platform():
            raise ReleaseError("the release artifact does not match the current native host")
        cli, daemon = lifecycle.extract_packaged_binaries(
            artifact_entries["rust"], platform_name, temporary / "packaged-bin"
        )
        suffix = PLATFORMS[platform_name]["binary_suffix"]
        executable_paths = {"inex": cli, "inexd": daemon}
        executable_seals = {
            product: _capture_physical_file_seal(
                executable,
                f"packaged {product} executable",
                strip_posix_write_bits=True,
                require_posix_executable=True,
            )
            for product, executable in executable_paths.items()
        }
        executable_members: dict[str, str] = {}
        executable_hashes: dict[str, str] = {}
        for product, executable in executable_paths.items():
            members = [
                name
                for name in artifact_entries["rust"]
                if name.endswith(f"/bin/{product}{suffix}")
            ]
            if len(members) != 1:
                raise ReleaseError(
                    "the audited Rust archive does not contain one executable per product"
                )
            member = members[0]
            digest = executable_seals[product].sha256
            if digest != sha256_bytes(artifact_entries["rust"][member][0]):
                raise ReleaseError(
                    "an extracted packaged executable differs from audited archive bytes"
                )
            executable_members[product] = member
            executable_hashes[product] = digest
        rust_artifacts = [
            name
            for name in artifact_hashes
            if artifact_audit.artifact_identity(name)[0] == "rust"
        ]
        if len(rust_artifacts) != 1:
            raise ReleaseError("the audited artifact set does not contain one Rust archive")
        for product, shared_digest_field in (
            ("inex", "sharedCliSha256"),
            ("inexd", "sharedSidecarSha256"),
        ):
            if executable_hashes[product] != release_set_audit.get(shared_digest_field):
                raise ReleaseError(
                    f"the packaged {product} differs from its strict shared release identity"
                )
        _verify_execution_inputs(
            executable_paths,
            executable_seals,
            artifact_snapshot,
            artifact_seals,
        )

        runtime_probes: list[dict[str, object]] = []
        for product, arguments in (
            ("inex", ("runtime-info",)),
            ("inexd", ("--runtime-info",)),
        ):
            probe_root = temporary / f"runtime-probe-{product}"
            probe_root.mkdir(mode=0o700)
            environment, cwd = _private_environment(probe_root)
            files_before = lifecycle.snapshot_regular_tree(probe_root)
            directories_before = lifecycle.directory_manifest(probe_root)
            _verify_execution_inputs(
                executable_paths,
                executable_seals,
                artifact_snapshot,
                artifact_seals,
            )
            capture = probe_runner(
                executable_paths[product],
                arguments,
                environment=environment,
                cwd=cwd,
                timeout=PROCESS_TIMEOUT_SECONDS,
                platform_name=platform_name,
            )
            _verify_execution_inputs(
                executable_paths,
                executable_seals,
                artifact_snapshot,
                artifact_seals,
            )
            if not isinstance(capture, ProcessCapture) or capture.resource_observation is not None:
                raise ReleaseError("a runtime-info probe returned an invalid bounded capture")
            runtime_info = parse_runtime_info(
                capture.stdout,
                product=product,
                version=release_version,
                platform_name=platform_name,
            )
            if (
                lifecycle.snapshot_regular_tree(probe_root) != files_before
                or lifecycle.directory_manifest(probe_root) != directories_before
            ):
                raise ReleaseError("a runtime-info process left private-environment residue")
            runtime_probes.append(
                {
                    "product": product,
                    "arguments": list(arguments),
                    "exitStatus": 0,
                    "privateEnvironmentResidueEntries": 0,
                    "runtimeInfo": runtime_info,
                }
            )

        attempts: list[dict[str, object]] = []
        for ordinal in range(1, ATTEMPT_COUNT + 1):
            attempt_root = temporary / f"attempt-{ordinal}"
            attempt_root.mkdir(mode=0o700)
            environment, cwd = _private_environment(attempt_root)
            files_before = lifecycle.snapshot_regular_tree(attempt_root)
            directories_before = lifecycle.directory_manifest(attempt_root)
            _verify_execution_inputs(
                executable_paths,
                executable_seals,
                artifact_snapshot,
                artifact_seals,
            )
            capture = runner(
                cli,
                environment=environment,
                cwd=cwd,
                timeout=PROCESS_TIMEOUT_SECONDS,
                platform_name=platform_name,
            )
            _verify_execution_inputs(
                executable_paths,
                executable_seals,
                artifact_snapshot,
                artifact_seals,
            )
            if not isinstance(capture, ProcessCapture) or capture.resource_observation is None:
                raise ReleaseError("a KDF calibration attempt returned an invalid bounded capture")
            observation = parse_calibration_report(
                capture.stdout,
                expected_version=release_version,
                expected_platform=platform_name,
            )
            validate_process_resource_observation(
                capture.resource_observation, platform_name
            )
            if (
                lifecycle.snapshot_regular_tree(attempt_root) != files_before
                or lifecycle.directory_manifest(attempt_root) != directories_before
            ):
                raise ReleaseError("a KDF calibration process left private-environment residue")
            attempts.append(
                {
                    "ordinal": ordinal,
                    "exitStatus": 0,
                    "privateEnvironmentResidueEntries": 0,
                    "calibrationReport": observation,
                    "processResourceObservation": capture.resource_observation,
                }
            )

        host_identity = observe_identity()
        host_resources = observe_resources()
        lifecycle.assert_harness_source_unchanged(
            REPOSITORY_ROOT, harness_hashes, harness_source
        )
        _verify_execution_inputs(
            executable_paths,
            executable_seals,
            artifact_snapshot,
            artifact_seals,
        )
        runtime_identity = {
            field: attempts[0]["calibrationReport"][field]
            for field in CALIBRATION_RUNTIME_FIELDS
        }
        report: dict[str, object] = {
            "schemaVersion": 1,
            "reportType": "inex-kdf-calibration-evidence",
            "reportScope": REPORT_SCOPE,
            "artifactSource": artifact_source,
            "harnessSource": harness_source,
            "harnessFiles": [
                {"name": name, "sha256": harness_hashes[name]}
                for name in KDF_HARNESS_FILES
            ],
            "releaseSetAudit": release_set_audit,
            "artifactSetFileCount": 4,
            "auditedArtifactCount": len(artifact_hashes),
            "auditedArtifacts": [
                {"name": name, "sha256": artifact_hashes[name]}
                for name in sorted(artifact_hashes)
            ],
            "checksumManifest": {
                "name": "SHA256SUMS",
                "sha256": artifact_seals["SHA256SUMS"].sha256,
            },
            "releaseVersion": release_version,
            "nativePlatform": platform_name,
            "packagedExecutables": [
                {
                    "product": product,
                    "archiveName": rust_artifacts[0],
                    "archiveSha256": artifact_hashes[rust_artifacts[0]],
                    "memberName": executable_members[product],
                    "sha256": executable_hashes[product],
                }
                for product in ("inex", "inexd")
            ],
            "runtimeProbes": runtime_probes,
            "calibrationRuntimeIdentity": runtime_identity,
            "hostIdentity": host_identity,
            "hostResources": host_resources,
            "harnessRuntime": {
                "implementation": HARNESS_PYTHON_IMPLEMENTATION,
                "pythonVersion": HARNESS_PYTHON_VERSION,
            },
            "operationalTimeoutSeconds": PROCESS_TIMEOUT_SECONDS,
            "processOutputLimitBytes": PROCESS_OUTPUT_LIMIT_BYTES,
            "attemptCount": ATTEMPT_COUNT,
            "retryCount": 0,
            "attempts": attempts,
            "freshProcessPerAttempt": True,
            "stdinMode": "null",
            "privateEnvironmentPerAttempt": True,
            "privateEnvironmentResidueEntries": 0,
            "selectedObservationScope": (
                "validation-possible-libsodium-init-secure-allocation-and-argon2id-before-key-drop"
            ),
            "endToEndSla": False,
            "reportProtection": expected_report_protection(platform_name),
            "nativeKdfCalibrationEvidence": "passed",
            "notCovered": list(REPORT_NOT_COVERED),
            "trustAssumptions": list(REPORT_TRUST_ASSUMPTIONS),
        }
        encoded = encode_evidence_report(report)
        return report, encoded


def _path_is_within(
    candidate: Path, parent: Path, *, case_insensitive: bool | None = None
) -> bool:
    insensitive = os.name == "nt" if case_insensitive is None else case_insensitive
    candidate_text = os.path.abspath(os.fspath(candidate))
    parent_text = os.path.abspath(os.fspath(parent))
    if insensitive:
        candidate_text = os.path.normcase(candidate_text).casefold()
        parent_text = os.path.normcase(parent_text).casefold()
    try:
        return os.path.commonpath((candidate_text, parent_text)) == parent_text
    except ValueError:
        return False


def resolve_evidence_output_path(output: Path, artifact_directory: Path) -> Path:
    try:
        portable_archive_key(output.name)
    except ReleaseError as error:
        raise ReleaseError("KDF evidence output name is not portable or ADS-safe") from error
    try:
        artifact_directory = artifact_directory.resolve(strict=True)
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise ReleaseError(
            "KDF evidence output parent or artifact directory is unavailable"
        ) from error
    if lifecycle.is_link_like(parent) or not parent.is_dir() or not output.name:
        raise ReleaseError("KDF evidence output parent is unsafe")
    resolved = parent / output.name
    if _path_is_within(resolved, artifact_directory):
        raise ReleaseError("KDF evidence report cannot be written inside the artifact directory")
    try:
        metadata = resolved.lstat()
    except FileNotFoundError:
        return resolved
    except OSError as error:
        raise ReleaseError("KDF evidence output path is unavailable") from error
    if lifecycle.is_link_like(resolved, metadata) or stat.S_ISREG(metadata.st_mode):
        raise ReleaseError("KDF evidence output path already exists")
    raise ReleaseError("KDF evidence output path is unsafe")


def write_evidence_report(path: Path, encoded: bytes) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    binary = getattr(os, "O_BINARY", 0)
    created = False
    descriptor = -1
    try:
        try:
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | no_follow | binary,
                0o600,
            )
            created = True
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(descriptor)
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    except BaseException as error:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        if isinstance(error, OSError):
            raise ReleaseError("KDF evidence report could not be written safely") from error
        raise
    try:
        metadata = path.lstat()
        if (
            lifecycle.is_link_like(path, metadata)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (os.name != "nt" and stat.S_IMODE(metadata.st_mode) != 0o600)
            or lifecycle.sha256_file(path) != sha256_bytes(encoded)
        ):
            raise ReleaseError(
                "KDF evidence report identity or platform protection is invalid"
            )
    except BaseException:
        if created:
            try:
                path.unlink()
            except OSError:
                pass
        raise


def main() -> int:
    arguments = parse_arguments()
    if os.name == "nt":
        raise ReleaseError(WINDOWS_EVIDENCE_BOUNDARY_ERROR)
    _require_supported_harness_runtime()
    artifact_directory = arguments.directory.resolve(strict=True)
    output = resolve_evidence_output_path(arguments.output, artifact_directory)
    _report, encoded = run_kdf_calibration_drill(artifact_directory)
    write_evidence_report(output, encoded)
    print(f"kdf-calibration-evidence-sha256: {sha256_bytes(encoded)}")
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
        print(f"drill_kdf_calibration: {error}", file=sys.stderr)
        raise SystemExit(1) from None
