#!/usr/bin/env python3
"""Prepare hash-pinned libsodium MSVC inputs before offline Cargo builds.

The locked crate's source pair is copied from Cargo's checksum-verified package,
and the MSVC pair is fetched from a versioned upstream release. The locked
`libsodium-sys-stable` build script performs the official public-key signature
verification for both pairs when it consumes `SODIUM_DIST_DIR`.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys


BASE_URL = (
    "https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE"
)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOCKED_CRATE_NAME = "libsodium-sys-stable"
LOCKED_CRATE_VERSION = "1.24.0"
LOCKED_CRATE_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
BUNDLED_FILES = {
    "LATEST.tar.gz": {
        "sha256": "b20a92e7ec25b285eafa349d721a5bb27e3a8ba94c0816630a127883f1d1b3ab",
        "max_bytes": 2_100_000,
    },
    "LATEST.tar.gz.minisig": {
        "sha256": "2162883303fb903068519916871476b192d5cf31d5e412378db8ae05a0c05895",
        "max_bytes": 4_096,
    },
}
FILES = {
    "libsodium-1.0.22-stable-msvc.zip": {
        "source_name": "libsodium-1.0.22-msvc.zip",
        "sha256": "3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279",
        "max_bytes": 18_000_000,
    },
    "libsodium-1.0.22-stable-msvc.zip.minisig": {
        "source_name": "libsodium-1.0.22-msvc.zip.minisig",
        "sha256": "3210cf4d985f7b192bb8d5eb2ec7f481e0f47420f144cf1069921f714bfad1d1",
        "max_bytes": 4_096,
    },
}


class FetchError(RuntimeError):
    pass


def read_bounded_regular_file(path: Path, maximum: int, label: str) -> bytes:
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise FetchError(f"{label} is missing") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size > maximum
    ):
        raise FetchError(f"{label} is not a bounded single-link regular file")
    payload = path.read_bytes()
    after = path.lstat()
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_after != identity_before or len(payload) != before.st_size:
        raise FetchError(f"{label} changed while it was read")
    return payload


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare hash-pinned libsodium source and MSVC archives with their "
            "minisign companions."
        )
    )
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--github-env",
        action="store_true",
        help="Append the native absolute SODIUM_DIST_DIR to GITHUB_ENV.",
    )
    return parser.parse_args()


def locked_crate_directory() -> Path:
    cargo = shutil.which("cargo")
    if cargo is None:
        raise FetchError("cargo is required to resolve the locked libsodium package")
    try:
        completed = subprocess.run(
            [
                cargo,
                "metadata",
                "--locked",
                "--format-version",
                "1",
                "--manifest-path",
                str(PROJECT_ROOT / "Cargo.toml"),
            ],
            check=True,
            cwd=PROJECT_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
        metadata = json.loads(completed.stdout)
    except (subprocess.CalledProcessError, json.JSONDecodeError) as error:
        raise FetchError("could not resolve locked libsodium package metadata") from error

    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise FetchError("locked Cargo metadata has no package list")
    matches = [
        package
        for package in packages
        if isinstance(package, dict)
        and package.get("name") == LOCKED_CRATE_NAME
        and package.get("version") == LOCKED_CRATE_VERSION
        and package.get("source") == LOCKED_CRATE_SOURCE
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("manifest_path"), str):
        raise FetchError("locked Cargo metadata does not identify the reviewed libsodium crate")
    return Path(matches[0]["manifest_path"]).parent


def copy_bundled_input(
    filename: str,
    source_directory: Path,
    destination: Path,
    expected: dict[str, object],
) -> None:
    source = source_directory / filename
    payload = read_bounded_regular_file(
        source,
        int(expected["max_bytes"]),
        f"locked libsodium input {filename}",
    )
    if hashlib.sha256(payload).hexdigest() != expected["sha256"]:
        raise FetchError(f"locked libsodium input checksum mismatch: {filename}")

    temporary = destination.with_name(destination.name + ".tmp")
    try:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        with temporary.open("xb") as handle:
            handle.write(payload)
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def download(filename: str, destination: Path, expected: dict[str, object]) -> None:
    maximum = int(expected["max_bytes"])
    source_name = str(expected["source_name"])
    temporary = destination.with_name(destination.name + ".tmp")
    curl = shutil.which("curl")
    if curl is None:
        raise FetchError("curl is required to fetch the pinned release input")
    try:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        subprocess.run(
            [
                curl,
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--location",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "15",
                "--max-time",
                "300",
                "--max-filesize",
                str(maximum),
                "--retry",
                "2",
                "--retry-all-errors",
                "--retry-delay",
                "2",
                "--output",
                str(temporary),
                f"{BASE_URL}/{source_name}",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
        )
        payload = read_bounded_regular_file(
            temporary, maximum, f"downloaded libsodium input {filename}"
        )
        digest = hashlib.sha256(payload).hexdigest()
        if digest != expected["sha256"]:
            raise FetchError(f"libsodium input checksum mismatch: {filename}")
        os.replace(temporary, destination)
    except subprocess.CalledProcessError as error:
        raise FetchError(f"could not download pinned libsodium input: {filename}") from error
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def existing_is_valid(path: Path, expected: dict[str, object]) -> bool:
    try:
        payload = read_bounded_regular_file(
            path, int(expected["max_bytes"]), f"existing libsodium input {path.name}"
        )
    except FetchError:
        return False
    return hashlib.sha256(payload).hexdigest() == expected["sha256"]


def main() -> int:
    arguments = parse_arguments()
    output_argument = str(arguments.output)
    if "\r" in output_argument or "\n" in output_argument:
        raise FetchError("output path must not contain line breaks")
    prospective_output = arguments.output.resolve(strict=False)
    if "\r" in str(prospective_output) or "\n" in str(prospective_output):
        raise FetchError("resolved output path must not contain line breaks")
    if arguments.output.is_symlink():
        raise FetchError("output must be a non-symlink directory")
    arguments.output.mkdir(parents=True, exist_ok=True)
    if arguments.output.is_symlink() or not arguments.output.is_dir():
        raise FetchError("output must be a non-symlink directory")
    output = arguments.output.resolve(strict=True)
    if "\r" in str(output) or "\n" in str(output):
        raise FetchError("resolved output path must not contain line breaks")
    source_directory = None
    for filename, expected in BUNDLED_FILES.items():
        destination = output / filename
        if not existing_is_valid(destination, expected):
            if source_directory is None:
                source_directory = locked_crate_directory()
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            copy_bundled_input(filename, source_directory, destination, expected)
        print(f"verified {filename} sha256:{expected['sha256']}")
    for filename, expected in FILES.items():
        destination = output / filename
        if not existing_is_valid(destination, expected):
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
            download(filename, destination, expected)
        print(f"verified {filename} sha256:{expected['sha256']}")
    if arguments.github_env:
        github_environment = os.environ.get("GITHUB_ENV")
        if not github_environment:
            raise FetchError("GITHUB_ENV is unavailable")
        with Path(github_environment).open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(f"SODIUM_DIST_DIR={output}\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (FetchError, OSError) as error:
        print(f"fetch_libsodium_dist: {error}", file=sys.stderr)
        raise SystemExit(1) from None
