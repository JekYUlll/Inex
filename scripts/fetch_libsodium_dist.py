#!/usr/bin/env python3
"""Fetch hash-pinned libsodium MSVC inputs before offline Cargo builds.

The companion minisign file is fetched and hash-pinned here. The locked
`libsodium-sys-stable` build script performs the actual public-key signature
verification when it consumes `SODIUM_DIST_DIR`.
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys


BASE_URL = "https://download.libsodium.org/libsodium/releases"
FILES = {
    "libsodium-1.0.22-stable-msvc.zip": {
        "sha256": "fd816a693dd4cb1afc39da167172c653a51d4dc95cf852f15855e456e1f25e90",
        "max_bytes": 18_000_000,
    },
    "libsodium-1.0.22-stable-msvc.zip.minisig": {
        "sha256": "4f3f4f8b093c35f00c125529e914c5432ea392be466f4ac8728d8d132dba81e0",
        "max_bytes": 4_096,
    },
}


class FetchError(RuntimeError):
    pass


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Download and hash-check the libsodium MSVC archive and minisign companion."
    )
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--github-env",
        action="store_true",
        help="Append the native absolute SODIUM_DIST_DIR to GITHUB_ENV.",
    )
    return parser.parse_args()


def download(filename: str, destination: Path, expected: dict[str, object]) -> None:
    maximum = int(expected["max_bytes"])
    temporary = destination.with_name(destination.name + ".tmp")
    curl = shutil.which("curl")
    if curl is None:
        raise FetchError("curl is required to fetch the pinned release input")
    try:
        subprocess.run(
            [
                curl,
                "--proto",
                "=https",
                "--tlsv1.2",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "15",
                "--max-time",
                "300",
                "--retry",
                "2",
                "--retry-all-errors",
                "--retry-delay",
                "2",
                "--output",
                str(temporary),
                f"{BASE_URL}/{filename}",
            ],
            check=True,
            stdin=subprocess.DEVNULL,
        )
        size = temporary.stat().st_size
        if size > maximum:
            raise FetchError(f"libsodium input exceeded its size ceiling: {filename}")
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
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


def existing_is_valid(path: Path, expected_sha256: str) -> bool:
    if not path.is_file() or path.is_symlink():
        return False
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest == expected_sha256


def main() -> int:
    arguments = parse_arguments()
    output = arguments.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if output.is_symlink() or not output.is_dir():
        raise FetchError("output must be a non-symlink directory")
    for filename, expected in FILES.items():
        destination = output / filename
        if not existing_is_valid(destination, str(expected["sha256"])):
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
