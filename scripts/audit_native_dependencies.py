#!/usr/bin/env python3
"""Verify release binary dependencies with the platform's native inspection tool."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

from release_common import PLATFORMS, ReleaseError, require_regular_file


def _find_dumpbin(platform: str) -> Path:
    discovered = shutil.which("dumpbin.exe") or shutil.which("dumpbin")
    if discovered is not None:
        return Path(discovered).resolve()
    installer = Path(
        os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
    ) / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    require_regular_file(installer, "Visual Studio locator")
    try:
        result = subprocess.run(
            [
                str(installer),
                "-latest",
                "-products",
                "*",
                "-property",
                "installationPath",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError) as error:
        raise ReleaseError("could not locate a Visual Studio installation") from error
    installation = Path(result.stdout.strip())
    target = "arm64" if platform == "windows-arm64" else "x64"
    host_preferences = (
        ("hostarm64", "hostx64", "hostx86")
        if platform == "windows-arm64"
        else ("hostx64", "hostarm64", "hostx86")
    )
    candidates = []
    tools_root = installation / "VC" / "Tools" / "MSVC"
    for version_root in sorted(tools_root.glob("*"), reverse=True):
        for host in host_preferences:
            candidate = version_root / "bin" / host / target / "dumpbin.exe"
            if candidate.is_file() and not candidate.is_symlink():
                candidates.append(candidate)
    if not candidates:
        raise ReleaseError(f"could not locate dumpbin.exe for {platform}")
    return candidates[0].resolve()


def inspect_dependencies(platform: str, binary: Path) -> str:
    require_regular_file(binary, "native dependency input", executable=True)
    if platform.startswith("linux-"):
        tool = shutil.which("readelf")
        if tool is None:
            raise ReleaseError("readelf is required for the Linux release dependency audit")
        # Keep argv[0] from PATH: multicall toolchains (including xlings) select
        # the requested native inspector from that basename.
        command = [tool, "--dynamic", "--wide", str(binary)]
    else:
        command = [str(_find_dumpbin(platform)), "/DEPENDENTS", str(binary)]
    try:
        result = subprocess.run(
            command,
            check=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=30,
        )
    except (OSError, UnicodeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise ReleaseError(f"native dependency inspection failed for {binary.name}") from error
    output = result.stdout + "\n" + result.stderr
    if "libsodium" in output.casefold():
        raise ReleaseError(f"{binary.name} dynamically depends on libsodium")
    evidence_marker = "(needed)" if platform.startswith("linux-") else "image has the following dependencies"
    if evidence_marker not in output.casefold():
        raise ReleaseError(f"native dependency tool returned no dependency evidence for {binary.name}")
    return output


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fail unless native tools confirm release binaries do not depend on libsodium."
    )
    parser.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    parser.add_argument("binaries", nargs="+", type=Path)
    arguments = parser.parse_args()
    for binary in arguments.binaries:
        inspect_dependencies(arguments.platform, binary.resolve())
        print(f"native dependency audit passed: {binary}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"audit_native_dependencies: {error}", file=sys.stderr)
        raise SystemExit(1) from None
