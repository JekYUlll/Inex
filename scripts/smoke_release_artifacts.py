#!/usr/bin/env python3
"""Execute packaged binaries and optionally install the generated VSIX."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from audit_release_artifacts import artifact_identity, audit_directory
from release_common import PLATFORMS, ReleaseError, safe_archive_name


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke-test an audited release artifact directory.")
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--vscode-cli",
        type=Path,
        help="Optional exact VS Code CLI used to install the platform VSIX.",
    )
    parser.add_argument(
        "--allow-dirty-source",
        action="store_true",
        help="Developer-only: smoke a package whose manifest records a dirty tree.",
    )
    return parser.parse_args()


def extract_archive(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path, "r") as archive:
        for information in archive.infolist():
            if information.is_dir():
                continue
            name = safe_archive_name(information.filename)
            output = destination.joinpath(*name.split("/"))
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(archive.read(information))
            mode = (information.external_attr >> 16) & 0o777
            if mode:
                output.chmod(mode)


def run_binary(executable: Path, arguments: list[str], expected_stdout: str | None) -> str:
    result = subprocess.run(
        [str(executable), *arguments],
        check=False,
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        env={
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "WINDIR": os.environ.get("WINDIR", ""),
        },
    )
    if result.returncode != 0:
        raise ReleaseError(f"packaged executable failed: {executable.name}")
    stdout = result.stdout.decode("utf-8", "strict").strip()
    if expected_stdout is not None and stdout != expected_stdout:
        raise ReleaseError(f"packaged executable returned an unexpected version: {executable.name}")
    if result.stderr:
        raise ReleaseError(f"packaged executable wrote unexpected stderr: {executable.name}")
    return stdout


def require_repository_import_command(executable: Path) -> None:
    usage = run_binary(executable, ["--help"], None)
    expected = (
        "  inex import-repository <source-repository> <destination-vault> [--dry-run]"
    )
    if usage.splitlines().count(expected) != 1:
        raise ReleaseError(
            "packaged CLI does not expose the repository-import command exactly once"
        )


def expected_runtime_info(product: str, version: str, platform: str) -> str:
    return "\n".join(
        (
            "runtime-info-schema: inex-runtime-v1",
            f"product: {product}",
            f"version: {version}",
            f"rust-target: {PLATFORMS[platform]['rust_target']}",
            "rust-debug-assertions: false",
            "libsodium-version: 1.0.22",
            "libsodium-library-major: 26",
            "libsodium-library-minor: 4",
            "libsodium-minimal: false",
        )
    )


def smoke_portable_archives(directory: Path, temporary: Path) -> None:
    rust_archive = next(directory.glob("inex-rust-*.zip"))
    sublime_archive = next(directory.glob("inex-sublime-*.zip"))
    rust_root = temporary / "rust"
    sublime_root = temporary / "sublime"
    extract_archive(rust_archive, rust_root)
    extract_archive(sublime_archive, sublime_root)

    suffix = ".exe" if os.name == "nt" else ""
    inex_matches = list(rust_root.glob(f"*/bin/inex{suffix}"))
    inexd_matches = list(rust_root.glob(f"*/bin/inexd{suffix}"))
    sublime_inexd = sublime_root / "Inex" / "bin" / f"inexd{suffix}"
    if len(inex_matches) != 1 or len(inexd_matches) != 1 or not sublime_inexd.is_file():
        raise ReleaseError("packaged executable layout is invalid")

    _kind, version, platform = artifact_identity(rust_archive.name)
    run_binary(inex_matches[0], ["--version"], f"inex {version}")
    require_repository_import_command(inex_matches[0])
    run_binary(
        inex_matches[0],
        ["runtime-info"],
        expected_runtime_info("inex", version, platform),
    )
    run_binary(
        inexd_matches[0],
        ["--runtime-info"],
        expected_runtime_info("inexd", version, platform),
    )
    run_binary(inexd_matches[0], [], "")
    run_binary(
        sublime_inexd,
        ["--runtime-info"],
        expected_runtime_info("inexd", version, platform),
    )
    run_binary(sublime_inexd, [], "")


def smoke_vsix(directory: Path, vscode_cli: Path, temporary: Path) -> None:
    if not vscode_cli.is_file() or vscode_cli.is_symlink():
        raise ReleaseError("VS Code CLI must be a non-symlink regular file")
    vsix = next(directory.glob("inex-vscode-*.vsix"))
    extensions = temporary / "extensions"
    user_data = temporary / "user-data"
    home = temporary / "home"
    for path in (extensions, user_data, home):
        path.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    for sensitive_name in (
        "AZURE_DEVOPS_EXT_PAT",
        "GITHUB_TOKEN",
        "NODE_AUTH_TOKEN",
        "NPM_TOKEN",
        "VSCE_PAT",
    ):
        environment.pop(sensitive_name, None)
    environment.update(
        {
            "HOME": str(home),
            "XDG_CACHE_HOME": str(temporary / "cache"),
            "XDG_CONFIG_HOME": str(temporary / "config"),
            "XDG_DATA_HOME": str(temporary / "data"),
            "XDG_STATE_HOME": str(temporary / "state"),
        }
    )
    cli_arguments = [
        "--install-extension",
        str(vsix),
        "--force",
        f"--extensions-dir={extensions}",
        f"--user-data-dir={user_data}",
        "--disable-telemetry",
    ]
    if os.name == "nt" and vscode_cli.suffix.casefold() in {".bat", ".cmd"}:
        command_interpreter = environment.get("COMSPEC") or environment.get("ComSpec")
        if not command_interpreter:
            command_interpreter = str(Path(environment["SYSTEMROOT"]) / "System32" / "cmd.exe")
        command = [command_interpreter, "/d", "/s", "/c", str(vscode_cli), *cli_arguments]
    else:
        command = [str(vscode_cli), *cli_arguments]
    result = subprocess.run(
        command,
        env=environment,
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    if result.returncode != 0:
        raise ReleaseError("VS Code failed to install the generated VSIX")

    matches = []
    for package_json in extensions.glob("*/package.json"):
        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            continue
        if package.get("name") == "inex-vscode" and package.get("publisher") == "horeb":
            matches.append(package_json.parent)
    if len(matches) != 1:
        raise ReleaseError("installed VSIX layout was not found exactly once")
    sidecars = list((matches[0] / "bin").glob("*/inexd")) + list(
        (matches[0] / "bin").glob("*/inexd.exe")
    )
    clis = list((matches[0] / "bin").glob("*/inex")) + list(
        (matches[0] / "bin").glob("*/inex.exe")
    )
    if len(sidecars) != 1:
        raise ReleaseError("installed VSIX does not contain exactly one sidecar")
    if len(clis) != 1:
        raise ReleaseError("installed VSIX does not contain exactly one CLI")
    if os.name != "nt":
        for executable, label in ((clis[0], "CLI"), (sidecars[0], "sidecar")):
            if executable.stat().st_mode & 0o111 == 0:
                raise ReleaseError(f"installed VSIX {label} lost its executable mode")
    _kind, version, platform = artifact_identity(vsix.name)
    require_repository_import_command(clis[0])
    run_binary(
        clis[0],
        ["--runtime-info"],
        expected_runtime_info("inex", version, platform),
    )
    run_binary(
        sidecars[0],
        ["--runtime-info"],
        expected_runtime_info("inexd", version, platform),
    )
    run_binary(sidecars[0], [], "")


def main() -> int:
    arguments = parse_arguments()
    directory = arguments.directory.resolve(strict=True)
    audit_directory(directory, require_clean_source=not arguments.allow_dirty_source)
    with tempfile.TemporaryDirectory(prefix="inex-package-smoke-") as temporary_name:
        temporary = Path(temporary_name)
        smoke_portable_archives(directory, temporary)
        if arguments.vscode_cli is not None:
            smoke_vsix(directory, arguments.vscode_cli.resolve(), temporary)
    print(json.dumps({"packageSmoke": "passed", "directory": str(directory)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ReleaseError, StopIteration, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        print(f"smoke_release_artifacts: {error}", file=sys.stderr)
        raise SystemExit(1) from None
