#!/usr/bin/env python3
"""Build fail-closed, platform-specific Inex release archives from existing outputs."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

from release_common import (
    PLATFORMS,
    REPOSITORY_ROOT,
    ReleaseError,
    files_as_entries,
    generate_license_materials,
    normalize_zip,
    package_manifest,
    read_json,
    require_regular_file,
    validate_native_binary,
    write_reproducible_zip,
    write_sha256sums,
)


SUBLIME_PACKAGE_FILES = (
    ".python-version",
    "Inex.py",
    "Inex.sublime-settings",
    "Main.sublime-commands",
    "README.md",
    "inex_core.py",
    "inex_markdown.py",
    "inex_password.py",
    "inex_rpc.py",
)

DOCUMENTATION_FILES = (
    "PRD.md",
    "acceptance-matrix.md",
    "architecture.md",
    "dependencies.md",
    "editor-security.md",
    "installation.md",
    "operations-and-recovery.md",
    "release-checklist.md",
    "troubleshooting.md",
    "user-guide.md",
    "spec/edry-v1.md",
    "spec/git-merge-v1.md",
    "spec/import-v1.md",
    "spec/json-rpc-v1.md",
    "spec/vault-v1.md",
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Package Rust binaries and the VS Code/Sublime clients for one native target."
    )
    parser.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    parser.add_argument(
        "--target-dir",
        type=Path,
        default=REPOSITORY_ROOT / "target" / "release",
        help="Directory containing native release inex/inexd binaries.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="Output directory (default: target/release-artifacts/<platform>).",
    )
    parser.add_argument(
        "--vsce",
        type=Path,
        help="Pinned vsce JavaScript entrypoint (default: packaging/vsce/node_modules/@vscode/vsce/vsce).",
    )
    return parser.parse_args()


def project_version(repository_root: Path) -> str:
    vscode_package = read_json(repository_root / "editors" / "vscode" / "package.json")
    editor_version = (
        vscode_package.get("version") if isinstance(vscode_package, dict) else None
    )
    stable_version = re.compile(
        r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    )
    if not isinstance(editor_version, str) or stable_version.fullmatch(editor_version) is None:
        raise ReleaseError("VS Code package has an invalid release version")
    try:
        cargo_document = tomllib.loads(
            (repository_root / "Cargo.toml").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError("Cargo workspace manifest is not valid UTF-8 TOML") from error
    workspace = cargo_document.get("workspace")
    workspace_package = workspace.get("package") if isinstance(workspace, dict) else None
    cargo_version = (
        workspace_package.get("version")
        if isinstance(workspace_package, dict)
        else None
    )
    if not isinstance(cargo_version, str) or stable_version.fullmatch(cargo_version) is None:
        raise ReleaseError("Cargo workspace has an invalid release version")
    if cargo_version != editor_version:
        raise ReleaseError("Cargo workspace and editor package versions differ")
    return editor_version


def add_documentation_entries(
    entries: dict[str, tuple[bytes, int]], repository_root: Path, prefix: str
) -> None:
    for relative in DOCUMENTATION_FILES:
        source = require_regular_file(
            repository_root / "docs" / relative, f"release documentation {relative}"
        )
        entries[f"{prefix}docs/{relative}"] = (source.read_bytes(), 0o644)


def add_license_text_entries(
    entries: dict[str, tuple[bytes, int]],
    prefix: str,
    license_texts: dict[str, tuple[bytes, int]],
) -> None:
    for relative, value in license_texts.items():
        entries[f"{prefix}{relative}"] = value


def read_product_entries(
    repository_root: Path,
    target_dir: Path,
    platform: str,
    licenses: bytes,
    license_texts: dict[str, tuple[bytes, int]],
) -> tuple[dict[str, tuple[bytes, int]], Path, Path]:
    configuration = PLATFORMS[platform]
    suffix = configuration["binary_suffix"]
    inex = require_regular_file(target_dir / f"inex{suffix}", "inex binary", executable=True)
    inexd = require_regular_file(target_dir / f"inexd{suffix}", "inexd binary", executable=True)
    validate_native_binary(inex.read_bytes(), platform, "inex binary")
    validate_native_binary(inexd.read_bytes(), platform, "inexd binary")
    root_name = f"inex-{project_version(repository_root)}-{platform}"
    files = {
        f"{root_name}/LICENSE": (repository_root / "LICENSE", 0o644),
        f"{root_name}/README.md": (repository_root / "README.md", 0o644),
        f"{root_name}/SECURITY.md": (repository_root / "SECURITY.md", 0o644),
        f"{root_name}/bin/inex{suffix}": (inex, 0o755),
        f"{root_name}/bin/inexd{suffix}": (inexd, 0o755),
    }
    entries = files_as_entries(files)
    entries[f"{root_name}/THIRD_PARTY_LICENSES.json"] = (licenses, 0o644)
    add_license_text_entries(entries, f"{root_name}/", license_texts)
    add_documentation_entries(entries, repository_root, f"{root_name}/")
    return entries, inex, inexd


def package_rust(
    repository_root: Path,
    output_directory: Path,
    target_dir: Path,
    platform: str,
    version: str,
    licenses: bytes,
    license_texts: dict[str, tuple[bytes, int]],
) -> tuple[Path, Path]:
    entries, inex, inexd = read_product_entries(
        repository_root, target_dir, platform, licenses, license_texts
    )
    prefix = f"inex-{version}-{platform}"
    manifest_name = f"{prefix}/PACKAGE-MANIFEST.json"
    entries[manifest_name] = (
        package_manifest(
            kind="rust-binaries",
            platform=platform,
            version=version,
            repository_root=repository_root,
            entries=entries,
            install_format="portable ZIP with bin/inex and bin/inexd",
        ),
        0o644,
    )
    output = output_directory / f"inex-rust-{version}-{platform}.zip"
    write_reproducible_zip(output, entries)
    return output, inexd


def stage_vscode(
    repository_root: Path,
    stage: Path,
    inexd: Path,
    platform: str,
    version: str,
    licenses: bytes,
    license_texts: dict[str, tuple[bytes, int]],
) -> None:
    editor = repository_root / "editors" / "vscode"
    runtime = PLATFORMS[platform]["vscode_runtime"]
    suffix = PLATFORMS[platform]["binary_suffix"]
    stage.mkdir(parents=True, exist_ok=False)

    files = {
        "LICENSE.txt": (repository_root / "LICENSE", 0o644),
        "SECURITY.md": (repository_root / "SECURITY.md", 0o644),
        "dist/extension.js": (editor / "dist" / "extension.js", 0o644),
        "resources/inex.svg": (editor / "resources" / "inex.svg", 0o644),
        f"bin/{runtime}/inexd{suffix}": (inexd, 0o755),
    }
    entries = files_as_entries(files)
    readme = (editor / "README.md").read_text(encoding="utf-8")
    readme = readme.replace("../../docs/editor-security.md", "docs/editor-security.md")
    entries["readme.md"] = (readme.encode("utf-8"), 0o644)
    package = read_json(editor / "package.json")
    if not isinstance(package, dict):
        raise ReleaseError("VS Code package manifest must be an object")
    package["repository"] = {
        "type": "git",
        "url": "https://github.com/JekYUlll/Inex.git",
    }
    package["files"] = [
        "LICENSE.txt",
        "PACKAGE-MANIFEST.json",
        "SECURITY.md",
        "THIRD_PARTY_LICENSES.json",
        "THIRD_PARTY_LICENSE_TEXTS/**",
        "bin/**",
        "dist/extension.js",
        "docs/**",
        "readme.md",
        "resources/**",
    ]
    entries["package.json"] = (
        (json.dumps(package, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        ),
        0o644,
    )
    entries["THIRD_PARTY_LICENSES.json"] = (licenses, 0o644)
    add_license_text_entries(entries, "", license_texts)
    add_documentation_entries(entries, repository_root, "")
    entries["PACKAGE-MANIFEST.json"] = (
        package_manifest(
            kind="vscode-extension",
            platform=platform,
            version=version,
            repository_root=repository_root,
            entries=entries,
            install_format=f"VSIX target {PLATFORMS[platform]['vscode_target']}",
        ),
        0o644,
    )
    for name, (data, mode) in entries.items():
        destination = stage / Path(name)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(mode)


def package_vscode(
    repository_root: Path,
    output_directory: Path,
    inexd: Path,
    platform: str,
    version: str,
    licenses: bytes,
    license_texts: dict[str, tuple[bytes, int]],
    vsce: Path,
) -> Path:
    require_regular_file(vsce, "pinned vsce entrypoint")
    node_name = "node.exe" if os.name == "nt" else "node"
    node = shutil.which(node_name)
    if node is None:
        raise ReleaseError("Node.js is required to run pinned vsce")
    node = str(Path(node).resolve())
    require_regular_file(Path(node), "Node.js executable", executable=True)
    output = output_directory / f"inex-vscode-{version}-{platform}.vsix"
    with tempfile.TemporaryDirectory(prefix="inex-vscode-stage-") as temporary:
        stage = Path(temporary) / "extension"
        stage_vscode(
            repository_root, stage, inexd, platform, version, licenses, license_texts
        )
        environment = os.environ.copy()
        for sensitive_name in (
            "AZURE_DEVOPS_EXT_PAT",
            "GITHUB_TOKEN",
            "NODE_AUTH_TOKEN",
            "NPM_TOKEN",
            "VSCE_PAT",
        ):
            environment.pop(sensitive_name, None)
        environment["NO_UPDATE_NOTIFIER"] = "1"
        environment["npm_config_offline"] = "true"
        try:
            subprocess.run(
                [
                    node,
                    str(vsce.resolve()),
                    "package",
                    "--no-dependencies",
                    "--no-rewrite-relative-links",
                    "--target",
                    PLATFORMS[platform]["vscode_target"],
                    "--out",
                    str(output.resolve()),
                ],
                cwd=stage,
                env=environment,
                check=True,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.CalledProcessError) as error:
            raise ReleaseError("pinned vsce failed to package the curated staging tree") from error
    normalize_zip(output)
    return output


def package_sublime(
    repository_root: Path,
    output_directory: Path,
    inexd: Path,
    platform: str,
    version: str,
    licenses: bytes,
    license_texts: dict[str, tuple[bytes, int]],
) -> Path:
    """Create an unpacked-package ZIP, not a compressed .sublime-package.

    The client validates and executes `Packages/Inex/bin/inexd` as a real
    regular file. A .sublime-package remains compressed and therefore cannot
    provide that path without adding an extraction mechanism to product code.
    """

    editor = repository_root / "editors" / "sublime"
    suffix = PLATFORMS[platform]["binary_suffix"]
    files = {
        f"Inex/{name}": (editor / name, 0o644) for name in SUBLIME_PACKAGE_FILES
    }
    files["Inex/LICENSE"] = (repository_root / "LICENSE", 0o644)
    files["Inex/SECURITY.md"] = (repository_root / "SECURITY.md", 0o644)
    files[f"Inex/bin/inexd{suffix}"] = (inexd, 0o755)
    entries = files_as_entries(files)
    entries["Inex/THIRD_PARTY_LICENSES.json"] = (licenses, 0o644)
    add_license_text_entries(entries, "Inex/", license_texts)
    add_documentation_entries(entries, repository_root, "Inex/")
    entries["Inex/PACKAGE-MANIFEST.json"] = (
        package_manifest(
            kind="sublime-unpacked-package",
            platform=platform,
            version=version,
            repository_root=repository_root,
            entries=entries,
            install_format="extract the Inex directory into the Sublime Text Packages directory",
        ),
        0o644,
    )
    output = output_directory / f"inex-sublime-{version}-{platform}.zip"
    write_reproducible_zip(output, entries)
    return output


def default_vsce(repository_root: Path) -> Path:
    return (
        repository_root
        / "packaging"
        / "vsce"
        / "node_modules"
        / "@vscode"
        / "vsce"
        / "vsce"
    )


def main() -> int:
    arguments = parse_arguments()
    repository_root = REPOSITORY_ROOT
    platform = arguments.platform
    target_dir = arguments.target_dir.resolve()
    output_directory = (
        arguments.output_dir
        if arguments.output_dir is not None
        else repository_root / "target" / "release-artifacts" / platform
    ).resolve()
    vsce = (arguments.vsce or default_vsce(repository_root)).resolve()
    output_directory.mkdir(parents=True, exist_ok=True)

    version = project_version(repository_root)
    licenses, license_texts = generate_license_materials(repository_root, version)
    rust_archive, inexd = package_rust(
        repository_root,
        output_directory,
        target_dir,
        platform,
        version,
        licenses,
        license_texts,
    )
    vscode_archive = package_vscode(
        repository_root,
        output_directory,
        inexd,
        platform,
        version,
        licenses,
        license_texts,
        vsce,
    )
    sublime_archive = package_sublime(
        repository_root,
        output_directory,
        inexd,
        platform,
        version,
        licenses,
        license_texts,
    )
    checksum_path = write_sha256sums(
        output_directory, [rust_archive, vscode_archive, sublime_archive]
    )
    print(
        json.dumps(
            {
                "outputDirectory": str(output_directory),
                "platform": platform,
                "artifacts": [
                    rust_archive.name,
                    vscode_archive.name,
                    sublime_archive.name,
                    checksum_path.name,
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"package_release: {error}", file=sys.stderr)
        raise SystemExit(1) from None
