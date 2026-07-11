#!/usr/bin/env python3
"""Audit release ZIP/VSIX contents and their SHA-256 manifest."""

from __future__ import annotations

import argparse
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import xml.etree.ElementTree as ElementTree
import zipfile

from release_common import (
    MAX_ARCHIVE_MEMBER_BYTES,
    MAX_ARCHIVE_MEMBERS,
    MAX_ARCHIVE_TOTAL_BYTES,
    PLATFORMS,
    ReleaseError,
    register_archive_member,
    require_regular_file,
    safe_archive_name,
    sha256_bytes,
    sha256_file,
    validate_native_binary,
    zip_member_name,
)


FORBIDDEN_COMPONENTS = {
    "__pycache__",
    ".git",
    ".vscode-test",
    "canaries",
    "canary",
    "coverage",
    "fixture",
    "fixtures",
    "node_modules",
    "test",
    "tests",
}
FORBIDDEN_SUFFIXES = (
    ".env",
    ".key",
    ".map",
    ".pem",
    ".pyc",
    ".pyo",
    ".ts",
    ".tsx",
)
FORBIDDEN_PAYLOAD_MARKERS = (
    b"INEXQA_EDIT_",
    b"INEXQA_ORIGINAL_",
    b"Inex-extension-residue-audit-2026",
    b"inex-residue:",
)
CHECKSUM_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]*)$")
MARKDOWN_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
REQUIRED_DOCUMENTATION = (
    "docs/acceptance-matrix.md",
    "docs/dependencies.md",
    "docs/editor-security.md",
    "docs/installation.md",
    "docs/operations-and-recovery.md",
    "docs/release-checklist.md",
    "docs/troubleshooting.md",
    "docs/user-guide.md",
    "docs/spec/edry-v1.md",
    "docs/spec/git-merge-v1.md",
    "docs/spec/import-v1.md",
    "docs/spec/json-rpc-v1.md",
    "docs/spec/vault-v1.md",
)
VSIX_NAMESPACE = "http://schemas.microsoft.com/developer/vsx-schema/2011"
CONTENT_TYPES_NAMESPACE = (
    "http://schemas.openxmlformats.org/package/2006/content-types"
)
MAX_VSIX_METADATA_BYTES = 1024 * 1024


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail if release artifacts contain forbidden or unexpected material."
    )
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--allow-dirty-source",
        action="store_true",
        help="Developer-only: audit contents while allowing a manifest marked dirty.",
    )
    return parser.parse_args()


def artifact_identity(name: str) -> tuple[str, str, str]:
    match = re.fullmatch(
        r"inex-(rust|vscode|sublime)-([0-9]+\.[0-9]+\.[0-9]+)-"
        r"(linux-(?:x64|arm64)|windows-(?:x64|arm64))\.(zip|vsix)",
        name,
    )
    if match is None:
        raise ReleaseError(f"unexpected release artifact name: {name}")
    kind, version, platform, extension = match.groups()
    expected_extension = "vsix" if kind == "vscode" else "zip"
    if extension != expected_extension:
        raise ReleaseError(f"release artifact has the wrong extension: {name}")
    return kind, version, platform


def validate_member_name(name: str) -> str:
    normalized = safe_archive_name(name)
    path = PurePosixPath(normalized)
    lowered_components = {component.casefold() for component in path.parts}
    forbidden = lowered_components & FORBIDDEN_COMPONENTS
    if forbidden:
        raise ReleaseError(
            f"artifact contains forbidden path component {sorted(forbidden)[0]}: {name}"
        )
    lowered = normalized.casefold()
    if lowered.endswith(FORBIDDEN_SUFFIXES):
        raise ReleaseError(f"artifact contains forbidden file type: {name}")
    return normalized


def _read_zip_entries(
    archive: zipfile.ZipFile, label: str
) -> dict[str, tuple[bytes, int]]:
    entries: dict[str, tuple[bytes, int]] = {}
    seen: dict[str, tuple[str, bool]] = {}
    total = 0
    if not archive.infolist() or len(archive.infolist()) > MAX_ARCHIVE_MEMBERS:
        raise ReleaseError("artifact has an invalid member count")
    for information in archive.infolist():
        raw_name, is_directory = zip_member_name(information)
        name = validate_member_name(raw_name)
        register_archive_member(seen, name, is_directory=is_directory)
        mode = information.external_attr >> 16
        if information.flag_bits & 0x1:
            raise ReleaseError(f"artifact contains an encrypted member: {name}")
        if is_directory:
            continue
        if name in entries:
            raise ReleaseError(f"artifact contains a duplicate member: {name}")
        if information.file_size > MAX_ARCHIVE_MEMBER_BYTES:
            raise ReleaseError(f"artifact member exceeds the size ceiling: {name}")
        total += information.file_size
        if total > MAX_ARCHIVE_TOTAL_BYTES:
            raise ReleaseError(f"artifact exceeds the total size ceiling: {label}")
        data = archive.read(information)
        if len(data) != information.file_size:
            raise ReleaseError(f"artifact member size changed while reading: {name}")
        for marker in FORBIDDEN_PAYLOAD_MARKERS:
            if marker in data:
                raise ReleaseError(f"artifact contains a test canary marker: {name}")
        entries[name] = (data, mode & 0o777)
    if not entries:
        raise ReleaseError(f"artifact is empty: {label}")
    return entries


def read_zip_entries(path: Path) -> dict[str, tuple[bytes, int]]:
    try:
        with zipfile.ZipFile(path, "r") as archive:
            return _read_zip_entries(archive, path.name)
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseError(f"artifact is not a valid ZIP container: {path}") from error


def read_zip_entries_from_bytes(data: bytes, label: str) -> dict[str, tuple[bytes, int]]:
    if len(data) > MAX_ARCHIVE_TOTAL_BYTES:
        raise ReleaseError(f"artifact container exceeds the size ceiling: {label}")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as archive:
            return _read_zip_entries(archive, label)
    except (OSError, zipfile.BadZipFile) as error:
        raise ReleaseError(f"artifact is not a valid ZIP container: {label}") from error


def require_entry(entries: dict[str, tuple[bytes, int]], name: str) -> tuple[bytes, int]:
    try:
        return entries[name]
    except KeyError as error:
        raise ReleaseError(f"artifact is missing required member: {name}") from error


def find_single(entries: dict[str, tuple[bytes, int]], suffix: str) -> str:
    matches = [name for name in entries if name.endswith(suffix)]
    if len(matches) != 1:
        raise ReleaseError(f"expected one {suffix} member, found {len(matches)}")
    return matches[0]


def _parse_strict_xml(data: bytes, label: str) -> ElementTree.Element:
    if not data or len(data) > MAX_VSIX_METADATA_BYTES:
        raise ReleaseError(f"{label} has an invalid size")
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise ReleaseError(f"{label} contains a forbidden XML declaration")
    try:
        text = data.decode("utf-8", "strict")
        root = ElementTree.fromstring(text)
    except (UnicodeError, ElementTree.ParseError) as error:
        raise ReleaseError(f"{label} is not strict UTF-8 XML") from error
    return root


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"VSIX package.json repeats a key: {key}")
        result[key] = value
    return result


def _single_xml_child(
    parent: ElementTree.Element, qualified_name: str, label: str
) -> ElementTree.Element:
    matches = [child for child in parent if child.tag == qualified_name]
    if len(matches) != 1:
        raise ReleaseError(f"VSIX manifest must contain exactly one {label}")
    return matches[0]


def validate_vsix_metadata(
    entries: dict[str, tuple[bytes, int]], *, expected_platform: str, expected_version: str
) -> None:
    """Validate the signed identity surface interpreted by VS Code's installer."""

    manifest_data = require_entry(entries, "extension.vsixmanifest")[0]
    content_types_data = require_entry(entries, "[Content_Types].xml")[0]
    package_data = require_entry(entries, "extension/package.json")[0]

    manifest = _parse_strict_xml(manifest_data, "extension.vsixmanifest")
    manifest_tag = f"{{{VSIX_NAMESPACE}}}PackageManifest"
    if manifest.tag != manifest_tag or manifest.attrib != {"Version": "2.0.0"}:
        raise ReleaseError("VSIX manifest has an invalid PackageManifest root")
    allowed_root_children = {
        f"{{{VSIX_NAMESPACE}}}{name}"
        for name in ("Metadata", "Installation", "Dependencies", "Assets")
    }
    if {child.tag for child in manifest} != allowed_root_children or len(manifest) != 4:
        raise ReleaseError("VSIX manifest has an unexpected root structure")

    metadata = _single_xml_child(
        manifest, f"{{{VSIX_NAMESPACE}}}Metadata", "Metadata element"
    )
    expected_metadata_children = {
        f"{{{VSIX_NAMESPACE}}}{name}"
        for name in (
            "Identity",
            "DisplayName",
            "Description",
            "Tags",
            "Categories",
            "GalleryFlags",
            "Properties",
            "License",
        )
    }
    if {child.tag for child in metadata} != expected_metadata_children or len(metadata) != 8:
        raise ReleaseError("VSIX manifest has an unexpected Metadata structure")
    identity = _single_xml_child(
        metadata, f"{{{VSIX_NAMESPACE}}}Identity", "Identity element"
    )
    expected_identity = {
        "Language": "en-US",
        "Id": "inex-vscode",
        "Version": expected_version,
        "Publisher": "horeb",
        "TargetPlatform": PLATFORMS[expected_platform]["vscode_target"],
    }
    if identity.attrib != expected_identity or list(identity):
        raise ReleaseError("VSIX manifest identity does not match the artifact")

    installation = _single_xml_child(
        manifest, f"{{{VSIX_NAMESPACE}}}Installation", "Installation element"
    )
    target = _single_xml_child(
        installation,
        f"{{{VSIX_NAMESPACE}}}InstallationTarget",
        "InstallationTarget element",
    )
    if (
        len(installation) != 1
        or installation.attrib
        or target.attrib != {"Id": "Microsoft.VisualStudio.Code"}
        or list(target)
    ):
        raise ReleaseError("VSIX manifest has an invalid installation target")

    dependencies = _single_xml_child(
        manifest, f"{{{VSIX_NAMESPACE}}}Dependencies", "Dependencies element"
    )
    if dependencies.attrib or list(dependencies):
        raise ReleaseError("VSIX manifest declares unexpected dependencies")

    assets = _single_xml_child(
        manifest, f"{{{VSIX_NAMESPACE}}}Assets", "Assets element"
    )
    asset_records: set[tuple[str, str]] = set()
    for asset in assets:
        if asset.tag != f"{{{VSIX_NAMESPACE}}}Asset" or set(asset.attrib) != {
            "Type",
            "Path",
            "Addressable",
        }:
            raise ReleaseError("VSIX manifest contains an invalid asset record")
        if asset.attrib["Addressable"] != "true" or list(asset):
            raise ReleaseError("VSIX manifest contains a non-addressable asset")
        path = safe_archive_name(asset.attrib["Path"])
        require_entry(entries, path)
        record = (asset.attrib["Type"], path)
        if record in asset_records:
            raise ReleaseError("VSIX manifest repeats an asset")
        asset_records.add(record)
    expected_assets = {
        ("Microsoft.VisualStudio.Code.Manifest", "extension/package.json"),
        ("Microsoft.VisualStudio.Services.Content.Details", "extension/readme.md"),
        ("Microsoft.VisualStudio.Services.Content.License", "extension/LICENSE.txt"),
    }
    if asset_records != expected_assets:
        raise ReleaseError("VSIX manifest assets differ from the curated package")

    properties = _single_xml_child(
        metadata, f"{{{VSIX_NAMESPACE}}}Properties", "Properties element"
    )
    property_values: dict[str, str] = {}
    for child in properties:
        if (
            child.tag != f"{{{VSIX_NAMESPACE}}}Property"
            or set(child.attrib) != {"Id", "Value"}
            or list(child)
        ):
            raise ReleaseError("VSIX manifest contains an invalid property")
        property_id = child.attrib["Id"]
        if not property_id or property_id in property_values:
            raise ReleaseError("VSIX manifest repeats a property")
        property_values[property_id] = child.attrib["Value"]
    engine_values = [property_values.get("Microsoft.VisualStudio.Code.Engine")]
    if engine_values != ["^1.125.0"]:
        raise ReleaseError("VSIX manifest has an unexpected VS Code engine")

    license_element = _single_xml_child(
        metadata, f"{{{VSIX_NAMESPACE}}}License", "License element"
    )
    if license_element.attrib or (license_element.text or "").strip() != "extension/LICENSE.txt":
        raise ReleaseError("VSIX manifest has an invalid license path")

    try:
        package = json.loads(
            package_data.decode("utf-8", "strict"), object_pairs_hook=_strict_json_object
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("VSIX package.json is not strict UTF-8 JSON") from error
    if not isinstance(package, dict):
        raise ReleaseError("VSIX package.json is not an object")
    expected_package_fields = {
        "name": "inex-vscode",
        "publisher": "horeb",
        "version": expected_version,
        "main": "./dist/extension.js",
    }
    if any(package.get(key) != value for key, value in expected_package_fields.items()):
        raise ReleaseError("VSIX package.json identity does not match the artifact")
    engines = package.get("engines")
    if not isinstance(engines, dict) or engines.get("vscode") != "^1.125.0":
        raise ReleaseError("VSIX package.json has an unexpected VS Code engine")

    content_types = _parse_strict_xml(content_types_data, "[Content_Types].xml")
    if (
        content_types.tag != f"{{{CONTENT_TYPES_NAMESPACE}}}Types"
        or content_types.attrib
        or not list(content_types)
    ):
        raise ReleaseError("VSIX content-types document has an invalid root")
    mappings: dict[str, str] = {}
    for child in content_types:
        if child.tag != f"{{{CONTENT_TYPES_NAMESPACE}}}Default" or set(
            child.attrib
        ) != {"Extension", "ContentType"}:
            raise ReleaseError("VSIX content-types document contains an invalid mapping")
        extension = child.attrib["Extension"]
        content_type = child.attrib["ContentType"]
        if (
            re.fullmatch(r"\.[A-Za-z0-9][A-Za-z0-9._+-]*", extension) is None
            or re.fullmatch(r"[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+", content_type) is None
            or list(child)
            or (child.text or "").strip()
        ):
            raise ReleaseError("VSIX content-types document has a malformed mapping")
        key = extension.casefold()
        if key in mappings:
            raise ReleaseError("VSIX content-types document repeats an extension")
        mappings[key] = content_type
    required_mappings = {
        ".vsixmanifest": "text/xml",
        ".json": "application/json",
        ".js": "application/javascript",
        ".md": "text/markdown",
        ".svg": "image/svg+xml",
        ".txt": "text/plain",
    }
    if any(mappings.get(key) != value for key, value in required_mappings.items()):
        raise ReleaseError("VSIX content-types document omits a required mapping")


def validate_license_inventory(
    data: bytes,
    entries: dict[str, tuple[bytes, int]],
    root_prefix: str,
    expected_version: str,
) -> None:
    try:
        inventory = json.loads(data)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("third-party license inventory is invalid JSON") from error
    if not isinstance(inventory, dict) or inventory.get("schemaVersion") != 1:
        raise ReleaseError("third-party license inventory has an invalid schema")
    project = inventory.get("project")
    if (
        not isinstance(project, dict)
        or project.get("name") != "Inex"
        or project.get("version") != expected_version
        or project.get("license") != "GPL-3.0-only"
        or project.get("repository") != "https://github.com/JekYUlll/Inex"
    ):
        raise ReleaseError("third-party license inventory has invalid project provenance")
    components = inventory.get("components")
    if not isinstance(components, list) or not components:
        raise ReleaseError("third-party license inventory is empty")
    declared_license_files: set[str] = set()
    for component in components:
        if not isinstance(component, dict) or not all(
            isinstance(component.get(key), str) and component[key]
            for key in ("name", "version", "license", "source")
        ):
            raise ReleaseError("third-party license inventory has an invalid component")
        license_files = component.get("licenseFiles")
        if not isinstance(license_files, list) or not license_files:
            raise ReleaseError("third-party component has no bundled license text")
        for relative in license_files:
            if not isinstance(relative, str):
                raise ReleaseError("third-party component license path is invalid")
            archive_name = safe_archive_name(root_prefix + relative)
            declared_license_files.add(archive_name)
            content = require_entry(entries, archive_name)[0]
            if not content:
                raise ReleaseError("third-party component license text is empty")
    native = inventory.get("bundledNativeLibraries")
    if not isinstance(native, list) or not any(
        isinstance(component, dict)
        and component.get("name") == "libsodium"
        and component.get("version") == "1.0.22"
        for component in native
    ):
        raise ReleaseError("third-party inventory omits bundled libsodium 1.0.22")
    for component in native:
        if not isinstance(component, dict):
            raise ReleaseError("native license inventory component is invalid")
        license_files = component.get("licenseFiles")
        if not isinstance(license_files, list) or not license_files:
            raise ReleaseError("native dependency has no bundled license text")
        for relative in license_files:
            if not isinstance(relative, str):
                raise ReleaseError("native dependency license path is invalid")
            archive_name = safe_archive_name(root_prefix + relative)
            declared_license_files.add(archive_name)
            content = require_entry(entries, archive_name)[0]
            if not content:
                raise ReleaseError("native dependency license text is empty")
    actual_license_files = {
        name
        for name in entries
        if name.startswith(root_prefix + "THIRD_PARTY_LICENSE_TEXTS/")
    }
    if actual_license_files != declared_license_files:
        raise ReleaseError("bundled license texts differ from the license inventory")


def _resolve_markdown_target(root_prefix: str, source: str, raw_target: str) -> str | None:
    target = raw_target.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1]
    if not target or target.startswith("#"):
        return None
    lowered = target.casefold()
    if lowered.startswith(("http://", "https://", "mailto:")):
        return None
    target = target.split("#", 1)[0].split("?", 1)[0]
    if not target:
        return None
    if target.startswith("/") or "\\" in target or "%" in target:
        raise ReleaseError(f"packaged Markdown has an unsafe local link: {source} -> {raw_target}")
    parts = list(PurePosixPath(source).parent.parts)
    for component in PurePosixPath(target).parts:
        if component in {"", "."}:
            continue
        if component == "..":
            if not parts or "/".join(parts) == root_prefix.rstrip("/"):
                raise ReleaseError(
                    f"packaged Markdown link escapes its package: {source} -> {raw_target}"
                )
            parts.pop()
        else:
            parts.append(component)
    resolved = "/".join(parts)
    if not resolved.startswith(root_prefix):
        raise ReleaseError(f"packaged Markdown link escapes its package: {source} -> {raw_target}")
    return resolved


def validate_documentation(
    entries: dict[str, tuple[bytes, int]], root_prefix: str
) -> None:
    require_entry(entries, root_prefix + "SECURITY.md")
    for relative in REQUIRED_DOCUMENTATION:
        require_entry(entries, root_prefix + relative)
    for name, (content, _mode) in entries.items():
        if not name.startswith(root_prefix) or not name.casefold().endswith(".md"):
            continue
        try:
            markdown = content.decode("utf-8", "strict")
        except UnicodeError as error:
            raise ReleaseError(f"packaged Markdown is not UTF-8: {name}") from error
        for match in MARKDOWN_LINK.finditer(markdown):
            target = _resolve_markdown_target(root_prefix, name, match.group(1))
            if target is not None:
                require_entry(entries, target)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ReleaseError(f"package manifest repeats a JSON key: {key}")
        result[key] = value
    return result


def validate_package_manifest(
    data: bytes,
    expected_kind: str,
    entries: dict[str, tuple[bytes, int]],
    *,
    archive_prefix: str = "",
    manifest_name: str,
    require_clean_source: bool,
    expected_platform: str,
    expected_version: str,
) -> None:
    try:
        text = data.decode("utf-8", "strict")
        manifest = json.loads(text, object_pairs_hook=_strict_json_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError("package manifest is not strict UTF-8 JSON") from error
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {
            "schemaVersion",
            "package",
            "platform",
            "version",
            "installFormat",
            "source",
            "files",
        }
        or not isinstance(manifest.get("schemaVersion"), int)
        or isinstance(manifest.get("schemaVersion"), bool)
        or manifest.get("schemaVersion") != 1
    ):
        raise ReleaseError("package manifest has an invalid schema")
    kind = manifest.get("package")
    expected = {
        "rust": "rust-binaries",
        "vscode": "vscode-extension",
        "sublime": "sublime-unpacked-package",
    }[expected_kind]
    if kind != expected:
        raise ReleaseError(f"package manifest kind mismatch: expected {expected}")
    if manifest.get("platform") != expected_platform:
        raise ReleaseError("package manifest platform does not match the artifact identity")
    if manifest.get("version") != expected_version:
        raise ReleaseError("package manifest version does not match the artifact identity")
    expected_install_format = {
        "rust": "portable ZIP with bin/inex and bin/inexd",
        "vscode": f"VSIX target {PLATFORMS[expected_platform]['vscode_target']}",
        "sublime": "extract the Inex directory into the Sublime Text Packages directory",
    }[expected_kind]
    if manifest.get("installFormat") != expected_install_format:
        raise ReleaseError("package manifest install format does not match the artifact")
    source = manifest.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"commit", "dirtySourceTree", "repository"}
        or not isinstance(source.get("commit"), str)
        or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["commit"])
        or source.get("repository") != "https://github.com/JekYUlll/Inex"
    ):
        raise ReleaseError("package manifest has an invalid source revision")
    dirty_source = source.get("dirtySourceTree")
    if not isinstance(dirty_source, bool):
        raise ReleaseError("package manifest omits the source cleanliness result")
    if require_clean_source and dirty_source:
        raise ReleaseError("release package was built from a dirty source tree")
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ReleaseError("package manifest has no file inventory")
    declared: set[str] = set()
    for record in files:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
            raise ReleaseError("package manifest contains an invalid file record")
        relative = record.get("path")
        digest = record.get("sha256")
        size = record.get("size")
        if (
            not isinstance(relative, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
        ):
            raise ReleaseError("package manifest contains malformed file metadata")
        archive_name = safe_archive_name(f"{archive_prefix}{relative}")
        if archive_name in declared:
            raise ReleaseError(f"package manifest repeats a file: {archive_name}")
        declared.add(archive_name)
        content = require_entry(entries, archive_name)[0]
        if len(content) != size or sha256_bytes(content) != digest:
            raise ReleaseError(f"package manifest file digest mismatch: {archive_name}")

    product_entries = {
        name
        for name in entries
        if expected_kind != "vscode" or name.startswith("extension/")
    }
    if product_entries != declared | {manifest_name}:
        raise ReleaseError("archive product files differ from the package manifest allowlist")


def validate_rust(
    entries: dict[str, tuple[bytes, int]],
    *,
    require_clean_source: bool,
    expected_platform: str,
    expected_version: str,
) -> None:
    license_name = find_single(entries, "/THIRD_PARTY_LICENSES.json")
    manifest_name = find_single(entries, "/PACKAGE-MANIFEST.json")
    root_prefix = license_name.removesuffix("THIRD_PARTY_LICENSES.json")
    if root_prefix != f"inex-{expected_version}-{expected_platform}/":
        raise ReleaseError("Rust archive root does not match its artifact identity")
    require_entry(entries, root_prefix + "LICENSE")
    cli = find_single(entries, "/bin/inex") if any(
        name.endswith("/bin/inex") for name in entries
    ) else find_single(entries, "/bin/inex.exe")
    sidecar = (
        find_single(entries, "/bin/inexd")
        if any(name.endswith("/bin/inexd") for name in entries)
        else find_single(entries, "/bin/inexd.exe")
    )
    if expected_platform.startswith("linux-") and (
        entries[cli][1] & 0o111 == 0 or entries[sidecar][1] & 0o111 == 0
    ):
        raise ReleaseError("Linux Rust binary is not executable in the archive")
    expected_suffix = ".exe" if expected_platform.startswith("windows-") else ""
    if not cli.endswith("inex" + expected_suffix) or not sidecar.endswith(
        "inexd" + expected_suffix
    ):
        raise ReleaseError("Rust executable suffix does not match the artifact platform")
    validate_native_binary(entries[cli][0], expected_platform, "packaged inex")
    validate_native_binary(entries[sidecar][0], expected_platform, "packaged inexd")
    validate_license_inventory(
        require_entry(entries, license_name)[0], entries, root_prefix, expected_version
    )
    validate_documentation(entries, root_prefix)
    validate_package_manifest(
        require_entry(entries, manifest_name)[0],
        "rust",
        entries,
        manifest_name=manifest_name,
        require_clean_source=require_clean_source,
        expected_platform=expected_platform,
        expected_version=expected_version,
    )


def validate_vscode(
    entries: dict[str, tuple[bytes, int]],
    *,
    require_clean_source: bool,
    expected_platform: str,
    expected_version: str,
) -> None:
    root_members = {name for name in entries if not name.startswith("extension/")}
    if root_members != {"[Content_Types].xml", "extension.vsixmanifest"}:
        raise ReleaseError("VSIX root members differ from the pinned vsce structure")
    required = (
        "extension/LICENSE.txt",
        "extension/PACKAGE-MANIFEST.json",
        "extension/THIRD_PARTY_LICENSES.json",
        "extension/dist/extension.js",
        "extension/package.json",
        "extension/resources/inex.svg",
        "extension.vsixmanifest",
        "[Content_Types].xml",
    )
    for name in required:
        require_entry(entries, name)
    validate_vsix_metadata(
        entries,
        expected_platform=expected_platform,
        expected_version=expected_version,
    )
    sidecars = [
        name
        for name in entries
        if name.startswith("extension/bin/") and name.rsplit("/", 1)[-1] in {"inexd", "inexd.exe"}
    ]
    if len(sidecars) != 1:
        raise ReleaseError(f"VSIX must contain exactly one target sidecar, found {len(sidecars)}")
    if sidecars[0].endswith("/inexd") and entries[sidecars[0]][1] & 0o111 == 0:
        raise ReleaseError("Linux VSIX sidecar is not executable in the archive")
    runtime = sidecars[0].split("/")[-2]
    platform = {
        "linux-x64": "linux-x64",
        "linux-arm64": "linux-arm64",
        "win32-x64": "windows-x64",
        "win32-arm64": "windows-arm64",
    }.get(runtime)
    if platform is None:
        raise ReleaseError("VSIX sidecar has an unsupported runtime directory")
    if platform != expected_platform:
        raise ReleaseError("VSIX runtime directory does not match the artifact platform")
    validate_native_binary(entries[sidecars[0]][0], expected_platform, "VSIX inexd")
    validate_license_inventory(
        entries["extension/THIRD_PARTY_LICENSES.json"][0],
        entries,
        "extension/",
        expected_version,
    )
    validate_documentation(entries, "extension/")
    validate_package_manifest(
        entries["extension/PACKAGE-MANIFEST.json"][0],
        "vscode",
        entries,
        archive_prefix="extension/",
        manifest_name="extension/PACKAGE-MANIFEST.json",
        require_clean_source=require_clean_source,
        expected_platform=expected_platform,
        expected_version=expected_version,
    )


def validate_sublime(
    entries: dict[str, tuple[bytes, int]],
    *,
    require_clean_source: bool,
    expected_platform: str,
    expected_version: str,
) -> None:
    required = (
        "Inex/Inex.py",
        "Inex/LICENSE",
        "Inex/Main.sublime-commands",
        "Inex/PACKAGE-MANIFEST.json",
        "Inex/THIRD_PARTY_LICENSES.json",
        "Inex/inex_rpc.py",
    )
    for name in required:
        require_entry(entries, name)
    sidecars = [name for name in entries if name in {"Inex/bin/inexd", "Inex/bin/inexd.exe"}]
    if len(sidecars) != 1:
        raise ReleaseError("Sublime artifact must contain exactly one unpacked-package sidecar")
    if sidecars[0].endswith("/inexd") and entries[sidecars[0]][1] & 0o111 == 0:
        raise ReleaseError("Linux Sublime sidecar is not executable in the archive")
    expected_suffix = ".exe" if expected_platform.startswith("windows-") else ""
    if sidecars[0] != "Inex/bin/inexd" + expected_suffix:
        raise ReleaseError("Sublime sidecar suffix does not match the artifact platform")
    validate_native_binary(entries[sidecars[0]][0], expected_platform, "Sublime inexd")
    validate_license_inventory(
        entries["Inex/THIRD_PARTY_LICENSES.json"][0], entries, "Inex/", expected_version
    )
    validate_documentation(entries, "Inex/")
    validate_package_manifest(
        entries["Inex/PACKAGE-MANIFEST.json"][0],
        "sublime",
        entries,
        manifest_name="Inex/PACKAGE-MANIFEST.json",
        require_clean_source=require_clean_source,
        expected_platform=expected_platform,
        expected_version=expected_version,
    )


def parse_checksums(path: Path) -> dict[str, str]:
    require_regular_file(path, "SHA256SUMS")
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ReleaseError("SHA256SUMS is not strict ASCII") from error
    checksums: dict[str, str] = {}
    for line in lines:
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ReleaseError("SHA256SUMS contains a malformed line")
        digest, name = match.groups()
        if name in checksums:
            raise ReleaseError(f"SHA256SUMS repeats an artifact: {name}")
        checksums[name] = digest
    return checksums


def audit_directory(directory: Path, *, require_clean_source: bool = True) -> list[str]:
    try:
        resolved = directory.resolve(strict=True)
    except OSError as error:
        raise ReleaseError(f"release directory is unavailable: {directory}") from error
    if not resolved.is_dir():
        raise ReleaseError(f"release path is not a directory: {directory}")
    checksums = parse_checksums(resolved / "SHA256SUMS")
    artifact_paths = []
    for path in resolved.iterdir():
        if path.name == "SHA256SUMS":
            continue
        if path.is_symlink() or not path.is_file():
            raise ReleaseError(f"release directory contains a non-file entry: {path.name}")
        artifact_paths.append(path)
    artifact_paths.sort(key=lambda path: path.name)
    if len(artifact_paths) != 3:
        raise ReleaseError(f"expected exactly three release archives, found {len(artifact_paths)}")
    if set(checksums) != {path.name for path in artifact_paths}:
        raise ReleaseError("SHA256SUMS and release artifact names differ")

    validated = []
    kinds = set()
    release_identity: tuple[str, str] | None = None
    release_source_identity: tuple[str, bool, str] | None = None
    for path in artifact_paths:
        kind, version, platform = artifact_identity(path.name)
        if kind in kinds:
            raise ReleaseError(f"release directory repeats artifact kind: {kind}")
        kinds.add(kind)
        identity = (version, platform)
        if release_identity is None:
            release_identity = identity
        elif release_identity != identity:
            raise ReleaseError("release directory mixes artifact versions or platforms")
        if sha256_file(path) != checksums[path.name]:
            raise ReleaseError(f"SHA-256 mismatch: {path.name}")
        entries = read_zip_entries(path)
        {"rust": validate_rust, "vscode": validate_vscode, "sublime": validate_sublime}[
            kind
        ](
            entries,
            require_clean_source=require_clean_source,
            expected_platform=platform,
            expected_version=version,
        )
        manifest_name = {
            "rust": f"inex-{version}-{platform}/PACKAGE-MANIFEST.json",
            "vscode": "extension/PACKAGE-MANIFEST.json",
            "sublime": "Inex/PACKAGE-MANIFEST.json",
        }[kind]
        manifest = json.loads(require_entry(entries, manifest_name)[0])
        source = manifest["source"]
        source_identity = (
            source["commit"],
            source["dirtySourceTree"],
            source["repository"],
        )
        if release_source_identity is None:
            release_source_identity = source_identity
        elif release_source_identity != source_identity:
            raise ReleaseError("release directory mixes package source revisions")
        validated.append(path.name)
    if kinds != {"rust", "vscode", "sublime"}:
        raise ReleaseError("release directory does not contain all artifact kinds")
    return validated


def main() -> int:
    arguments = parse_arguments()
    validated = audit_directory(
        arguments.directory, require_clean_source=not arguments.allow_dirty_source
    )
    print(json.dumps({"auditedArtifacts": validated}, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"audit_release_artifacts: {error}", file=sys.stderr)
        raise SystemExit(1) from None
