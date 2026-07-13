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
    ACCEPTED_CARGO_LICENSE_EXPRESSIONS,
    LIBSODIUM_LICENSE_SHA256,
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
    "docs/release-notes-0.1.0-pre-alpha.md",
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
LICENSE_POLICY_ARCHIVE_PATH = "DEPENDENCY_LICENSE_POLICY.json"
LICENSE_POLICY_TYPE = "engineering-collection-not-legal-approval"
LICENSE_POLICY_REQUIRED_REVIEW = "independent-legal-review-pending"
LICENSE_INVENTORY_POLICY_STATUS = (
    "engineering-collection-only-independent-legal-review-pending"
)
CARGO_REGISTRY_SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
LICENSE_INVENTORY_SCOPE = {
    "rust": "locked normal/build Cargo packages reachable for the native package target",
    "vscodeRuntime": (
        "no shipped npm runtime dependencies; vscode and Node built-ins are host-provided"
    ),
    "sublimeRuntime": "Python standard library and Sublime host API only",
    "buildTools": "not shipped and intentionally excluded",
}
RELEASE_SET_NOT_COVERED = (
    "artifact-signing-and-publication",
    "independent-legal-review",
    "native-runtime-install-and-editor-behavior",
)
RELEASE_SET_TRUST_ASSUMPTIONS = (
    "artifact-directory-remains-stable-during-audit",
    "auditor-source-and-runtime-are-trusted",
)


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
            raise ReleaseError(f"release JSON repeats a JSON key: {key}")
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


def _parse_canonical_release_json(data: bytes, label: str) -> dict[str, object]:
    try:
        text = data.decode("utf-8", "strict")
        value = json.loads(text, object_pairs_hook=_strict_json_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ReleaseError(f"{label} is not strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ReleaseError(f"{label} is not a JSON object")
    canonical = (
        json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    if data != canonical:
        raise ReleaseError(f"{label} is not canonical JSON")
    return value


def _validate_dependency_license_policy(
    data: bytes,
) -> tuple[set[str], dict[str, object]]:
    policy = _parse_canonical_release_json(data, "dependency license policy")
    if set(policy) != {
        "schemaVersion",
        "policyType",
        "requiredReview",
        "cargoRegistrySource",
        "acceptedCargoLicenseExpressions",
        "bundledNativeLibraries",
    }:
        raise ReleaseError("dependency license policy has an invalid root schema")
    schema = policy.get("schemaVersion")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != 1:
        raise ReleaseError("dependency license policy has an invalid schema version")
    if (
        policy.get("policyType") != LICENSE_POLICY_TYPE
        or policy.get("requiredReview") != LICENSE_POLICY_REQUIRED_REVIEW
        or policy.get("cargoRegistrySource") != CARGO_REGISTRY_SOURCE
    ):
        raise ReleaseError("dependency license policy has invalid fixed metadata")
    expressions = policy.get("acceptedCargoLicenseExpressions")
    if (
        not isinstance(expressions, list)
        or expressions != list(ACCEPTED_CARGO_LICENSE_EXPRESSIONS)
    ):
        raise ReleaseError("dependency license policy expressions differ from the reviewed set")
    native = policy.get("bundledNativeLibraries")
    if not isinstance(native, list) or len(native) != 1:
        raise ReleaseError("dependency license policy has invalid native metadata")
    sodium = native[0]
    if not isinstance(sodium, dict) or sodium != {
        "name": "libsodium",
        "version": "1.0.22",
        "license": "ISC",
        "source": "bundled by libsodium-sys-stable 1.24.0",
        "licenseSha256": LIBSODIUM_LICENSE_SHA256,
    }:
        raise ReleaseError("dependency license policy has invalid libsodium metadata")
    return set(expressions), sodium


def _require_license_text(
    entries: dict[str, tuple[bytes, int]], archive_name: str
) -> bytes:
    content, mode = require_entry(entries, archive_name)
    if not content or mode != 0o644:
        raise ReleaseError("third-party license text is empty or has an invalid mode")
    return content


def validate_license_inventory(
    data: bytes,
    entries: dict[str, tuple[bytes, int]],
    root_prefix: str,
    expected_version: str,
    expected_platform: str,
) -> None:
    policy_name = safe_archive_name(root_prefix + LICENSE_POLICY_ARCHIVE_PATH)
    policy_data, policy_mode = require_entry(entries, policy_name)
    if policy_mode != 0o644:
        raise ReleaseError("dependency license policy has an invalid archive mode")
    accepted_expressions, sodium_policy = _validate_dependency_license_policy(policy_data)

    inventory = _parse_canonical_release_json(data, "third-party license inventory")
    if set(inventory) != {
        "schemaVersion",
        "project",
        "target",
        "licensePolicy",
        "scope",
        "components",
        "bundledNativeLibraries",
    }:
        raise ReleaseError("third-party license inventory has an invalid root schema")
    schema = inventory.get("schemaVersion")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != 1:
        raise ReleaseError("third-party license inventory has an invalid schema version")
    project = inventory.get("project")
    if not isinstance(project, dict) or project != {
        "name": "Inex",
        "version": expected_version,
        "license": "GPL-3.0-only",
        "repository": "https://github.com/JekYUlll/Inex",
    }:
        raise ReleaseError("third-party license inventory has invalid project provenance")
    configuration = PLATFORMS.get(expected_platform)
    if configuration is None or inventory.get("target") != {
        "platform": expected_platform,
        "rustTriple": configuration["rust_target"],
    }:
        raise ReleaseError("third-party license inventory has the wrong target graph")
    if inventory.get("licensePolicy") != {
        "path": LICENSE_POLICY_ARCHIVE_PATH,
        "sha256": sha256_bytes(policy_data),
        "status": LICENSE_INVENTORY_POLICY_STATUS,
    }:
        raise ReleaseError("third-party license inventory has invalid policy provenance")
    if inventory.get("scope") != LICENSE_INVENTORY_SCOPE:
        raise ReleaseError("third-party license inventory has invalid scope metadata")

    components = inventory.get("components")
    if not isinstance(components, list) or not components:
        raise ReleaseError("third-party license inventory is empty")
    component_keys: list[tuple[str, str]] = []
    declared_license_files: set[str] = set()
    for component in components:
        if not isinstance(component, dict) or set(component) != {
            "ecosystem",
            "name",
            "version",
            "license",
            "source",
            "checksum",
            "licenseFiles",
        }:
            raise ReleaseError("third-party license inventory has an invalid Cargo component")
        name = component.get("name")
        version = component.get("version")
        license_expression = component.get("license")
        if not all(isinstance(value, str) and value for value in (name, version)):
            raise ReleaseError("third-party Cargo component has an invalid identity")
        if (
            component.get("ecosystem") != "cargo"
            or component.get("source") != CARGO_REGISTRY_SOURCE
            or not isinstance(license_expression, str)
            or license_expression not in accepted_expressions
            or not isinstance(component.get("checksum"), str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", component["checksum"]) is None
        ):
            raise ReleaseError("third-party Cargo component violates the license policy")
        component_keys.append((name, version))
        license_files = component.get("licenseFiles")
        if (
            not isinstance(license_files, list)
            or not license_files
            or any(
                not isinstance(record, dict)
                or set(record) != {"path", "sha256"}
                or not isinstance(record.get("path"), str)
                or not isinstance(record.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", record["sha256"]) is None
                for record in license_files
            )
            or license_files
            != sorted(license_files, key=lambda record: record["path"])
            or len({record["path"] for record in license_files}) != len(license_files)
        ):
            raise ReleaseError("third-party Cargo license paths are not unique and sorted")
        expected_prefix = f"THIRD_PARTY_LICENSE_TEXTS/cargo/{name}-{version}/"
        for record in license_files:
            relative = record["path"]
            if not relative.startswith(expected_prefix):
                raise ReleaseError("third-party Cargo license path has the wrong component")
            archive_name = safe_archive_name(root_prefix + relative)
            if archive_name in declared_license_files:
                raise ReleaseError("third-party license inventory repeats a license path")
            declared_license_files.add(archive_name)
            if sha256_bytes(_require_license_text(entries, archive_name)) != record["sha256"]:
                raise ReleaseError("third-party Cargo license text has the wrong digest")
    if component_keys != sorted(set(component_keys)):
        raise ReleaseError("third-party Cargo components are not unique and sorted")

    native = inventory.get("bundledNativeLibraries")
    if not isinstance(native, list) or len(native) != 1:
        raise ReleaseError("third-party inventory has invalid native components")
    sodium = native[0]
    if not isinstance(sodium, dict) or set(sodium) != {
        "name",
        "version",
        "license",
        "source",
        "licenseSha256",
        "licenseFiles",
    }:
        raise ReleaseError("native license inventory component has an invalid schema")
    license_files = sodium.get("licenseFiles")
    expected_native_path = "THIRD_PARTY_LICENSE_TEXTS/native/libsodium-1.0.22/LICENSE"
    expected_native_files = [
        {"path": expected_native_path, "sha256": LIBSODIUM_LICENSE_SHA256}
    ]
    if (
        {key: sodium.get(key) for key in sodium_policy} != sodium_policy
        or license_files != expected_native_files
    ):
        raise ReleaseError("native license inventory does not match the reviewed libsodium")
    native_archive_name = safe_archive_name(root_prefix + expected_native_path)
    if native_archive_name in declared_license_files:
        raise ReleaseError("third-party license inventory repeats the native license path")
    declared_license_files.add(native_archive_name)
    native_license = _require_license_text(entries, native_archive_name)
    if sha256_bytes(native_license) != LIBSODIUM_LICENSE_SHA256:
        raise ReleaseError("bundled libsodium license text has the wrong digest")

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
        require_entry(entries, license_name)[0],
        entries,
        root_prefix,
        expected_version,
        expected_platform,
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
    runtime = {
        "linux-x64": "linux-x64",
        "linux-arm64": "linux-arm64",
        "windows-x64": "win32-x64",
        "windows-arm64": "win32-arm64",
    }.get(expected_platform)
    if runtime is None:
        raise ReleaseError("VSIX artifact has an unsupported platform")
    suffix = ".exe" if expected_platform.startswith("windows-") else ""
    expected_products = {
        f"extension/bin/{runtime}/inex{suffix}": "VSIX inex",
        f"extension/bin/{runtime}/inexd{suffix}": "VSIX inexd",
    }
    product_entries = {
        name
        for name in entries
        if name.startswith("extension/bin/")
        and name.rsplit("/", 1)[-1] in {"inex", "inex.exe", "inexd", "inexd.exe"}
    }
    if product_entries != set(expected_products):
        raise ReleaseError("VSIX must contain exactly one target inex and inexd pair")
    for executable, label in expected_products.items():
        if not suffix and entries[executable][1] & 0o111 == 0:
            raise ReleaseError(f"Linux {label} is not executable in the archive")
        validate_native_binary(entries[executable][0], expected_platform, label)
    validate_license_inventory(
        entries["extension/THIRD_PARTY_LICENSES.json"][0],
        entries,
        "extension/",
        expected_version,
        expected_platform,
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
        entries["Inex/THIRD_PARTY_LICENSES.json"][0],
        entries,
        "Inex/",
        expected_version,
        expected_platform,
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


def validate_release_set_report(report: dict[str, object]) -> None:
    if set(report) != {
        "schemaVersion",
        "reportType",
        "reportScope",
        "releaseVersion",
        "platform",
        "source",
        "artifactCount",
        "artifacts",
        "cargoComponentCount",
        "licenseTextCount",
        "sharedLicenseInventorySha256",
        "sharedCliSha256",
        "sharedSidecarSha256",
        "notCovered",
        "trustAssumptions",
    }:
        raise ReleaseError("release-set audit report has an invalid root schema")
    schema = report.get("schemaVersion")
    if not isinstance(schema, int) or isinstance(schema, bool) or schema != 1:
        raise ReleaseError("release-set audit report has an invalid schema version")
    if (
        report.get("reportType") != "inex-release-set-audit"
        or report.get("reportScope")
        != "artifact-structure-cross-package-consistency-not-release-approval"
        or report.get("notCovered") != list(RELEASE_SET_NOT_COVERED)
        or report.get("trustAssumptions") != list(RELEASE_SET_TRUST_ASSUMPTIONS)
    ):
        raise ReleaseError("release-set audit report has invalid fixed scope metadata")
    version = report.get("releaseVersion")
    platform = report.get("platform")
    if (
        not isinstance(version, str)
        or re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", version)
        is None
        or platform not in PLATFORMS
    ):
        raise ReleaseError("release-set audit report has invalid release identity")
    source = report.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"commit", "dirtySourceTree", "repository"}
        or not isinstance(source.get("dirtySourceTree"), bool)
        or source.get("repository") != "https://github.com/JekYUlll/Inex"
        or not isinstance(source.get("commit"), str)
        or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", source["commit"]) is None
    ):
        raise ReleaseError("release-set audit report has invalid source provenance")
    artifacts = report.get("artifacts")
    artifact_count = report.get("artifactCount")
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != 3
        or not isinstance(artifact_count, int)
        or isinstance(artifact_count, bool)
        or artifact_count != len(artifacts)
    ):
        raise ReleaseError("release-set audit report has an invalid artifact count")
    artifact_names = []
    kinds = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {
            "name",
            "sha256",
            "packageManifestSha256",
        }:
            raise ReleaseError("release-set audit report has an invalid artifact record")
        name = artifact.get("name")
        if not isinstance(name, str):
            raise ReleaseError("release-set audit report has an invalid artifact name")
        kind, artifact_version, artifact_platform = artifact_identity(name)
        if artifact_version != version or artifact_platform != platform or kind in kinds:
            raise ReleaseError("release-set audit report mixes artifact identities")
        kinds.add(kind)
        artifact_names.append(name)
        for field in ("sha256", "packageManifestSha256"):
            value = artifact.get(field)
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise ReleaseError("release-set audit report has an invalid digest")
    if artifact_names != sorted(artifact_names) or kinds != {"rust", "vscode", "sublime"}:
        raise ReleaseError("release-set audit report artifacts are not unique and sorted")
    for field in ("cargoComponentCount", "licenseTextCount"):
        value = report.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ReleaseError("release-set audit report has an invalid dependency count")
    for field in (
        "sharedLicenseInventorySha256",
        "sharedCliSha256",
        "sharedSidecarSha256",
    ):
        value = report.get(field)
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ReleaseError("release-set audit report has an invalid shared digest")


def encode_release_set_report(report: dict[str, object]) -> bytes:
    validate_release_set_report(report)
    return (json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def audit_directory(
    directory: Path, *, require_clean_source: bool = True
) -> dict[str, object]:
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

    artifact_records = []
    kinds = set()
    release_identity: tuple[str, str] | None = None
    release_source: dict[str, object] | None = None
    shared_inventory: bytes | None = None
    shared_cli_digest: str | None = None
    cli_artifact_count = 0
    shared_sidecar_digest: str | None = None
    cargo_component_count: int | None = None
    license_text_count: int | None = None
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
        manifest_data = require_entry(entries, manifest_name)[0]
        manifest = _parse_canonical_release_json(manifest_data, "package manifest")
        source = manifest["source"]
        if not isinstance(source, dict):
            raise ReleaseError("release directory contains invalid source provenance")
        if release_source is None:
            release_source = source
        elif release_source != source:
            raise ReleaseError("release directory mixes package source revisions")
        inventory_name = {
            "rust": f"inex-{version}-{platform}/THIRD_PARTY_LICENSES.json",
            "vscode": "extension/THIRD_PARTY_LICENSES.json",
            "sublime": "Inex/THIRD_PARTY_LICENSES.json",
        }[kind]
        inventory_data = require_entry(entries, inventory_name)[0]
        inventory = _parse_canonical_release_json(
            inventory_data, "third-party license inventory"
        )
        root_prefix = inventory_name.removesuffix("THIRD_PARTY_LICENSES.json")
        current_license_text_count = sum(
            name.startswith(root_prefix + "THIRD_PARTY_LICENSE_TEXTS/") for name in entries
        )
        components = inventory.get("components")
        if not isinstance(components, list):
            raise ReleaseError("release directory contains an invalid license inventory")
        if shared_inventory is None:
            shared_inventory = inventory_data
            cargo_component_count = len(components)
            license_text_count = current_license_text_count
        elif (
            inventory_data != shared_inventory
            or len(components) != cargo_component_count
            or current_license_text_count != license_text_count
        ):
            raise ReleaseError("release artifacts do not share one license inventory")
        sidecar_names = {
            "rust": [
                name
                for name in entries
                if name.endswith(("/bin/inexd", "/bin/inexd.exe"))
            ],
            "vscode": [
                name
                for name in entries
                if name.startswith("extension/bin/")
                and name.endswith(("/inexd", "/inexd.exe"))
            ],
            "sublime": [name for name in entries if name in {"Inex/bin/inexd", "Inex/bin/inexd.exe"}],
        }[kind]
        if len(sidecar_names) != 1:
            raise ReleaseError("release artifact does not contain exactly one sidecar")
        sidecar_digest = sha256_bytes(entries[sidecar_names[0]][0])
        if shared_sidecar_digest is None:
            shared_sidecar_digest = sidecar_digest
        elif sidecar_digest != shared_sidecar_digest:
            raise ReleaseError("release artifacts do not contain one identical sidecar")
        if kind in {"rust", "vscode"}:
            cli_names = (
                [
                    name
                    for name in entries
                    if name.endswith(("/bin/inex", "/bin/inex.exe"))
                ]
                if kind == "rust"
                else [
                    name
                    for name in entries
                    if name.startswith("extension/bin/")
                    and name.rsplit("/", 1)[-1] in {"inex", "inex.exe"}
                ]
            )
            if len(cli_names) != 1:
                raise ReleaseError("release artifact does not contain exactly one CLI")
            cli_digest = sha256_bytes(entries[cli_names[0]][0])
            cli_artifact_count += 1
            if shared_cli_digest is None:
                shared_cli_digest = cli_digest
            elif cli_digest != shared_cli_digest:
                raise ReleaseError("Rust and VSIX artifacts do not contain one identical CLI")
        artifact_records.append(
            {
                "name": path.name,
                "sha256": checksums[path.name],
                "packageManifestSha256": sha256_bytes(manifest_data),
            }
        )
    if kinds != {"rust", "vscode", "sublime"}:
        raise ReleaseError("release directory does not contain all artifact kinds")
    if (
        release_identity is None
        or release_source is None
        or shared_inventory is None
        or shared_cli_digest is None
        or cli_artifact_count != 2
        or shared_sidecar_digest is None
        or cargo_component_count is None
        or license_text_count is None
    ):
        raise ReleaseError("release directory audit did not produce complete evidence")
    version, platform = release_identity
    report: dict[str, object] = {
        "schemaVersion": 1,
        "reportType": "inex-release-set-audit",
        "reportScope": "artifact-structure-cross-package-consistency-not-release-approval",
        "releaseVersion": version,
        "platform": platform,
        "source": release_source,
        "artifactCount": len(artifact_records),
        "artifacts": artifact_records,
        "cargoComponentCount": cargo_component_count,
        "licenseTextCount": license_text_count,
        "sharedLicenseInventorySha256": sha256_bytes(shared_inventory),
        "sharedCliSha256": shared_cli_digest,
        "sharedSidecarSha256": shared_sidecar_digest,
        "notCovered": list(RELEASE_SET_NOT_COVERED),
        "trustAssumptions": list(RELEASE_SET_TRUST_ASSUMPTIONS),
    }
    validate_release_set_report(report)
    return report


def main() -> int:
    arguments = parse_arguments()
    report = audit_directory(
        arguments.directory, require_clean_source=not arguments.allow_dirty_source
    )
    sys.stdout.buffer.write(encode_release_set_report(report))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ReleaseError as error:
        print(f"audit_release_artifacts: {error}", file=sys.stderr)
        raise SystemExit(1) from None
