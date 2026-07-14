from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

import release_common as release_common_module

from audit_release_artifacts import (
    LIBSODIUM_LICENSE_SHA256,
    audit_directory,
    encode_release_set_report,
    read_zip_entries,
    read_zip_entries_from_bytes,
    validate_member_name,
    validate_license_inventory,
    validate_documentation,
    validate_package_manifest,
    validate_release_set_report,
    validate_vsix_metadata,
    validate_vscode,
)
from package_release import (
    add_documentation_entries,
    encode_package_report,
    package_report,
    packaged_root_readme,
    project_version,
    validate_package_report,
)
from release_common import (
    MAX_ARCHIVE_MEMBERS,
    ReleaseError,
    generate_license_materials,
    portable_archive_key,
    safe_archive_name,
    sha256_bytes,
    source_revision,
    validate_native_binary,
    write_reproducible_zip,
)
from smoke_release_artifacts import expected_runtime_info
from verify_release_tag import validate_release_tag


class ReleaseArchiveTests(unittest.TestCase):
    @staticmethod
    def canonical_json(value: object) -> bytes:
        return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
            "utf-8"
        )

    @classmethod
    def locked_license_fixture(
        cls, platform: str = "linux-x64"
    ) -> tuple[bytes, dict[str, tuple[bytes, int]]]:
        repository_root = Path(__file__).resolve().parents[2]
        inventory, materials = generate_license_materials(
            repository_root, "0.1.0", platform
        )
        entries = {f"root/{name}": value for name, value in materials.items()}
        entries["root/THIRD_PARTY_LICENSES.json"] = (inventory, 0o644)
        return inventory, entries

    @staticmethod
    def minimal_pe(machine: int, import_name: str = "KERNEL32.dll") -> bytes:
        data = bytearray(0x600)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3C, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        struct.pack_into("<HHIIIHH", data, 0x84, machine, 2, 0, 0, 0, 240, 0x0022)
        optional = 0x98
        struct.pack_into("<H", data, optional, 0x20B)
        struct.pack_into("<I", data, optional + 16, 0x1000)
        struct.pack_into("<I", data, optional + 20, 0x1000)
        struct.pack_into("<Q", data, optional + 24, 0x140000000)
        struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
        struct.pack_into("<II", data, optional + 56, 0x3000, 0x200)
        struct.pack_into("<H", data, optional + 68, 3)
        struct.pack_into("<I", data, optional + 108, 16)
        struct.pack_into("<II", data, optional + 120, 0x2000, 40)
        sections = optional + 240
        data[sections : sections + 8] = b".text\0\0\0"
        struct.pack_into("<IIII", data, sections + 8, 0x100, 0x1000, 0x200, 0x200)
        struct.pack_into("<I", data, sections + 36, 0x60000020)
        sections += 40
        data[sections : sections + 8] = b".idata\0\0"
        struct.pack_into("<IIII", data, sections + 8, 0x200, 0x2000, 0x200, 0x400)
        struct.pack_into("<I", data, sections + 36, 0xC0000040)
        struct.pack_into("<IIIII", data, 0x400, 0x2050, 0, 0, 0x2030, 0x2060)
        encoded_import = import_name.encode("ascii") + b"\0"
        data[0x430 : 0x430 + len(encoded_import)] = encoded_import
        return bytes(data)

    @staticmethod
    def minimal_vsix_metadata(
        *, version: str = "0.1.0", target: str = "linux-x64", identity: str = "inex-vscode"
    ) -> dict[str, tuple[bytes, int]]:
        manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="{identity}" Version="{version}" Publisher="horeb" TargetPlatform="{target}"/>
    <DisplayName>Inex</DisplayName>
    <Description>Inex test package</Description>
    <Tags></Tags>
    <Categories>Other</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Properties><Property Id="Microsoft.VisualStudio.Code.Engine" Value="^1.125.0"/></Properties>
    <License>extension/LICENSE.txt</License>
  </Metadata>
  <Installation><InstallationTarget Id="Microsoft.VisualStudio.Code"/></Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/readme.md" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.License" Path="extension/LICENSE.txt" Addressable="true"/>
  </Assets>
</PackageManifest>'''.encode()
        content_types = b'''<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension=".js" ContentType="application/javascript"/>
  <Default Extension=".json" ContentType="application/json"/>
  <Default Extension=".md" ContentType="text/markdown"/>
  <Default Extension=".svg" ContentType="image/svg+xml"/>
  <Default Extension=".txt" ContentType="text/plain"/>
  <Default Extension=".vsixmanifest" ContentType="text/xml"/>
</Types>'''
        package = json.dumps(
            {
                "name": "inex-vscode",
                "publisher": "horeb",
                "version": version,
                "main": "./dist/extension.js",
                "engines": {"vscode": "^1.125.0"},
            }
        ).encode()
        return {
            "extension.vsixmanifest": (manifest, 0o644),
            "[Content_Types].xml": (content_types, 0o644),
            "extension/package.json": (package, 0o644),
            "extension/readme.md": (b"readme", 0o644),
            "extension/LICENSE.txt": (b"license", 0o644),
        }

    @staticmethod
    def minimal_elf(machine: int, interpreter: str) -> bytes:
        encoded = interpreter.encode("utf-8") + b"\0"
        program_offset = 64
        interpreter_offset = program_offset + 56
        data = bytearray(interpreter_offset + len(encoded))
        data[:16] = b"\x7fELF\x02\x01\x01" + b"\0" * 9
        struct.pack_into(
            "<HHIQQQIHHHHHH",
            data,
            16,
            3,
            machine,
            1,
            0,
            program_offset,
            0,
            0,
            64,
            56,
            1,
            0,
            0,
            0,
        )
        struct.pack_into(
            "<IIQQQQQQ",
            data,
            program_offset,
            3,
            4,
            interpreter_offset,
            0,
            0,
            len(encoded),
            len(encoded),
            1,
        )
        data[interpreter_offset:] = encoded
        return bytes(data)

    def test_reproducible_zip_is_byte_identical(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.zip"
            second = Path(directory) / "second.zip"
            entries = {
                "root/bin/inexd": (b"binary", 0o755),
                "root/LICENSE": (b"license", 0o644),
            }
            write_reproducible_zip(first, entries)
            write_reproducible_zip(second, dict(reversed(list(entries.items()))))
            self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_archive_path_traversal_is_rejected(self) -> None:
        for name in (
            "../secret",
            "/absolute",
            "C:/absolute",
            "root//secret",
            "root/../../secret",
            "root\\secret",
        ):
            with self.subTest(name=name), self.assertRaises(ReleaseError):
                safe_archive_name(name)

    def test_test_and_dependency_trees_are_rejected(self) -> None:
        for name in (
            "extension/node_modules/module.js",
            "extension/test/runner.js",
            "extension/fixtures/plain.md",
            "extension/dist/extension.js.map",
        ):
            with self.subTest(name=name), self.assertRaises(ReleaseError):
                validate_member_name(name)

    def test_symbolic_link_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                information = zipfile.ZipInfo("root/link")
                information.create_system = 3
                information.external_attr = (stat.S_IFLNK | 0o777) << 16
                archive.writestr(information, "target")
            with self.assertRaisesRegex(ReleaseError, "symbolic link"):
                read_zip_entries(archive_path)

    def test_in_memory_archive_parser_matches_path_parser(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "safe.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                information = zipfile.ZipInfo("root/file")
                information.create_system = 3
                information.external_attr = (stat.S_IFREG | 0o600) << 16
                archive.writestr(information, b"payload")
            self.assertEqual(
                read_zip_entries_from_bytes(archive_path.read_bytes(), "captured.zip"),
                read_zip_entries(archive_path),
            )

    def test_non_regular_zip_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                information = zipfile.ZipInfo("root/pipe")
                information.create_system = 3
                information.external_attr = (stat.S_IFIFO | 0o600) << 16
                archive.writestr(information, b"")
            with self.assertRaisesRegex(ReleaseError, "non-regular"):
                read_zip_entries(archive_path)

    def test_portable_path_collisions_are_rejected(self) -> None:
        for names in (("root/Pipe", "root/pipe"), ("root/file", "root/file/child")):
            with self.subTest(names=names), tempfile.TemporaryDirectory() as directory:
                archive_path = Path(directory) / "bad.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    for name in names:
                        information = zipfile.ZipInfo(name)
                        information.create_system = 3
                        information.external_attr = (stat.S_IFREG | 0o600) << 16
                        archive.writestr(information, b"x")
                with self.assertRaisesRegex(ReleaseError, "collide"):
                    read_zip_entries(archive_path)
        with tempfile.TemporaryDirectory() as directory, self.assertRaisesRegex(
            ReleaseError, "collide"
        ):
            write_reproducible_zip(
                Path(directory) / "bad.zip",
                {"root/File": (b"a", 0o644), "root/file": (b"b", 0o644)},
            )
        for name in (
            "root/a<b",
            "root/a>b",
            'root/a"b',
            "root/a|b",
            "root/a?b",
            "root/a*b",
            "root/COM¹.txt",
            "root/com²",
            "root/LPT³.log",
            "root/CONIN$",
            "root/conout$.txt",
        ):
            with self.subTest(name=name), self.assertRaises(ReleaseError):
                portable_archive_key(name)

    def test_privileged_zip_permission_bits_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                information = zipfile.ZipInfo("root/executable")
                information.create_system = 3
                information.external_attr = (stat.S_IFREG | 0o4755) << 16
                archive.writestr(information, b"binary")
            with self.assertRaisesRegex(ReleaseError, "privileged permission"):
                read_zip_entries(archive_path)

    def test_zip_member_count_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                for index in range(MAX_ARCHIVE_MEMBERS + 1):
                    archive.writestr(f"root/{index}", b"")
            with self.assertRaisesRegex(ReleaseError, "member count"):
                read_zip_entries(archive_path)

    def test_residue_marker_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive_path = Path(directory) / "bad.zip"
            write_reproducible_zip(
                archive_path,
                {"root/file.txt": (b"prefix inex-residue:secret suffix", 0o644)},
            )
            with self.assertRaisesRegex(ReleaseError, "canary marker"):
                read_zip_entries(archive_path)

    def test_dirty_source_manifest_is_rejected_by_default(self) -> None:
        content = b"payload"
        manifest = {
            "schemaVersion": 1,
            "package": "rust-binaries",
            "platform": "linux-x64",
            "version": "0.1.0",
            "installFormat": "portable ZIP with bin/inex and bin/inexd",
            "source": {
                "commit": "1" * 40,
                "dirtySourceTree": True,
                "repository": "https://github.com/JekYUlll/Inex",
            },
            "files": [
                {
                    "path": "root/file",
                    "sha256": sha256_bytes(content),
                    "size": len(content),
                }
            ],
        }
        encoded = (json.dumps(manifest) + "\n").encode("utf-8")
        entries = {
            "root/file": (content, 0o644),
            "root/PACKAGE-MANIFEST.json": (encoded, 0o644),
        }
        with self.assertRaisesRegex(ReleaseError, "dirty source tree"):
            validate_package_manifest(
                encoded,
                "rust",
                entries,
                manifest_name="root/PACKAGE-MANIFEST.json",
                require_clean_source=True,
                expected_platform="linux-x64",
                expected_version="0.1.0",
            )
        validate_package_manifest(
            encoded,
            "rust",
            entries,
            manifest_name="root/PACKAGE-MANIFEST.json",
            require_clean_source=False,
            expected_platform="linux-x64",
            expected_version="0.1.0",
        )
        duplicate = encoded.decode("utf-8").replace(
            '"installFormat":',
            '"installFormat": "wrong", "installFormat":',
            1,
        ).encode("utf-8")
        with self.assertRaisesRegex(ReleaseError, "repeats a JSON key"):
            validate_package_manifest(
                duplicate,
                "rust",
                entries,
                manifest_name="root/PACKAGE-MANIFEST.json",
                require_clean_source=True,
                expected_platform="linux-x64",
                expected_version="0.1.0",
            )
        with self.assertRaisesRegex(ReleaseError, "strict UTF-8 JSON"):
            validate_package_manifest(
                encoded.decode("utf-8").encode("utf-16"),
                "rust",
                entries,
                manifest_name="root/PACKAGE-MANIFEST.json",
                require_clean_source=True,
                expected_platform="linux-x64",
                expected_version="0.1.0",
            )
        for invalid_schema in (True, 1.0):
            manifest["schemaVersion"] = invalid_schema
            invalid = (json.dumps(manifest) + "\n").encode("utf-8")
            with self.assertRaisesRegex(ReleaseError, "invalid schema"):
                validate_package_manifest(
                    invalid,
                    "rust",
                    entries,
                    manifest_name="root/PACKAGE-MANIFEST.json",
                    require_clean_source=True,
                    expected_platform="linux-x64",
                    expected_version="0.1.0",
                )
        manifest["schemaVersion"] = 1
        manifest["installFormat"] = "wrong"
        encoded = (json.dumps(manifest) + "\n").encode("utf-8")
        entries["root/PACKAGE-MANIFEST.json"] = (encoded, 0o644)
        with self.assertRaisesRegex(ReleaseError, "install format"):
            validate_package_manifest(
                encoded,
                "rust",
                entries,
                manifest_name="root/PACKAGE-MANIFEST.json",
                require_clean_source=True,
                expected_platform="linux-x64",
                expected_version="0.1.0",
            )
        manifest["installFormat"] = "portable ZIP with bin/inex and bin/inexd"
        manifest["source"]["unexpected"] = True
        encoded = (json.dumps(manifest) + "\n").encode("utf-8")
        entries["root/PACKAGE-MANIFEST.json"] = (encoded, 0o644)
        with self.assertRaisesRegex(ReleaseError, "source revision"):
            validate_package_manifest(
                encoded,
                "rust",
                entries,
                manifest_name="root/PACKAGE-MANIFEST.json",
                require_clean_source=True,
                expected_platform="linux-x64",
                expected_version="0.1.0",
            )
        manifest["source"].pop("unexpected")
        manifest["source"]["commit"] = "2" * 64
        manifest["source"]["dirtySourceTree"] = False
        encoded = (json.dumps(manifest) + "\n").encode("utf-8")
        entries["root/PACKAGE-MANIFEST.json"] = (encoded, 0o644)
        validate_package_manifest(
            encoded,
            "rust",
            entries,
            manifest_name="root/PACKAGE-MANIFEST.json",
            require_clean_source=True,
            expected_platform="linux-x64",
            expected_version="0.1.0",
        )

    def test_manifest_platform_mismatch_is_rejected(self) -> None:
        content = b"payload"
        manifest = {
            "schemaVersion": 1,
            "package": "rust-binaries",
            "platform": "linux-arm64",
            "version": "0.1.0",
            "installFormat": "portable ZIP with bin/inex and bin/inexd",
            "source": {
                "commit": "1" * 40,
                "dirtySourceTree": False,
                "repository": "https://github.com/JekYUlll/Inex",
            },
            "files": [
                {
                    "path": "root/file",
                    "sha256": sha256_bytes(content),
                    "size": len(content),
                }
            ],
        }
        encoded = (json.dumps(manifest) + "\n").encode("utf-8")
        entries = {
            "root/file": (content, 0o644),
            "root/PACKAGE-MANIFEST.json": (encoded, 0o644),
        }
        with self.assertRaisesRegex(ReleaseError, "platform"):
            validate_package_manifest(
                encoded,
                "rust",
                entries,
                manifest_name="root/PACKAGE-MANIFEST.json",
                require_clean_source=True,
                expected_platform="linux-x64",
                expected_version="0.1.0",
            )

    def test_locked_license_inventory_is_target_bound_complete_and_reviewed(self) -> None:
        inventory, entries = self.locked_license_fixture()
        validate_license_inventory(
            inventory, entries, "root/", "0.1.0", "linux-x64"
        )
        decoded = json.loads(inventory)
        self.assertEqual(decoded["target"]["rustTriple"], "x86_64-unknown-linux-gnu")
        self.assertEqual(len(decoded["components"]), 78)
        self.assertEqual(
            len(
                [
                    name
                    for name in entries
                    if name.startswith("root/THIRD_PARTY_LICENSE_TEXTS/")
                ]
            ),
            149,
        )
        sodium_path = "root/THIRD_PARTY_LICENSE_TEXTS/native/libsodium-1.0.22/LICENSE"
        self.assertEqual(
            release_common_module.sha256_bytes(entries[sodium_path][0]),
            LIBSODIUM_LICENSE_SHA256,
        )

        windows_inventory, _ = self.locked_license_fixture("windows-x64")
        windows = json.loads(windows_inventory)
        linux_components = {(item["name"], item["version"]) for item in decoded["components"]}
        windows_components = {(item["name"], item["version"]) for item in windows["components"]}
        self.assertEqual(windows["target"]["rustTriple"], "x86_64-pc-windows-msvc")
        self.assertNotEqual(linux_components, windows_components)
        self.assertIn(("rustix", "1.1.4"), linux_components - windows_components)
        self.assertIn(("windows-targets", "0.52.6"), windows_components - linux_components)

    def test_license_graph_rejects_non_workspace_path_dependencies(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        first_party = [
            {
                "id": name,
                "name": name,
                "source": None,
                "manifest_path": str(repository_root / relative),
            }
            for name, relative in release_common_module.EXPECTED_WORKSPACE_PACKAGES
        ]
        metadata = {
            "workspace_root": str(repository_root),
            "workspace_members": [package["id"] for package in first_party],
            "resolve": {
                "nodes": [
                    {
                        "id": "inex-cli",
                        "deps": [
                            {
                                "pkg": "local-path",
                                "dep_kinds": [{"kind": None}],
                            }
                        ],
                    },
                    {"id": "local-path", "deps": []},
                    *[
                        {"id": package["id"], "deps": []}
                        for package in first_party
                        if package["id"] != "inex-cli"
                    ],
                ]
            },
            "packages": [
                *first_party,
                {
                    "id": "local-path",
                    "name": "local-path",
                    "source": None,
                    "manifest_path": str(repository_root / "vendor/local-path/Cargo.toml"),
                },
            ],
        }
        with self.assertRaisesRegex(ReleaseError, "non-workspace path dependency"):
            release_common_module._native_resolved_packages(metadata, repository_root)

        auto_member = json.loads(json.dumps(metadata))
        auto_member["workspace_members"].append("local-path")
        with self.assertRaisesRegex(ReleaseError, "workspace member set"):
            release_common_module._native_resolved_packages(auto_member, repository_root)

    def test_license_inventory_rejects_noncanonical_or_unreviewed_metadata(self) -> None:
        inventory, entries = self.locked_license_fixture()
        baseline = json.loads(inventory)
        mutations = []

        unknown_root = json.loads(inventory)
        unknown_root["unexpected"] = True
        mutations.append(("root schema", unknown_root))
        bool_schema = json.loads(inventory)
        bool_schema["schemaVersion"] = True
        mutations.append(("schema version", bool_schema))
        missing_checksum = json.loads(inventory)
        missing_checksum["components"][0].pop("checksum")
        mutations.append(("Cargo component", missing_checksum))
        fake_source = json.loads(inventory)
        fake_source["components"][0]["source"] = "git+https://example.invalid/repository"
        mutations.append(("license policy", fake_source))
        unknown_license = json.loads(inventory)
        unknown_license["components"][0]["license"] = "Proprietary"
        mutations.append(("license policy", unknown_license))
        repeated_component = json.loads(inventory)
        repeated_component["components"].append(
            dict(repeated_component["components"][0])
        )
        mutations.append(("repeats a license path", repeated_component))
        reversed_components = json.loads(inventory)
        reversed_components["components"].reverse()
        mutations.append(("unique and sorted", reversed_components))
        repeated_path = json.loads(inventory)
        repeated_path["components"][0]["licenseFiles"].append(
            dict(repeated_path["components"][0]["licenseFiles"][0])
        )
        mutations.append(("paths", repeated_path))
        wrong_target = json.loads(inventory)
        wrong_target["target"]["platform"] = "windows-x64"
        mutations.append(("target graph", wrong_target))

        for message, mutation in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(ReleaseError, message):
                validate_license_inventory(
                    self.canonical_json(mutation),
                    entries,
                    "root/",
                    "0.1.0",
                    "linux-x64",
                )

        text = inventory.decode("utf-8")
        duplicate = text.replace(
            '  "schemaVersion": 1,',
            '  "schemaVersion": 1,\n  "schemaVersion": 1,',
            1,
        ).encode("utf-8")
        with self.assertRaisesRegex(ReleaseError, "repeats a JSON key"):
            validate_license_inventory(
                duplicate, entries, "root/", "0.1.0", "linux-x64"
            )
        with self.assertRaisesRegex(ReleaseError, "strict UTF-8"):
            validate_license_inventory(
                json.dumps(baseline).encode("utf-16"),
                entries,
                "root/",
                "0.1.0",
                "linux-x64",
            )

    def test_license_inventory_rejects_policy_and_license_text_tampering(self) -> None:
        inventory, entries = self.locked_license_fixture()
        policy_name = "root/DEPENDENCY_LICENSE_POLICY.json"
        policy = json.loads(entries[policy_name][0])
        policy["acceptedCargoLicenseExpressions"].append("Proprietary")
        tampered_policy_entries = dict(entries)
        tampered_policy_entries[policy_name] = (self.canonical_json(policy), 0o644)
        with self.assertRaises(ReleaseError):
            validate_license_inventory(
                inventory,
                tampered_policy_entries,
                "root/",
                "0.1.0",
                "linux-x64",
            )

        repository_root = Path(__file__).resolve().parents[2]
        policy_path = repository_root / "packaging/dependency-license-policy.json"
        wrong_sodium = json.loads(policy_path.read_bytes())
        wrong_sodium["bundledNativeLibraries"][0]["licenseSha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            staged_root = Path(directory)
            (staged_root / "packaging").mkdir()
            (staged_root / "packaging" / policy_path.name).write_bytes(
                self.canonical_json(wrong_sodium)
            )
            with self.assertRaisesRegex(ReleaseError, "libsodium metadata"):
                release_common_module._load_dependency_license_policy(staged_root)

        sodium_name = "root/THIRD_PARTY_LICENSE_TEXTS/native/libsodium-1.0.22/LICENSE"
        tampered_license_entries = dict(entries)
        tampered_license_entries[sodium_name] = (b"not the reviewed ISC text", 0o644)
        with self.assertRaisesRegex(ReleaseError, "wrong digest"):
            validate_license_inventory(
                inventory,
                tampered_license_entries,
                "root/",
                "0.1.0",
                "linux-x64",
            )

        cargo_record = json.loads(inventory)["components"][0]["licenseFiles"][0]
        cargo_name = "root/" + cargo_record["path"]
        tampered_cargo_entries = dict(entries)
        tampered_cargo_entries[cargo_name] = (b"not the collected Cargo license", 0o644)
        with self.assertRaisesRegex(ReleaseError, "Cargo license text has the wrong digest"):
            validate_license_inventory(
                inventory,
                tampered_cargo_entries,
                "root/",
                "0.1.0",
                "linux-x64",
            )

    def test_release_set_requires_shared_inventory_cli_and_sidecar(self) -> None:
        version = "0.1.0"
        platform = "linux-x64"
        source = {
            "commit": "1" * 40,
            "dirtySourceTree": False,
            "repository": "https://github.com/JekYUlll/Inex",
        }
        manifest = self.canonical_json({"source": source})
        inventory = self.canonical_json({"components": [{"name": "component"}]})
        cli = b"one-identical-cli"
        sidecar = b"one-identical-sidecar"
        artifact_names = {
            "rust": f"inex-rust-{version}-{platform}.zip",
            "vscode": f"inex-vscode-{version}-{platform}.vsix",
            "sublime": f"inex-sublime-{version}-{platform}.zip",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for kind, name in artifact_names.items():
                (root / name).write_bytes(f"{kind}-archive".encode("ascii"))
            sums = "".join(
                f"{release_common_module.sha256_file(root / name)}  {name}\n"
                for name in sorted(artifact_names.values())
            )
            (root / "SHA256SUMS").write_text(sums, encoding="ascii")
            rust_prefix = f"inex-{version}-{platform}/"
            entries_by_name = {
                artifact_names["rust"]: {
                    rust_prefix + "PACKAGE-MANIFEST.json": (manifest, 0o644),
                    rust_prefix + "THIRD_PARTY_LICENSES.json": (inventory, 0o644),
                    rust_prefix + "bin/inex": (cli, 0o755),
                    rust_prefix + "bin/inexd": (sidecar, 0o755),
                    rust_prefix + "THIRD_PARTY_LICENSE_TEXTS/license": (b"license", 0o644),
                },
                artifact_names["vscode"]: {
                    "extension/PACKAGE-MANIFEST.json": (manifest, 0o644),
                    "extension/THIRD_PARTY_LICENSES.json": (inventory, 0o644),
                    "extension/bin/linux-x64/inex": (cli, 0o755),
                    "extension/bin/linux-x64/inexd": (sidecar, 0o755),
                    "extension/THIRD_PARTY_LICENSE_TEXTS/license": (b"license", 0o644),
                },
                artifact_names["sublime"]: {
                    "Inex/PACKAGE-MANIFEST.json": (manifest, 0o644),
                    "Inex/THIRD_PARTY_LICENSES.json": (inventory, 0o644),
                    "Inex/bin/inexd": (sidecar, 0o755),
                    "Inex/THIRD_PARTY_LICENSE_TEXTS/license": (b"license", 0o644),
                },
            }

            def run_audit() -> dict[str, object]:
                with (
                    mock.patch("audit_release_artifacts.validate_rust"),
                    mock.patch("audit_release_artifacts.validate_vscode"),
                    mock.patch("audit_release_artifacts.validate_sublime"),
                    mock.patch(
                        "audit_release_artifacts.read_zip_entries",
                        side_effect=lambda path: entries_by_name[path.name],
                    ),
                ):
                    return audit_directory(root)

            report = run_audit()
            validate_release_set_report(report)
            encoded = encode_release_set_report(report)
            self.assertEqual(json.loads(encoded), report)
            self.assertEqual(report["artifactCount"], 3)
            self.assertEqual(report["cargoComponentCount"], 1)
            self.assertEqual(report["licenseTextCount"], 1)
            self.assertEqual(report["sharedCliSha256"], sha256_bytes(cli))

            vscode_inventory_name = "extension/THIRD_PARTY_LICENSES.json"
            original_inventory = entries_by_name[artifact_names["vscode"]][
                vscode_inventory_name
            ]
            entries_by_name[artifact_names["vscode"]][vscode_inventory_name] = (
                self.canonical_json({"components": [{"name": "different"}]}),
                0o644,
            )
            with self.assertRaisesRegex(ReleaseError, "one license inventory"):
                run_audit()
            entries_by_name[artifact_names["vscode"]][
                vscode_inventory_name
            ] = original_inventory

            sidecar_name = "extension/bin/linux-x64/inexd"
            original_sidecar = entries_by_name[artifact_names["vscode"]][sidecar_name]
            entries_by_name[artifact_names["vscode"]][sidecar_name] = (
                b"different-sidecar",
                0o755,
            )
            with self.assertRaisesRegex(ReleaseError, "identical sidecar"):
                run_audit()
            entries_by_name[artifact_names["vscode"]][sidecar_name] = original_sidecar

            cli_name = "extension/bin/linux-x64/inex"
            original_cli = entries_by_name[artifact_names["vscode"]][cli_name]
            entries_by_name[artifact_names["vscode"]][cli_name] = (
                b"different-cli",
                0o755,
            )
            with self.assertRaisesRegex(ReleaseError, "identical CLI"):
                run_audit()
            entries_by_name[artifact_names["vscode"]][cli_name] = original_cli

            invalid_report = dict(report)
            invalid_report["schemaVersion"] = True
            with self.assertRaisesRegex(ReleaseError, "schema version"):
                validate_release_set_report(invalid_report)
            invalid_report = dict(report)
            invalid_report["unexpected"] = True
            with self.assertRaisesRegex(ReleaseError, "root schema"):
                validate_release_set_report(invalid_report)
            invalid_report = dict(report)
            invalid_report["notCovered"] = []
            with self.assertRaisesRegex(ReleaseError, "scope metadata"):
                validate_release_set_report(invalid_report)

            report["notCovered"].append("caller-mutation")
            with self.assertRaisesRegex(ReleaseError, "scope metadata"):
                validate_release_set_report(report)
            self.assertNotIn("caller-mutation", run_audit()["notCovered"])

    def test_package_report_is_canonical_exact_and_non_approving(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifacts = []
            for kind, extension in (("rust", "zip"), ("sublime", "zip"), ("vscode", "vsix")):
                path = root / f"inex-{kind}-0.1.0-linux-x64.{extension}"
                path.write_bytes(kind.encode("ascii"))
                artifacts.append(path)
            checksum = root / "SHA256SUMS"
            checksum.write_text(
                "".join(
                    f"{release_common_module.sha256_file(path)}  {path.name}\n"
                    for path in sorted(artifacts, key=lambda path: path.name)
                ),
                encoding="ascii",
            )
            report = package_report("linux-x64", "0.1.0", artifacts, checksum)
            validate_package_report(report)
            self.assertEqual(json.loads(encode_package_report(report)), report)
            self.assertIn("independent-legal-review", report["notCovered"])
            self.assertEqual(
                report["trustAssumptions"],
                ["package-inputs-and-toolchain-are-trusted-and-stable"],
            )

            for field, value, message in (
                ("schemaVersion", True, "schema version"),
                ("artifactCount", 2, "artifact count"),
                ("notCovered", [], "fixed release metadata"),
            ):
                invalid = dict(report)
                invalid[field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ReleaseError, message):
                    validate_package_report(invalid)

            report["notCovered"].append("caller-mutation")
            with self.assertRaisesRegex(ReleaseError, "fixed release metadata"):
                validate_package_report(report)
            fresh = package_report("linux-x64", "0.1.0", artifacts, checksum)
            self.assertNotIn("caller-mutation", fresh["notCovered"])

            checksum.write_text("not valid checksums\n", encoding="ascii")
            with self.assertRaisesRegex(ReleaseError, "exactly bind"):
                package_report("linux-x64", "0.1.0", artifacts, checksum)

    def test_packaged_root_readme_links_the_bundled_license_policy(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        readme = packaged_root_readme(repository_root).decode("utf-8")
        self.assertIn(
            "[`dependency-license-policy.json`](DEPENDENCY_LICENSE_POLICY.json)",
            readme,
        )
        self.assertNotIn("(packaging/dependency-license-policy.json)", readme)

    def test_packaged_root_documentation_links_are_closed(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        entries = {
            "root/README.md": (packaged_root_readme(repository_root), 0o644),
            "root/SECURITY.md": (
                (repository_root / "SECURITY.md").read_bytes(),
                0o644,
            ),
            "root/LICENSE": ((repository_root / "LICENSE").read_bytes(), 0o644),
            "root/DEPENDENCY_LICENSE_POLICY.json": (
                (repository_root / "packaging/dependency-license-policy.json").read_bytes(),
                0o644,
            ),
        }
        add_documentation_entries(entries, repository_root, "root/")
        validate_documentation(entries, "root/")

    def test_package_smoke_binds_release_target_and_profile(self) -> None:
        report = expected_runtime_info("inex", "0.1.0", "windows-x64")
        self.assertIn("rust-target: x86_64-pc-windows-msvc", report)
        self.assertIn("rust-debug-assertions: false", report)
        self.assertNotIn("x86_64-pc-windows-gnu", report)

    def test_windows_pe_architecture_and_dynamic_sodium_are_checked(self) -> None:
        validate_native_binary(self.minimal_pe(0x8664), "windows-x64", "test")
        validate_native_binary(self.minimal_pe(0xAA64), "windows-arm64", "test")
        with self.assertRaisesRegex(ReleaseError, "does not match"):
            validate_native_binary(self.minimal_pe(0xAA64), "windows-x64", "test")
        with self.assertRaisesRegex(ReleaseError, "dynamically links libsodium"):
            validate_native_binary(
                self.minimal_pe(0x8664, "LIBSODIUM.DLL"), "windows-x64", "test"
            )

    def test_malformed_pe32_plus_structures_are_rejected(self) -> None:
        mutations = []
        dll = bytearray(self.minimal_pe(0x8664))
        struct.pack_into("<H", dll, 0x96, 0x2022)
        mutations.append(("non-DLL", bytes(dll), "non-DLL"))
        pe32 = bytearray(self.minimal_pe(0x8664))
        struct.pack_into("<H", pe32, 0x98, 0x10B)
        mutations.append(("PE32", bytes(pe32), "PE32"))
        sections = bytearray(self.minimal_pe(0x8664))
        struct.pack_into("<H", sections, 0x86, 0)
        mutations.append(("sections", bytes(sections), "section count"))
        imports = bytearray(self.minimal_pe(0x8664))
        struct.pack_into("<II", imports, 0x98 + 120, 0x2FF0, 40)
        mutations.append(("imports", bytes(imports), "import table"))
        for label, data, message in mutations:
            with self.subTest(label=label), self.assertRaisesRegex(ReleaseError, message):
                validate_native_binary(data, "windows-x64", "test")

    def test_linux_elf_interpreter_and_architecture_are_checked(self) -> None:
        validate_native_binary(
            self.minimal_elf(0x3E, "/lib64/ld-linux-x86-64.so.2"),
            "linux-x64",
            "test",
        )
        validate_native_binary(
            self.minimal_elf(0xB7, "/lib/ld-linux-aarch64.so.1"),
            "linux-arm64",
            "test",
        )
        with self.assertRaisesRegex(ReleaseError, "non-portable ELF interpreter"):
            validate_native_binary(
                self.minimal_elf(0x3E, "/home/builder/lib/ld-linux-x86-64.so.2"),
                "linux-x64",
                "test",
            )

    def test_vsix_extra_root_member_is_rejected_first(self) -> None:
        entries = {
            "[Content_Types].xml": (b"types", 0o644),
            "extension.vsixmanifest": (b"manifest", 0o644),
            "unexpected.txt": (b"unexpected", 0o644),
        }
        with self.assertRaisesRegex(ReleaseError, "root members"):
            validate_vscode(
                entries,
                require_clean_source=True,
                expected_platform="linux-x64",
                expected_version="0.1.0",
            )

    def test_vsix_requires_one_platform_native_executable_pair(self) -> None:
        cli_name = "extension/bin/linux-x64/inex"
        daemon_name = "extension/bin/linux-x64/inexd"
        native = self.minimal_elf(0x3E, "/lib64/ld-linux-x86-64.so.2")
        entries = self.minimal_vsix_metadata()
        entries.update(
            {
                "extension/PACKAGE-MANIFEST.json": (b"manifest", 0o644),
                "extension/THIRD_PARTY_LICENSES.json": (b"licenses", 0o644),
                "extension/dist/extension.js": (b"extension", 0o644),
                "extension/resources/inex.svg": (b"svg", 0o644),
                cli_name: (native, 0o755),
                daemon_name: (native, 0o755),
            }
        )

        def validate(candidate: dict[str, tuple[bytes, int]]) -> None:
            with (
                mock.patch("audit_release_artifacts.validate_license_inventory"),
                mock.patch("audit_release_artifacts.validate_documentation"),
                mock.patch("audit_release_artifacts.validate_package_manifest"),
            ):
                validate_vscode(
                    candidate,
                    require_clean_source=True,
                    expected_platform="linux-x64",
                    expected_version="0.1.0",
                )

        validate(entries)
        for label, replacement in (
            ("missing CLI", {cli_name: None}),
            (
                "wrong runtime",
                {
                    cli_name: None,
                    "extension/bin/linux-arm64/inex": (native, 0o755),
                },
            ),
            (
                "extra CLI",
                {"extension/bin/linux-arm64/inex": (native, 0o755)},
            ),
            ("CLI mode", {cli_name: (native, 0o644)}),
            ("daemon mode", {daemon_name: (native, 0o644)}),
        ):
            candidate = dict(entries)
            for name, value in replacement.items():
                if value is None:
                    candidate.pop(name)
                else:
                    candidate[name] = value
            with self.subTest(label=label), self.assertRaises(ReleaseError):
                validate(candidate)

        wrong_architecture = self.minimal_elf(
            0xB7, "/lib/ld-linux-aarch64.so.1"
        )
        for name in (cli_name, daemon_name):
            candidate = dict(entries)
            candidate[name] = (wrong_architecture, 0o755)
            with self.subTest(native=name), self.assertRaisesRegex(
                ReleaseError, "does not match"
            ):
                validate(candidate)

    def test_vsix_identity_and_content_types_are_strictly_validated(self) -> None:
        entries = self.minimal_vsix_metadata()
        validate_vsix_metadata(
            entries, expected_platform="linux-x64", expected_version="0.1.0"
        )
        for label, replacement in (
            ("identity", self.minimal_vsix_metadata(identity="other")),
            ("target", self.minimal_vsix_metadata(target="linux-arm64")),
            ("version", self.minimal_vsix_metadata(version="9.9.9")),
        ):
            with self.subTest(label=label), self.assertRaises(ReleaseError):
                validate_vsix_metadata(
                    replacement,
                    expected_platform="linux-x64",
                    expected_version="0.1.0",
                )
        malformed = dict(entries)
        malformed["extension.vsixmanifest"] = (b"<not-a-vsix-manifest/>", 0o644)
        with self.assertRaisesRegex(ReleaseError, "PackageManifest"):
            validate_vsix_metadata(
                malformed, expected_platform="linux-x64", expected_version="0.1.0"
            )
        unsafe_xml = dict(entries)
        unsafe_xml["extension.vsixmanifest"] = (
            b'<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><x>&y;</x>',
            0o644,
        )
        with self.assertRaisesRegex(ReleaseError, "forbidden XML"):
            validate_vsix_metadata(
                unsafe_xml, expected_platform="linux-x64", expected_version="0.1.0"
            )
        bad_types = dict(entries)
        bad_types["[Content_Types].xml"] = (
            entries["[Content_Types].xml"][0].replace(b"text/xml", b"text/plain"),
            0o644,
        )
        with self.assertRaisesRegex(ReleaseError, "required mapping"):
            validate_vsix_metadata(
                bad_types, expected_platform="linux-x64", expected_version="0.1.0"
            )
        bad_package = dict(entries)
        package = json.loads(entries["extension/package.json"][0])
        package["publisher"] = "attacker"
        bad_package["extension/package.json"] = (json.dumps(package).encode(), 0o644)
        with self.assertRaisesRegex(ReleaseError, "package.json identity"):
            validate_vsix_metadata(
                bad_package, expected_platform="linux-x64", expected_version="0.1.0"
            )

    def test_project_version_uses_workspace_package_toml(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "editors/vscode").mkdir(parents=True)
            (root / "editors/vscode/package.json").write_text(
                '{"version":"0.1.0"}', encoding="utf-8"
            )
            (root / "Cargo.toml").write_text(
                '[package]\nversion = "0.1.0"\n[workspace.package]\nversion = "0.2.0"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ReleaseError, "versions differ"):
                project_version(root)
            (root / "Cargo.toml").write_text(
                '[package]\nversion = "9.9.9"\n[workspace.package]\nversion = "0.1.0"\n',
                encoding="utf-8",
            )
            self.assertEqual(project_version(root), "0.1.0")

    def test_release_tag_must_exactly_match_version(self) -> None:
        validate_release_tag("v0.1.0", "0.1.0")
        for tag in ("v0.1", "v0.1.1", "v01.1.0", "release-0.1.0"):
            with self.subTest(tag=tag), self.assertRaises(ReleaseError):
                validate_release_tag(tag, "0.1.0")

    def test_source_revision_requires_canonical_origin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(
                ["git", "config", "user.name", "Inex release test"], cwd=root, check=True
            )
            subprocess.run(
                ["git", "config", "user.email", "release-test@example.invalid"],
                cwd=root,
                check=True,
            )
            (root / "tracked").write_text("content\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "fixture"], cwd=root, check=True
            )
            head_reference = subprocess.run(
                ["git", "symbolic-ref", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
                encoding="ascii",
            ).stdout.strip()
            subprocess.run(
                ["git", "remote", "add", "origin", "https://github.com/fork/Inex.git"],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "canonical"):
                source_revision(root)
            subprocess.run(
                [
                    "git",
                    "remote",
                    "set-url",
                    "origin",
                    "git@github.com:JekYUlll/Inex.git",
                ],
                cwd=root,
                check=True,
            )
            revision = source_revision(root)
            self.assertEqual(
                revision["repository"], "https://github.com/JekYUlll/Inex"
            )
            self.assertFalse(revision["dirtySourceTree"])
            subprocess.run(
                ["git", "config", "gc.auto", "0"], cwd=root, check=True
            )
            subprocess.run(
                ["git", "config", "core.autocrlf", "false"], cwd=root, check=True
            )
            self.assertFalse(source_revision(root)["dirtySourceTree"])
            subprocess.run(
                ["git", "config", "--unset", "gc.auto"], cwd=root, check=True
            )
            subprocess.run(
                ["git", "config", "--unset", "core.autocrlf"],
                cwd=root,
                check=True,
            )
            for unsafe_autocrlf in ("true", "input"):
                subprocess.run(
                    ["git", "config", "core.autocrlf", unsafe_autocrlf],
                    cwd=root,
                    check=True,
                )
                with self.assertRaisesRegex(ReleaseError, "unsafe local Git"):
                    source_revision(root)
                subprocess.run(
                    ["git", "config", "--unset", "core.autocrlf"],
                    cwd=root,
                    check=True,
                )
            with tempfile.TemporaryDirectory() as auxiliary_directory:
                fake_home = Path(auxiliary_directory) / "home"
                fake_home.mkdir()
                (fake_home / ".gitconfig").write_text(
                    "[url \"https://attacker.invalid/\"]\n"
                    "\tinsteadOf = git@github.com:JekYUlll/Inex.git\n",
                    encoding="utf-8",
                )
                with mock.patch.dict(os.environ, {"HOME": str(fake_home)}):
                    self.assertFalse(source_revision(root)["dirtySourceTree"])
                include_config = Path(auxiliary_directory) / "origin-rewrite.config"
                include_config.write_text(
                    "[remote \"origin\"]\n"
                    "\turl = https://attacker.invalid/Inex.git\n",
                    encoding="utf-8",
                )
                subprocess.run(
                    ["git", "config", "include.path", str(include_config)],
                    cwd=root,
                    check=True,
                )
                with self.assertRaisesRegex(ReleaseError, "unsafe local Git"):
                    source_revision(root)
                subprocess.run(
                    ["git", "config", "--unset-all", "include.path"],
                    cwd=root,
                    check=True,
                )
            subprocess.run(
                [
                    "git",
                    "config",
                    "url.https://attacker.invalid/.insteadOf",
                    "git@github.com:JekYUlll/Inex.git",
                ],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "unsafe local Git"):
                source_revision(root)
            subprocess.run(
                [
                    "git",
                    "config",
                    "--unset-all",
                    "url.https://attacker.invalid/.insteadOf",
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "--add", "remote.origin.url", ""],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "exactly one local origin"):
                source_revision(root)
            subprocess.run(
                ["git", "config", "--unset-all", "remote.origin.url"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "config",
                    "remote.origin.url",
                    "git@github.com:JekYUlll/Inex.git",
                ],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "extensions.worktreeConfig", "true"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "config",
                    "--worktree",
                    "remote.origin.url",
                    "https://attacker.invalid/Inex.git",
                ],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "worktree state|unsafe local Git"):
                source_revision(root)
            subprocess.run(
                ["git", "config", "--worktree", "--unset-all", "remote.origin.url"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "--unset", "extensions.worktreeConfig"],
                cwd=root,
                check=True,
            )
            (root / ".git" / "config.worktree").unlink(missing_ok=True)
            subprocess.run(
                ["git", "config", "core.ignoreCase", "true"],
                cwd=root,
                check=True,
            )
            (root / "TRACKED").write_text("untracked alias\n", encoding="utf-8")
            self.assertTrue(source_revision(root)["dirtySourceTree"])
            (root / "TRACKED").unlink()
            subprocess.run(
                ["git", "config", "--unset", "core.ignoreCase"],
                cwd=root,
                check=True,
            )
            private_exclude = root / ".git" / "info" / "exclude"
            default_exclude = private_exclude.read_bytes()
            private_exclude.write_bytes(default_exclude + b"\nTRACKED\n")
            (root / "TRACKED").write_text("privately ignored\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "exclude patterns"):
                source_revision(root)
            (root / "TRACKED").unlink()
            private_exclude.write_bytes(default_exclude)
            private_attributes = root / ".git" / "info" / "attributes"
            private_attributes.write_text("tracked filter=evil\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "private Git attributes"):
                source_revision(root)
            private_attributes.unlink()
            (root / ".gitignore").write_text("*\n", encoding="utf-8")
            (root / "TRACKED").write_text("hidden alias\n", encoding="utf-8")
            (root / "hidden-input").write_text("hidden\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ReleaseError, "untracked ignore file outside an ignored directory"
            ):
                source_revision(root)
            (root / ".gitignore").unlink()
            (root / "TRACKED").unlink()
            (root / "hidden-input").unlink()
            nested_ignore = root / "visible" / ".gitignore"
            nested_ignore.parent.mkdir()
            nested_ignore.write_text("*\n", encoding="utf-8")
            (nested_ignore.parent / "hidden").write_text("hidden\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ReleaseError, "untracked ignore file outside an ignored directory"
            ):
                source_revision(root)
            (nested_ignore.parent / "hidden").unlink()
            nested_ignore.unlink()
            nested_ignore.parent.rmdir()
            with tempfile.TemporaryDirectory() as worktree_parent:
                linked_worktree = Path(worktree_parent) / "linked"
                subprocess.run(
                    [
                        "git",
                        "worktree",
                        "add",
                        "--detach",
                        "--quiet",
                        str(linked_worktree),
                        "HEAD",
                    ],
                    cwd=root,
                    check=True,
                )
                with self.assertRaisesRegex(ReleaseError, "standalone checkout"):
                    source_revision(root)
                with self.assertRaisesRegex(
                    ReleaseError, "Git directory|standalone checkout"
                ):
                    source_revision(linked_worktree)
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(linked_worktree)],
                    cwd=root,
                    check=True,
                )
                subprocess.run(
                    ["git", "worktree", "prune"], cwd=root, check=True
                )
            if os.name != "nt":
                with tempfile.TemporaryDirectory() as index_parent:
                    index_path = root / ".git" / "index"
                    external_index = Path(index_parent) / "index"
                    os.replace(index_path, external_index)
                    index_path.symlink_to(external_index)
                    with self.assertRaisesRegex(
                        ReleaseError, "Git index path is indirect"
                    ):
                        source_revision(root)
                    index_path.unlink()
                    os.replace(external_index, index_path)
            subprocess.run(
                ["git", "update-index", "--split-index"], cwd=root, check=True
            )
            with self.assertRaisesRegex(ReleaseError, "split Git index"):
                source_revision(root)
            subprocess.run(
                ["git", "update-index", "--no-split-index"], cwd=root, check=True
            )
            for shared_index in (root / ".git").glob("sharedindex.*"):
                shared_index.unlink()
            with tempfile.TemporaryDirectory() as alternate_parent:
                alternates = root / ".git" / "objects" / "info" / "alternates"
                alternates.write_text(
                    f"{Path(alternate_parent).resolve()}\n", encoding="utf-8"
                )
                with self.assertRaisesRegex(ReleaseError, "without alternates"):
                    source_revision(root)
                alternates.unlink()
            subprocess.run(
                ["git", "update-index", "--assume-unchanged", "tracked"],
                cwd=root,
                check=True,
            )
            (root / "tracked").write_text("changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ReleaseError, "special or non-normal"):
                source_revision(root)
            subprocess.run(
                ["git", "update-index", "--no-assume-unchanged", "tracked"],
                cwd=root,
                check=True,
            )
            (root / "tracked").write_text("content\n", encoding="utf-8")
            self.assertFalse(source_revision(root)["dirtySourceTree"])
            subprocess.run(
                ["git", "update-index", "--skip-worktree", "tracked"],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "special or non-normal"):
                source_revision(root)
            subprocess.run(
                ["git", "update-index", "--no-skip-worktree", "tracked"],
                cwd=root,
                check=True,
            )
            good_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
                encoding="ascii",
            ).stdout.strip()
            filter_marker = root / "filter-ran"
            (root / ".gitattributes").write_text(
                "tracked filter=evil\n", encoding="utf-8"
            )
            subprocess.run(
                ["git", "add", ".gitattributes"], cwd=root, check=True
            )
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "filter fixture"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "config",
                    "filter.evil.clean",
                    "sh -c 'touch filter-ran; cat'",
                ],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "unsafe local Git"):
                source_revision(root)
            self.assertFalse(filter_marker.exists())
            subprocess.run(
                ["git", "config", "--unset-all", "filter.evil.clean"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "reset", "--hard", "--quiet", good_commit],
                cwd=root,
                check=True,
            )
            (root / "foo").write_text("file\n", encoding="utf-8")
            (root / "FOO").mkdir()
            (root / "FOO" / "bar").write_text("child\n", encoding="utf-8")
            subprocess.run(
                ["git", "add", "foo", "FOO/bar"], cwd=root, check=True
            )
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "portable prefix collision"],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "unsafe tracked entry"):
                source_revision(root)
            subprocess.run(
                ["git", "reset", "--hard", "--quiet", good_commit],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "tag", "--annotate", "--message", "fixture tag", "v1"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "symbolic-ref", "HEAD", "refs/tags/v1"],
                cwd=root,
                check=True,
            )
            self.assertEqual(source_revision(root)["commit"], good_commit)
            subprocess.run(
                ["git", "symbolic-ref", "HEAD", head_reference],
                cwd=root,
                check=True,
            )
            (root / "tracked").write_text("evil replacement\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked"], cwd=root, check=True)
            subprocess.run(
                ["git", "commit", "--quiet", "-m", "replacement"],
                cwd=root,
                check=True,
            )
            replacement_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
                text=True,
                encoding="ascii",
            ).stdout.strip()
            subprocess.run(
                ["git", "replace", good_commit, replacement_commit],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "reset", "--hard", "--quiet", good_commit],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "replacement object refs"):
                source_revision(root)
            subprocess.run(
                ["git", "replace", "-d", good_commit],
                cwd=root,
                check=True,
                stdout=subprocess.PIPE,
            )
            subprocess.run(
                ["git", "reset", "--hard", "--quiet", good_commit],
                cwd=root,
                check=True,
            )
            if os.name != "nt":
                original_mode = (root / "tracked").stat().st_mode & 0o777
                subprocess.run(
                    ["git", "config", "core.fileMode", "false"],
                    cwd=root,
                    check=True,
                )
                (root / "tracked").chmod(0o755)
                self.assertTrue(source_revision(root)["dirtySourceTree"])
                (root / "tracked").chmod(original_mode)
                subprocess.run(
                    ["git", "config", "--unset", "core.fileMode"],
                    cwd=root,
                    check=True,
                )
                (root / "tracked").chmod(0o755)
                subprocess.run(
                    ["git", "update-index", "--chmod=+x", "tracked"],
                    cwd=root,
                    check=True,
                )
                subprocess.run(
                    ["git", "commit", "--quiet", "-m", "executable fixture"],
                    cwd=root,
                    check=True,
                )
                self.assertFalse(source_revision(root)["dirtySourceTree"])
                subprocess.run(
                    ["git", "config", "core.fileMode", "false"],
                    cwd=root,
                    check=True,
                )
                (root / "tracked").chmod(0o441)
                self.assertTrue(source_revision(root)["dirtySourceTree"])
                with self.assertRaisesRegex(ReleaseError, "mode does not match"):
                    release_common_module._git_blob_oid(
                        root / "tracked", "sha1", "100755"
                    )
                (root / "tracked").chmod(0o755)
                subprocess.run(
                    ["git", "config", "--unset", "core.fileMode"],
                    cwd=root,
                    check=True,
                )
                subprocess.run(
                    ["git", "reset", "--hard", "--quiet", good_commit],
                    cwd=root,
                    check=True,
                )
                (root / "tracked").chmod(original_mode)

            subprocess.run(
                ["git", "config", "core.trustctime", "false"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "core.checkStat", "minimal"],
                cwd=root,
                check=True,
            )
            original_stat = (root / "tracked").stat()
            real_verify = release_common_module._verify_clean_head_tree
            verify_calls = 0

            def mutate_after_first_verify(*args: object, **kwargs: object) -> None:
                nonlocal verify_calls
                verify_calls += 1
                real_verify(*args, **kwargs)
                if verify_calls == 1:
                    (root / "tracked").write_text("changed\n", encoding="utf-8")
                    os.utime(
                        root / "tracked",
                        ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
                    )

            with mock.patch.object(
                release_common_module,
                "_verify_clean_head_tree",
                side_effect=mutate_after_first_verify,
            ), self.assertRaisesRegex(ReleaseError, "bytes do not match"):
                source_revision(root)
            self.assertEqual(verify_calls, 2)
            (root / "tracked").write_text("content\n", encoding="utf-8")
            subprocess.run(
                ["git", "config", "--unset", "core.trustctime"],
                cwd=root,
                check=True,
            )
            subprocess.run(
                ["git", "config", "--unset", "core.checkStat"],
                cwd=root,
                check=True,
            )

            external_worktree = root / "external-worktree"
            external_worktree.mkdir()
            (external_worktree / "tracked").write_text("content\n", encoding="utf-8")
            subprocess.run(
                ["git", "config", "core.worktree", str(external_worktree)],
                cwd=root,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "worktree root"):
                source_revision(root)
            subprocess.run(
                [
                    "git",
                    "--git-dir",
                    str(root / ".git"),
                    "config",
                    "--unset",
                    "core.worktree",
                ],
                cwd=root,
                check=True,
            )
            (external_worktree / "tracked").unlink()
            external_worktree.rmdir()

            with mock.patch.object(
                release_common_module, "MAX_SOURCE_GIT_LISTING_BYTES", 8
            ), self.assertRaisesRegex(ReleaseError, "byte ceiling|safety bounds"):
                source_revision(root)


if __name__ == "__main__":
    unittest.main()
