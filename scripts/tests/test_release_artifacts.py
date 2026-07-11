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
    read_zip_entries,
    read_zip_entries_from_bytes,
    validate_member_name,
    validate_package_manifest,
    validate_vsix_metadata,
    validate_vscode,
)
from package_release import project_version
from release_common import (
    MAX_ARCHIVE_MEMBERS,
    ReleaseError,
    portable_archive_key,
    safe_archive_name,
    sha256_bytes,
    source_revision,
    validate_native_binary,
    write_reproducible_zip,
)
from verify_release_tag import validate_release_tag


class ReleaseArchiveTests(unittest.TestCase):
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
