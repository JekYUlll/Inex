from __future__ import annotations

import json
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest
import zipfile

from audit_release_artifacts import (
    read_zip_entries,
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

    def test_manifest_platform_mismatch_is_rejected(self) -> None:
        content = b"payload"
        manifest = {
            "schemaVersion": 1,
            "package": "rust-binaries",
            "platform": "linux-arm64",
            "version": "0.1.0",
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


if __name__ == "__main__":
    unittest.main()
