from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

import fetch_libsodium_dist as fetch


class FetchLibsodiumDistTests(unittest.TestCase):
    def test_pins_source_pair_from_checksum_locked_crate(self) -> None:
        self.assertEqual(fetch.LOCKED_CRATE_NAME, "libsodium-sys-stable")
        self.assertEqual(fetch.LOCKED_CRATE_VERSION, "1.24.0")
        self.assertEqual(
            fetch.LOCKED_CRATE_SOURCE,
            "registry+https://github.com/rust-lang/crates.io-index",
        )
        self.assertEqual(
            fetch.BUNDLED_FILES,
            {
                "LATEST.tar.gz": {
                    "sha256": (
                        "b20a92e7ec25b285eafa349d721a5bb27e3a8ba94c0816630a127883f1d1b3ab"
                    ),
                    "max_bytes": 2_100_000,
                },
                "LATEST.tar.gz.minisig": {
                    "sha256": (
                        "2162883303fb903068519916871476b192d5cf31d5e412378db8ae05a0c05895"
                    ),
                    "max_bytes": 4_096,
                },
            },
        )

    def test_pins_versioned_release_assets_under_crate_expected_names(self) -> None:
        self.assertEqual(
            fetch.BASE_URL,
            "https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE",
        )
        self.assertEqual(
            fetch.FILES,
            {
                "libsodium-1.0.22-stable-msvc.zip": {
                    "source_name": "libsodium-1.0.22-msvc.zip",
                    "sha256": (
                        "3e03a726fac4bc09cb61d8f29d658ef7a5eca0811de59082130414f7ca2e4279"
                    ),
                    "max_bytes": 18_000_000,
                },
                "libsodium-1.0.22-stable-msvc.zip.minisig": {
                    "source_name": "libsodium-1.0.22-msvc.zip.minisig",
                    "sha256": (
                        "3210cf4d985f7b192bb8d5eb2ec7f481e0f47420f144cf1069921f714bfad1d1"
                    ),
                    "max_bytes": 4_096,
                },
            },
        )

    def test_download_uses_source_name_but_writes_expected_local_name(self) -> None:
        payload = b"immutable release input\n"
        expected = {
            "source_name": "upstream-name.zip",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "max_bytes": len(payload),
        }
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "crate-required-name.zip"

            def fake_run(arguments: list[str], **_kwargs: object) -> None:
                output_index = arguments.index("--output") + 1
                Path(arguments[output_index]).write_bytes(payload)
                self.assertIn("--location", arguments)
                self.assertEqual(
                    arguments[arguments.index("--proto-redir") + 1], "=https"
                )
                self.assertEqual(
                    arguments[arguments.index("--max-filesize") + 1],
                    str(len(payload)),
                )
                self.assertEqual(
                    arguments[-1], f"{fetch.BASE_URL}/upstream-name.zip"
                )

            with (
                mock.patch.object(fetch.shutil, "which", return_value="/usr/bin/curl"),
                mock.patch.object(fetch.subprocess, "run", side_effect=fake_run),
            ):
                fetch.download("crate-required-name.zip", destination, expected)

            self.assertEqual(destination.read_bytes(), payload)
            self.assertFalse(destination.with_name(destination.name + ".tmp").exists())

    def test_resolves_exact_registry_package_through_locked_metadata(self) -> None:
        manifest = Path("/cargo/registry/libsodium-sys-stable-1.24.0/Cargo.toml")
        metadata = {
            "packages": [
                {
                    "name": fetch.LOCKED_CRATE_NAME,
                    "version": fetch.LOCKED_CRATE_VERSION,
                    "source": fetch.LOCKED_CRATE_SOURCE,
                    "manifest_path": str(manifest),
                }
            ]
        }
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps(metadata), stderr=""
        )
        with (
            mock.patch.object(fetch.shutil, "which", return_value="/usr/bin/cargo"),
            mock.patch.object(fetch.subprocess, "run", return_value=completed) as run,
        ):
            self.assertEqual(fetch.locked_crate_directory(), manifest.parent)

        arguments = run.call_args.args[0]
        self.assertIn("--locked", arguments)
        self.assertEqual(
            arguments[arguments.index("--manifest-path") + 1],
            str(fetch.PROJECT_ROOT / "Cargo.toml"),
        )

    def test_copies_only_hash_pinned_regular_bundled_input(self) -> None:
        payload = b"checksum-locked crate input\n"
        expected = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "max_bytes": len(payload),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "LATEST.tar.gz").write_bytes(payload)
            destination = root / "dist" / "LATEST.tar.gz"
            destination.parent.mkdir()

            fetch.copy_bundled_input(
                "LATEST.tar.gz", source, destination, expected
            )

            self.assertEqual(destination.read_bytes(), payload)
            self.assertFalse(destination.with_name(destination.name + ".tmp").exists())

    def test_existing_input_rejects_oversize_symlink_and_hardlink(self) -> None:
        payload = b"pinned\n"
        expected = {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "max_bytes": len(payload),
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.write_bytes(payload)
            self.assertTrue(fetch.existing_is_valid(source, expected))

            oversized = root / "oversized"
            oversized.write_bytes(payload + b"x")
            self.assertFalse(fetch.existing_is_valid(oversized, expected))

            linked = root / "linked"
            linked.hardlink_to(source)
            self.assertFalse(fetch.existing_is_valid(source, expected))
            self.assertFalse(fetch.existing_is_valid(linked, expected))

            symbolic = root / "symbolic"
            symbolic.symlink_to(oversized)
            self.assertFalse(fetch.existing_is_valid(symbolic, expected))

    def test_main_rejects_symlink_output_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual"
            actual.mkdir()
            redirected = root / "redirected"
            redirected.symlink_to(actual, target_is_directory=True)
            arguments = argparse.Namespace(output=redirected, github_env=False)
            with (
                mock.patch.object(fetch, "parse_arguments", return_value=arguments),
                self.assertRaisesRegex(
                    fetch.FetchError, "output must be a non-symlink directory"
                ),
            ):
                fetch.main()

    def test_main_rejects_github_environment_line_injection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "dist\nINJECTED=yes"
            github_environment = root / "github.env"
            github_environment.write_text("SAFE=yes\n", encoding="utf-8")
            arguments = argparse.Namespace(output=output, github_env=True)
            with (
                mock.patch.object(fetch, "parse_arguments", return_value=arguments),
                mock.patch.dict(
                    fetch.os.environ,
                    {"GITHUB_ENV": str(github_environment)},
                    clear=False,
                ),
                self.assertRaisesRegex(
                    fetch.FetchError, "output path must not contain line breaks"
                ),
            ):
                fetch.main()

            self.assertFalse(output.exists())
            self.assertEqual(
                github_environment.read_text(encoding="utf-8"), "SAFE=yes\n"
            )

    def test_main_rejects_line_injection_from_resolved_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            actual = root / "actual\nINJECTED=yes"
            actual.mkdir()
            safe = root / "safe"
            safe.symlink_to(actual, target_is_directory=True)
            output = safe / "dist"
            github_environment = root / "github.env"
            github_environment.write_text("SAFE=yes\n", encoding="utf-8")
            arguments = argparse.Namespace(output=output, github_env=True)
            with (
                mock.patch.object(fetch, "parse_arguments", return_value=arguments),
                mock.patch.dict(
                    fetch.os.environ,
                    {"GITHUB_ENV": str(github_environment)},
                    clear=False,
                ),
                self.assertRaisesRegex(
                    fetch.FetchError, "resolved output path must not contain line breaks"
                ),
            ):
                fetch.main()

            self.assertFalse((actual / "dist").exists())
            self.assertEqual(
                github_environment.read_text(encoding="utf-8"), "SAFE=yes\n"
            )


if __name__ == "__main__":
    unittest.main()
