from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


RUNNER_PATH = (
    Path(__file__).resolve().parents[1]
    / "test"
    / "build4200"
    / "run_build4200.py"
)
SPEC = importlib.util.spec_from_file_location("inex_build4200_runner", RUNNER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Build 4200 runner module is unavailable")
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)


class Build4200RunnerFoundationTests(unittest.TestCase):
    def test_artifact_directory_and_output_are_required_together(self) -> None:
        self.assertIsNone(runner.parse_arguments([]).artifact_directory)
        paired = runner.parse_arguments(
            ["--artifact-directory", "/artifact", "--output", "/report.json"]
        )
        self.assertEqual(paired.artifact_directory, Path("/artifact"))
        self.assertEqual(paired.output, Path("/report.json"))
        for arguments in (
            ["--artifact-directory", "/artifact"],
            ["--output", "/report.json"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                runner.parse_arguments(arguments)

    def test_physical_seal_rejects_mutation_rebind_and_hardlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "input"
            path.write_bytes(b"before")
            seal = runner.capture_physical_file_seal(path, "input")
            runner.verify_physical_file_seal(path, seal, "input")

            path.write_bytes(b"after")
            with self.assertRaisesRegex(runner.QaFailure, "changed"):
                runner.verify_physical_file_seal(path, seal, "input")

            replacement = root / "replacement"
            replacement.write_bytes(b"before")
            os.replace(replacement, path)
            with self.assertRaisesRegex(runner.QaFailure, "changed"):
                runner.verify_physical_file_seal(path, seal, "input")

            linked = root / "linked"
            os.link(path, linked)
            with self.assertRaisesRegex(runner.QaFailure, "single-link"):
                runner.capture_physical_file_seal(path, "input")

    @unittest.skipIf(os.name == "nt", "POSIX executable mode assertion")
    def test_executable_seal_removes_write_bits_and_detects_self_modification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "inex"
            executable.write_bytes(b"packaged executable")
            executable.chmod(0o755)
            seal = runner.capture_physical_file_seal(
                executable,
                "inex",
                strip_posix_write_bits=True,
                require_posix_executable=True,
            )
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o555)
            runner.verify_physical_file_seal(
                executable, seal, "inex", require_posix_executable=True
            )
            executable.chmod(0o755)
            executable.write_bytes(b"self modified")
            with self.assertRaises(runner.QaFailure):
                runner.verify_physical_file_seal(
                    executable, seal, "inex", require_posix_executable=True
                )

    def test_artifact_snapshot_is_exact_and_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            destination = root / "snapshot"

            def fake_snapshot(_source: Path, output: Path) -> None:
                output.mkdir()
                for name in (
                    "SHA256SUMS",
                    "inex-rust-0.1.0-linux-x64.zip",
                    "inex-sublime-0.1.0-linux-x64.zip",
                    "inex-vscode-0.1.0-linux-x64.vsix",
                ):
                    (output / name).write_bytes(name.encode("ascii"))

            with mock.patch.object(
                runner.release_lifecycle,
                "snapshot_artifact_directory",
                side_effect=fake_snapshot,
            ):
                seals = runner.capture_artifact_snapshot(source, destination)
            self.assertEqual(len(seals), 4)
            runner.verify_artifact_snapshot(destination, seals)
            (destination / "SHA256SUMS").write_bytes(b"mutated")
            with self.assertRaisesRegex(runner.QaFailure, "changed"):
                runner.verify_artifact_snapshot(destination, seals)

    @unittest.skipIf(os.name == "nt", "Linux package shape fixture")
    def test_materialization_uses_in_memory_members_and_exclusive_creation(self) -> None:
        entries = {
            "rust": {
                "inex-0.1.0-linux-x64/bin/inex": (b"cli", 0o755),
            },
            "sublime": {
                "Inex/.python-version": (b"3.8\n", 0o644),
                "Inex/Inex.py": (b"plugin", 0o644),
                "Inex/bin/inexd": (b"daemon", 0o755),
            },
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            packages = root / "Packages"
            packages.mkdir()
            with mock.patch.object(
                runner.release_lifecycle,
                "native_platform",
                return_value="linux-x64",
            ):
                cli, daemon, records = runner.materialize_packaged_inputs(
                    entries, "linux-x64", root / "cli", packages
                )
            self.assertEqual(cli.read_bytes(), b"cli")
            self.assertEqual(daemon.read_bytes(), b"daemon")
            self.assertEqual(stat.S_IMODE(cli.stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE(daemon.stat().st_mode), 0o555)
            self.assertEqual(len(records), 4)
            with self.assertRaises(runner.QaFailure):
                runner.write_exclusive_member(cli, b"replacement", 0o555)

    @unittest.skipIf(os.name == "nt", "POSIX report protection assertion")
    def test_external_report_is_create_new_and_requires_private_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            artifact = root / "artifact"
            artifact.mkdir()
            evidence = root / "evidence"
            evidence.mkdir(mode=0o700)
            output = evidence / "sublime-normal.json"
            resolved = runner.resolve_artifact_output_path(output, artifact, None)
            self.assertEqual(resolved, output)
            runner.write_artifact_report(resolved, b"{}\n")
            self.assertEqual(resolved.read_bytes(), b"{}\n")
            self.assertEqual(stat.S_IMODE(resolved.stat().st_mode), 0o600)
            with self.assertRaises(runner.QaFailure):
                runner.write_artifact_report(resolved, b"replacement\n")

            public = root / "public"
            public.mkdir(mode=0o755)
            with self.assertRaisesRegex(runner.QaFailure, "unsafe"):
                runner.resolve_artifact_output_path(
                    public / "report.json", artifact, None
                )

    def test_residue_scanner_covers_url_encoding_and_fails_on_links(self) -> None:
        token = "INEXQA_URL_" + "ab" * 16
        labels = {label for label, _needle in runner.encoded_needles([token])}
        self.assertEqual(labels, set(runner.SCAN_ENCODINGS))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            encoded = dict(runner.encoded_needles([token]))["base64url-unpadded"]
            (root / "encoded.bin").write_bytes(encoded)
            hits = runner.scan_for_tokens((root,), [token])
            self.assertEqual(len(hits), 1)
            (root / "encoded.bin").unlink()
            target = root / "target"
            target.write_bytes(b"public")
            (root / "link").symlink_to(target)
            with self.assertRaisesRegex(runner.QaFailure, "non-regular|link-like"):
                runner.scan_for_tokens((root,), [token])


if __name__ == "__main__":
    unittest.main()
