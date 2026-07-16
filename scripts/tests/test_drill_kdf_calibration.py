from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import stat
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

import audit_release_artifacts as artifact_audit
import drill_kdf_calibration as kdf
from release_common import ReleaseError, sha256_bytes


class KdfCalibrationEvidenceTests(unittest.TestCase):
    SOURCE = {
        "commit": "1" * 40,
        "dirtySourceTree": False,
        "repository": "https://github.com/JekYUlll/Inex",
    }

    @staticmethod
    def calibration_output(
        outcome: str = "target-window",
        *,
        version: str = "0.1.0",
        platform_name: str = "linux-x64",
    ) -> bytes:
        selected = {
            "target-window": (12, 360_000_000, 2),
            "minimum-above-window": (3, 900_000_000, 1),
            "interior-above-window": (6, 900_000_000, 5),
            "maximum-above-window": (20, 900_000_000, 6),
            "maximum-below-window": (20, 100_000_000, 6),
        }[outcome]
        lines = (
            "kdf-calibration-info-schema: inex-kdf-calibration-v1",
            "product: inex",
            f"version: {version}",
            f"rust-target: {kdf.PLATFORMS[platform_name]['rust_target']}",
            "rust-debug-assertions: false",
            "algorithm: argon2id13",
            "measurement-input: inex-public-dummy-v1",
            "cache-scope: process",
            "sample-mode: single-per-candidate",
            "min-ops-limit: 3",
            "max-ops-limit: 20",
            f"selected-ops-limit: {selected[0]}",
            "mem-limit-bytes: 67108864",
            "parallelism: 1",
            "target-min-ns: 250000000",
            "target-max-ns: 750000000",
            f"selected-observed-ns: {selected[1]}",
            f"measurement-count: {selected[2]}",
            f"outcome: {outcome}",
            "end-to-end-sla: false",
        )
        return ("\n".join(lines) + "\n").encode("ascii")

    @staticmethod
    def runtime_output(
        product: str, *, version: str = "0.1.0", platform_name: str = "linux-x64"
    ) -> bytes:
        lines = (
            "runtime-info-schema: inex-runtime-v1",
            f"product: {product}",
            f"version: {version}",
            f"rust-target: {kdf.PLATFORMS[platform_name]['rust_target']}",
            "rust-debug-assertions: false",
            "libsodium-version: 1.0.22",
            "libsodium-library-major: 26",
            "libsodium-library-minor: 4",
            "libsodium-minimal: false",
        )
        return ("\n".join(lines) + "\n").encode("ascii")

    @staticmethod
    def linux_process_observation(sample_count: int = 7) -> dict[str, object]:
        return {
            "source": "linux-proc-status-poll",
            "sampleCount": sample_count,
            "vmHwmBytes": 80 * 1024 * 1024,
            "vmPeakBytes": 160 * 1024 * 1024,
            "maxPolledVmRssBytes": 79 * 1024 * 1024,
            "maxPolledVmSizeBytes": 159 * 1024 * 1024,
        }

    @staticmethod
    def windows_process_observation(sample_count: int = 7) -> dict[str, object]:
        return {
            "source": "windows-process-memory-counters-ex-poll",
            "sampleCount": sample_count,
            "peakWorkingSetBytes": 80 * 1024 * 1024,
            "peakPagefileUsageBytes": 160 * 1024 * 1024,
            "maxPolledWorkingSetBytes": 79 * 1024 * 1024,
            "maxPolledPrivateUsageBytes": 70 * 1024 * 1024,
            "killOnCloseJobObject": True,
        }

    @classmethod
    def release_set_audit(
        cls,
        platform_name: str = "linux-x64",
        *,
        cli_sha256: str = "f" * 64,
        daemon_sha256: str = "d" * 64,
    ) -> dict[str, object]:
        extension_by_kind = {"rust": "zip", "sublime": "zip", "vscode": "vsix"}
        artifacts = [
            {
                "name": f"inex-{kind}-0.1.0-{platform_name}.{extension_by_kind[kind]}",
                "sha256": str(index) * 64,
                "packageManifestSha256": "b" * 64,
            }
            for index, kind in enumerate(("rust", "sublime", "vscode"), start=2)
        ]
        return {
            "schemaVersion": 1,
            "reportType": "inex-release-set-audit",
            "reportScope": (
                "artifact-structure-cross-package-consistency-not-release-approval"
            ),
            "releaseVersion": "0.1.0",
            "platform": platform_name,
            "source": dict(cls.SOURCE),
            "artifactCount": 3,
            "artifacts": artifacts,
            "cargoComponentCount": 77,
            "licenseTextCount": 147,
            "sharedLicenseInventorySha256": "c" * 64,
            "sharedCliSha256": cli_sha256,
            "sharedSidecarSha256": daemon_sha256,
            "notCovered": list(artifact_audit.RELEASE_SET_NOT_COVERED),
            "trustAssumptions": list(artifact_audit.RELEASE_SET_TRUST_ASSUMPTIONS),
        }

    @classmethod
    def valid_report(cls, platform_name: str = "linux-x64") -> dict[str, object]:
        audit = cls.release_set_audit(platform_name)
        suffix = kdf.PLATFORMS[platform_name]["binary_suffix"]
        rust = audit["artifacts"][0]
        process_observation = (
            cls.windows_process_observation()
            if platform_name.startswith("windows-")
            else cls.linux_process_observation()
        )
        calibration = kdf.parse_calibration_report(
            cls.calibration_output(platform_name=platform_name),
            expected_version="0.1.0",
            expected_platform=platform_name,
        )
        runtime_probes = [
            {
                "product": product,
                "arguments": [argument],
                "exitStatus": 0,
                "privateEnvironmentResidueEntries": 0,
                "runtimeInfo": kdf.expected_runtime_info(
                    product, "0.1.0", platform_name
                ),
            }
            for product, argument in (
                ("inex", "runtime-info"),
                ("inexd", "--runtime-info"),
            )
        ]
        return {
            "schemaVersion": 1,
            "reportType": "inex-kdf-calibration-evidence",
            "reportScope": kdf.REPORT_SCOPE,
            "artifactSource": dict(cls.SOURCE),
            "harnessSource": dict(cls.SOURCE),
            "harnessFiles": [
                {"name": name, "sha256": "a" * 64}
                for name in kdf.KDF_HARNESS_FILES
            ],
            "releaseSetAudit": audit,
            "artifactSetFileCount": 4,
            "auditedArtifactCount": 3,
            "auditedArtifacts": [
                {"name": record["name"], "sha256": record["sha256"]}
                for record in audit["artifacts"]
            ],
            "checksumManifest": {"name": "SHA256SUMS", "sha256": "e" * 64},
            "releaseVersion": "0.1.0",
            "nativePlatform": platform_name,
            "packagedExecutables": [
                {
                    "product": "inex",
                    "archiveName": rust["name"],
                    "archiveSha256": rust["sha256"],
                    "memberName": (
                        f"inex-0.1.0-{platform_name}/bin/inex{suffix}"
                    ),
                    "sha256": "f" * 64,
                },
                {
                    "product": "inexd",
                    "archiveName": rust["name"],
                    "archiveSha256": rust["sha256"],
                    "memberName": (
                        f"inex-0.1.0-{platform_name}/bin/inexd{suffix}"
                    ),
                    "sha256": "d" * 64,
                },
            ],
            "runtimeProbes": runtime_probes,
            "calibrationRuntimeIdentity": kdf._expected_runtime_identity(
                "0.1.0", platform_name
            ),
            "hostIdentity": {
                "operatingSystem": "Windows" if platform_name.startswith("windows-") else "Linux",
                "kernelRelease": "test-kernel",
                "architecture": "AMD64" if platform_name.endswith("x64") else "ARM64",
                "cpuDescriptor": "deterministic-test-cpu",
            },
            "hostResources": {
                "logicalProcessorCount": 8,
                "physicalMemoryBytes": 16 * 1024 * 1024 * 1024,
            },
            "harnessRuntime": {
                "implementation": kdf.HARNESS_PYTHON_IMPLEMENTATION,
                "pythonVersion": kdf.HARNESS_PYTHON_VERSION,
            },
            "operationalTimeoutSeconds": kdf.PROCESS_TIMEOUT_SECONDS,
            "processOutputLimitBytes": kdf.PROCESS_OUTPUT_LIMIT_BYTES,
            "attemptCount": 3,
            "retryCount": 0,
            "attempts": [
                {
                    "ordinal": ordinal,
                    "exitStatus": 0,
                    "privateEnvironmentResidueEntries": 0,
                    "calibrationReport": dict(calibration),
                    "processResourceObservation": dict(process_observation),
                }
                for ordinal in range(1, 4)
            ],
            "freshProcessPerAttempt": True,
            "stdinMode": "null",
            "privateEnvironmentPerAttempt": True,
            "privateEnvironmentResidueEntries": 0,
            "selectedObservationScope": (
                "validation-possible-libsodium-init-secure-allocation-and-argon2id-before-key-drop"
            ),
            "endToEndSla": False,
            "reportProtection": kdf.expected_report_protection(platform_name),
            "nativeKdfCalibrationEvidence": "passed",
            "notCovered": list(kdf.REPORT_NOT_COVERED),
            "trustAssumptions": list(kdf.REPORT_TRUST_ASSUMPTIONS),
        }

    def test_calibration_parser_accepts_all_outcomes_and_rejects_noncanonical_text(self) -> None:
        for outcome in sorted(kdf.CALIBRATION_OUTCOMES):
            with self.subTest(outcome=outcome):
                observation = kdf.parse_calibration_report(
                    self.calibration_output(outcome),
                    expected_version="0.1.0",
                    expected_platform="linux-x64",
                )
                self.assertEqual(observation["outcome"], outcome)

        valid = self.calibration_output()
        invalid_values = (
            valid.replace(b"\n", b"\r\n"),
            valid + b"extra: value\n",
            valid[:-1],
            valid.replace(b"product: inex", "product: inéx".encode()),
            valid.replace(b"measurement-count: 2", b"measurement-count: 02"),
            valid.replace(b"rust-debug-assertions: false", b"rust-debug-assertions: true"),
            valid.replace(b"outcome: target-window", b"outcome: maximum-below-window"),
            valid.replace(b"target-min-ns: 250000000", b"target-min-ns: 250000001"),
        )
        for value in invalid_values:
            with self.subTest(value=value[:40]), self.assertRaises(ReleaseError):
                kdf.parse_calibration_report(
                    value,
                    expected_version="0.1.0",
                    expected_platform="linux-x64",
                )

    def test_runtime_info_parser_requires_exact_release_libsodium_identity(self) -> None:
        for product in ("inex", "inexd"):
            observed = kdf.parse_runtime_info(
                self.runtime_output(product),
                product=product,
                version="0.1.0",
                platform_name="linux-x64",
            )
            self.assertEqual(observed["libsodiumVersion"], "1.0.22")
            self.assertFalse(observed["libsodiumMinimal"])
        valid = self.runtime_output("inex")
        for invalid in (
            valid.replace(b"libsodium-minimal: false", b"libsodium-minimal: true"),
            valid.replace(b"libsodium-library-minor: 4", b"libsodium-library-minor: 5"),
            valid.replace(b"rust-debug-assertions: false", b"rust-debug-assertions: true"),
            valid + b"extra: value\n",
        ):
            with self.assertRaises(ReleaseError):
                kdf.parse_runtime_info(
                    invalid,
                    product="inex",
                    version="0.1.0",
                    platform_name="linux-x64",
                )

    def test_evidence_report_is_exact_canonical_and_binds_all_identities(self) -> None:
        report = self.valid_report()
        kdf.validate_evidence_report(report)
        encoded = kdf.encode_evidence_report(report)
        self.assertEqual(json.loads(encoded), report)
        self.assertTrue(encoded.endswith(b"\n"))

        mutations = []
        unknown = json.loads(json.dumps(report))
        unknown["unexpected"] = True
        mutations.append(unknown)
        wrong_binary = json.loads(json.dumps(report))
        wrong_binary["packagedExecutables"][1]["sha256"] = "9" * 64
        mutations.append(wrong_binary)
        wrong_shared_cli = json.loads(json.dumps(report))
        wrong_shared_cli["releaseSetAudit"]["sharedCliSha256"] = "9" * 64
        mutations.append(wrong_shared_cli)
        wrong_runtime = json.loads(json.dumps(report))
        wrong_runtime["runtimeProbes"][0]["runtimeInfo"]["libsodiumMinimal"] = True
        mutations.append(wrong_runtime)
        wrong_ordinal = json.loads(json.dumps(report))
        wrong_ordinal["attempts"][1]["ordinal"] = 1
        mutations.append(wrong_ordinal)
        retry = json.loads(json.dumps(report))
        retry["retryCount"] = 1
        mutations.append(retry)
        false_sample = json.loads(json.dumps(report))
        false_sample["attempts"][0]["processResourceObservation"]["sampleCount"] = False
        mutations.append(false_sample)
        for mutation in mutations:
            with self.assertRaises(ReleaseError):
                kdf.validate_evidence_report(mutation)

    def test_windows_schema_helpers_remain_but_pass_evidence_is_fail_closed(self) -> None:
        report = self.valid_report("windows-x64")
        protection = report["reportProtection"]
        self.assertEqual(
            protection["scheme"], "windows-create-new-inherited-parent-dacl"
        )
        self.assertNotIn("mode", protection)
        resource = report["attempts"][0]["processResourceObservation"]
        self.assertIn("maxPolledPrivateUsageBytes", resource)
        self.assertNotIn("peakPrivateCommitBytes", resource)
        self.assertTrue(resource["killOnCloseJobObject"])
        kdf.validate_process_resource_observation(resource, "windows-x64")
        with self.assertRaisesRegex(
            ReleaseError, "suspended-before-Job assignment.*Job-empty.*NTFS ADS"
        ):
            kdf.validate_evidence_report(report)

    def test_windows_run_fails_before_any_artifact_use(self) -> None:
        capture = mock.Mock()
        with (
            mock.patch.object(kdf.os, "name", "nt"),
            mock.patch.object(kdf, "_capture_harness_state", capture),
            self.assertRaisesRegex(
                ReleaseError, "suspended-before-Job assignment.*Job-empty.*NTFS ADS"
            ),
        ):
            kdf.run_kdf_calibration_drill(Path("/path-that-must-not-be-resolved"))
        capture.assert_not_called()

        arguments = mock.Mock(
            directory=Path("/path-that-must-not-be-resolved"),
            output=Path("/output-that-must-not-be-resolved/report.json"),
        )
        drill = mock.Mock()
        with (
            mock.patch.object(kdf.os, "name", "nt"),
            mock.patch.object(kdf, "parse_arguments", return_value=arguments),
            mock.patch.object(kdf, "run_kdf_calibration_drill", drill),
            self.assertRaisesRegex(
                ReleaseError, "suspended-before-Job assignment.*Job-empty.*NTFS ADS"
            ),
        ):
            kdf.main()
        drill.assert_not_called()

    def test_argparse_and_runtime_are_exactly_pinned(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(sys, "argv", ["drill_kdf_calibration.py", "--help"]),
            contextlib.redirect_stdout(output),
            self.assertRaises(SystemExit) as stopped,
        ):
            kdf.parse_arguments()
        self.assertEqual(stopped.exception.code, 0)
        self.assertIn("2 packaged runtime probes plus exactly 3", output.getvalue())

        report = self.valid_report()
        report["harnessRuntime"]["pythonVersion"] = "3.13.13"
        with self.assertRaisesRegex(ReleaseError, "harness runtime"):
            kdf.validate_evidence_report(report)
        with (
            mock.patch.object(kdf.host_platform, "python_version", return_value="3.13.13"),
            self.assertRaisesRegex(ReleaseError, "exact CPython 3.13.14"),
        ):
            kdf.run_kdf_calibration_drill(Path("/path-that-must-not-be-resolved"))

    @contextlib.contextmanager
    def patched_artifact_pipeline(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_directory = root / "artifacts"
            artifact_directory.mkdir()
            cli_bytes = b"packaged-cli"
            daemon_bytes = b"packaged-daemon"
            cli_sha256 = sha256_bytes(cli_bytes)
            daemon_sha256 = sha256_bytes(daemon_bytes)
            audit = self.release_set_audit(
                cli_sha256=cli_sha256,
                daemon_sha256=daemon_sha256,
            )
            artifact_hashes = {
                record["name"]: record["sha256"] for record in audit["artifacts"]
            }
            prefix = "inex-0.1.0-linux-x64/bin"
            entries = {
                "rust": {
                    f"{prefix}/inex": (cli_bytes, 0o755),
                    f"{prefix}/inexd": (daemon_bytes, 0o755),
                },
                "sublime": {},
                "vscode": {},
            }

            def snapshot(_source: Path, destination: Path) -> None:
                destination.mkdir()
                (destination / "SHA256SUMS").write_bytes(b"captured-checksums\n")
                for name in artifact_hashes:
                    (destination / name).write_bytes(name.encode("ascii"))
                self._artifact_snapshot = destination

            def extract(_entries: object, _platform: str, destination: Path):
                destination.mkdir()
                cli = destination / "inex"
                daemon = destination / "inexd"
                cli.write_bytes(cli_bytes)
                daemon.write_bytes(daemon_bytes)
                cli.chmod(0o700)
                daemon.chmod(0o700)
                return cli, daemon

            harness_hashes = {name: "a" * 64 for name in kdf.KDF_HARNESS_FILES}
            with contextlib.ExitStack() as stack:
                stack.enter_context(
                    mock.patch.object(
                        kdf,
                        "_capture_harness_state",
                        return_value=(dict(self.SOURCE), harness_hashes),
                    )
                )
                stack.enter_context(
                    mock.patch.object(kdf.lifecycle, "snapshot_artifact_directory", snapshot)
                )
                stack.enter_context(
                    mock.patch.object(
                        kdf.lifecycle,
                        "capture_audited_artifacts",
                        return_value=(
                            entries,
                            artifact_hashes,
                            dict(self.SOURCE),
                            "0.1.0",
                            "linux-x64",
                            audit,
                        ),
                    )
                )
                stack.enter_context(
                    mock.patch.object(kdf.lifecycle, "native_platform", return_value="linux-x64")
                )
                stack.enter_context(
                    mock.patch.object(kdf.lifecycle, "extract_packaged_binaries", extract)
                )
                stack.enter_context(
                    mock.patch.object(kdf.lifecycle, "assert_harness_source_unchanged")
                )
                yield artifact_directory

    def runtime_probe_runner(self, executable: Path, arguments, **_kwargs) -> kdf.ProcessCapture:
        product = executable.name
        expected_arguments = (
            ("runtime-info",) if product == "inex" else ("--runtime-info",)
        )
        self.assertEqual(tuple(arguments), expected_arguments)
        return kdf.ProcessCapture(self.runtime_output(product), None)

    def test_drill_runs_three_fresh_attempts_and_two_separate_runtime_probes(self) -> None:
        calls = []

        def calibration_runner(_executable: Path, **kwargs) -> kdf.ProcessCapture:
            calls.append(kwargs)
            self.assertEqual(stat.S_IMODE(_executable.stat().st_mode) & 0o222, 0)
            self.assertEqual(
                stat.S_IMODE(_executable.with_name("inexd").stat().st_mode) & 0o222,
                0,
            )
            required = {
                "HOME",
                "XDG_CACHE_HOME",
                "XDG_CONFIG_HOME",
                "XDG_DATA_HOME",
                "XDG_STATE_HOME",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
                "TEMP",
                "TMP",
                "TMPDIR",
            }
            self.assertTrue(required <= set(kwargs["environment"]))
            self.assertTrue(kwargs["cwd"].is_dir())
            self.assertEqual(kwargs["timeout"], 120)
            self.assertEqual(kwargs["platform_name"], "linux-x64")
            ordinal = len(calls)
            return kdf.ProcessCapture(
                self.calibration_output(), self.linux_process_observation(ordinal)
            )

        with self.patched_artifact_pipeline() as artifact_directory:
            report, encoded = kdf.run_kdf_calibration_drill(
                artifact_directory,
                process_runner=calibration_runner,
                runtime_probe_runner=self.runtime_probe_runner,
                resource_observer=lambda: {
                    "logicalProcessorCount": 8,
                    "physicalMemoryBytes": 16 * 1024 * 1024 * 1024,
                },
                identity_observer=lambda: {
                    "operatingSystem": "Linux",
                    "kernelRelease": "test-kernel",
                    "architecture": "x86_64",
                    "cpuDescriptor": "deterministic-test-cpu",
                },
            )
        self.assertEqual(len(calls), 3)
        self.assertEqual(len({str(call["cwd"]) for call in calls}), 3)
        self.assertTrue(all(not call["cwd"].exists() for call in calls))
        self.assertEqual([attempt["ordinal"] for attempt in report["attempts"]], [1, 2, 3])
        self.assertEqual([probe["product"] for probe in report["runtimeProbes"]], ["inex", "inexd"])
        self.assertEqual(
            report["packagedExecutables"][0]["sha256"],
            report["releaseSetAudit"]["sharedCliSha256"],
        )
        self.assertEqual(
            report["packagedExecutables"][1]["sha256"],
            report["releaseSetAudit"]["sharedSidecarSha256"],
        )
        self.assertEqual(json.loads(encoded), report)

    def test_runtime_probe_executable_self_modification_is_fail_closed(self) -> None:
        def mutating_probe(
            executable: Path, arguments, **_kwargs
        ) -> kdf.ProcessCapture:
            executable.chmod(0o700)
            executable.write_bytes(b"self-modified-cli")
            return self.runtime_probe_runner(executable, arguments)

        with self.patched_artifact_pipeline() as artifact_directory:
            with self.assertRaisesRegex(
                ReleaseError, "packaged inex executable"
            ):
                kdf.run_kdf_calibration_drill(
                    artifact_directory,
                    process_runner=lambda *_args, **_kwargs: kdf.ProcessCapture(
                        self.calibration_output(), self.linux_process_observation()
                    ),
                    runtime_probe_runner=mutating_probe,
                )

    def test_attempt_daemon_self_modification_is_fail_closed(self) -> None:
        def mutating_attempt(executable: Path, **_kwargs) -> kdf.ProcessCapture:
            daemon = executable.with_name("inexd")
            daemon.chmod(0o700)
            daemon.write_bytes(b"self-modified-daemon")
            return kdf.ProcessCapture(
                self.calibration_output(), self.linux_process_observation()
            )

        with self.patched_artifact_pipeline() as artifact_directory:
            with self.assertRaisesRegex(
                ReleaseError, "packaged inexd executable"
            ):
                kdf.run_kdf_calibration_drill(
                    artifact_directory,
                    process_runner=mutating_attempt,
                    runtime_probe_runner=self.runtime_probe_runner,
                )

    def test_artifact_snapshot_mutation_during_attempt_is_fail_closed(self) -> None:
        def mutating_attempt(_executable: Path, **_kwargs) -> kdf.ProcessCapture:
            (self._artifact_snapshot / "SHA256SUMS").write_bytes(
                b"mutated-checksums\n"
            )
            return kdf.ProcessCapture(
                self.calibration_output(), self.linux_process_observation()
            )

        with self.patched_artifact_pipeline() as artifact_directory:
            with self.assertRaisesRegex(
                ReleaseError, "artifact snapshot file SHA256SUMS"
            ):
                kdf.run_kdf_calibration_drill(
                    artifact_directory,
                    process_runner=mutating_attempt,
                    runtime_probe_runner=self.runtime_probe_runner,
                )

    def test_drill_stops_on_invalid_attempt_without_retry_or_cherry_pick(self) -> None:
        calls = 0

        def calibration_runner(_executable: Path, **_kwargs) -> kdf.ProcessCapture:
            nonlocal calls
            calls += 1
            output = self.calibration_output() if calls == 1 else b"invalid\n"
            return kdf.ProcessCapture(output, self.linux_process_observation())

        with self.patched_artifact_pipeline() as artifact_directory:
            with self.assertRaises(ReleaseError):
                kdf.run_kdf_calibration_drill(
                    artifact_directory,
                    process_runner=calibration_runner,
                    runtime_probe_runner=self.runtime_probe_runner,
                )
        self.assertEqual(calls, 2)

    def test_drill_fails_closed_on_private_environment_residue(self) -> None:
        calls = 0

        def calibration_runner(_executable: Path, **kwargs) -> kdf.ProcessCapture:
            nonlocal calls
            calls += 1
            (kwargs["cwd"] / "unexpected").write_bytes(b"residue")
            return kdf.ProcessCapture(
                self.calibration_output(), self.linux_process_observation()
            )

        with self.patched_artifact_pipeline() as artifact_directory:
            with self.assertRaisesRegex(ReleaseError, "residue"):
                kdf.run_kdf_calibration_drill(
                    artifact_directory,
                    process_runner=calibration_runner,
                    runtime_probe_runner=self.runtime_probe_runner,
                )
        self.assertEqual(calls, 1)

    def test_sampler_error_terminates_process_tree_and_finishes_readers_once(self) -> None:
        class FakeProcess:
            pid = 4242
            stdout = object()
            stderr = object()

            @staticmethod
            def poll():
                return None

            @staticmethod
            def wait(timeout=None):
                return -9

        readers = []

        class FakeReader:
            def __init__(self, *_args):
                self.finish_calls = 0
                readers.append(self)

            @staticmethod
            def start():
                return None

            def finish(self, *, timeout=10):
                self.finish_calls += 1
                return b""

        cleanup = mock.Mock()
        with (
            mock.patch.object(kdf.lifecycle, "prepare_process_isolation"),
            mock.patch.object(kdf.subprocess, "Popen", return_value=FakeProcess()),
            mock.patch.object(kdf.lifecycle, "BoundedPipeReader", FakeReader),
            mock.patch.object(kdf.lifecycle, "cleanup_process_descendants", cleanup),
            mock.patch.object(
                kdf,
                "_linux_process_memory_sample",
                side_effect=ReleaseError("sampler failed"),
            ),
        ):
            with self.assertRaisesRegex(ReleaseError, "sampler failed"):
                kdf.run_bounded_packaged_process(
                    Path("/fake/inex"),
                    ("kdf-calibration-info",),
                    environment={},
                    cwd=Path("/fake"),
                    timeout=120,
                    observe_resources=True,
                    platform_name="linux-x64",
                )
        cleanup.assert_called_once()
        self.assertEqual([reader.finish_calls for reader in readers], [1, 1])

    @unittest.skipIf(
        os.name == "nt"
        or not hasattr(os, "pidfd_open")
        or not hasattr(signal, "pidfd_send_signal"),
        "POSIX pidfd executable fixture",
    )
    def test_real_bounded_runner_uses_null_stdin_and_external_proc_observation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            executable = root / "fake-inex"
            output_literal = repr(self.calibration_output())
            executable.write_text(
                textwrap.dedent(
                    f"""\
                    #!{sys.executable}
                    import sys
                    import time
                    if sys.argv[1:] != ["kdf-calibration-info"]:
                        raise SystemExit(2)
                    if sys.stdin.buffer.read() != b"":
                        raise SystemExit(3)
                    sys.stdout.buffer.write({output_literal})
                    sys.stdout.buffer.flush()
                    time.sleep(0.5)
                    """
                ),
                encoding="utf-8",
            )
            executable.chmod(0o700)
            environment, cwd = kdf._private_environment(root / "private")
            capture = kdf.run_calibration_process(
                executable,
                environment=environment,
                cwd=cwd,
                timeout=10,
                platform_name="linux-x64",
            )
            observation = kdf.parse_calibration_report(
                capture.stdout,
                expected_version="0.1.0",
                expected_platform="linux-x64",
            )
            self.assertEqual(observation["outcome"], "target-window")
            kdf.validate_process_resource_observation(
                capture.resource_observation, "linux-x64"
            )

    def test_output_path_containment_and_platform_casefold_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "Artifacts"
            external = root / "evidence"
            artifact.mkdir()
            external.mkdir()
            with self.assertRaisesRegex(ReleaseError, "inside"):
                kdf.resolve_evidence_output_path(artifact, artifact)
            with self.assertRaisesRegex(ReleaseError, "inside"):
                kdf.resolve_evidence_output_path(artifact / "report.json", artifact)
            for unsafe_name in ("report.json:secret", "CON.json", "trailing-dot."):
                with self.subTest(unsafe_name=unsafe_name), self.assertRaisesRegex(
                    ReleaseError, "ADS-safe"
                ):
                    kdf.resolve_evidence_output_path(external / unsafe_name, artifact)
            resolved = kdf.resolve_evidence_output_path(external / "report.json", artifact)
            self.assertEqual(resolved, external / "report.json")
            self.assertTrue(
                kdf._path_is_within(
                    Path("/TMP/ARTIFACTS/report.json"),
                    Path("/tmp/artifacts"),
                    case_insensitive=True,
                )
            )
            self.assertFalse(
                kdf._path_is_within(
                    Path("/tmp/artifacts-other/report.json"),
                    Path("/tmp/artifacts"),
                    case_insensitive=True,
                )
            )

    @unittest.skipIf(os.name == "nt", "POSIX mode assertion")
    def test_report_writer_is_create_new_mode_0600_and_removes_partial_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence.json"
            encoded = b'{"canonical":true}\n'
            kdf.write_evidence_report(output, encoded)
            self.assertEqual(output.read_bytes(), encoded)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            with self.assertRaises(ReleaseError):
                kdf.write_evidence_report(output, encoded)

            partial = root / "partial.json"
            with mock.patch.object(kdf.os, "fsync", side_effect=OSError("forced")):
                with self.assertRaises(ReleaseError):
                    kdf.write_evidence_report(partial, encoded)
            self.assertFalse(partial.exists())


if __name__ == "__main__":
    unittest.main()
