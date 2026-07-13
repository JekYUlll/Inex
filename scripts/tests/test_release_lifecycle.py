from __future__ import annotations

import contextlib
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import audit_release_artifacts as artifact_audit
import drill_release_lifecycle as lifecycle

from drill_release_lifecycle import (
    EvidenceDirectory,
    FROZEN_V1_FILE_LIMITS,
    FROZEN_V1_MAX_TOTAL_BYTES,
    MAX_ARCHIVE_TOTAL_BYTES,
    ReleaseError,
    SCAN_CHUNK_BYTES,
    assert_harness_source_unchanged,
    assert_imported_vault_physical_layout,
    assert_plaintext_source_preserved,
    assert_single_commit_repository,
    assert_frozen_product_unchanged,
    assert_no_plaintext_markdown,
    copy_regular_tree,
    controlled_environment,
    create_plaintext_source,
    expected_tree_entries,
    file_contains_any,
    read_rpc_response,
    run_lifecycle_drill,
    run_process,
    is_auth_failed_response,
    prepare_frozen_v1_fixture,
    scan_for_sensitive_data,
    sensitive_variants,
    snapshot_regular_tree,
    snapshot_artifact_directory,
    shell_quote,
    strict_base64url_decode,
    verify_driver_configuration,
    verify_locked_structure,
)


class ReleaseLifecycleTests(unittest.TestCase):
    @staticmethod
    def valid_lifecycle_report() -> dict[str, object]:
        source = {
            "commit": "1" * 40,
            "dirtySourceTree": False,
            "repository": "https://github.com/JekYUlll/Inex",
        }
        artifacts = [
            {
                "name": f"inex-{kind}-0.1.0-linux-x64.{extension}",
                "sha256": str(index) * 64,
            }
            for index, (kind, extension) in enumerate(
                (("rust", "zip"), ("sublime", "zip"), ("vscode", "vsix")), start=2
            )
        ]
        release_set_audit = {
            "schemaVersion": 1,
            "reportType": "inex-release-set-audit",
            "reportScope": (
                "artifact-structure-cross-package-consistency-not-release-approval"
            ),
            "releaseVersion": "0.1.0",
            "platform": "linux-x64",
            "source": dict(source),
            "artifactCount": 3,
            "artifacts": [
                {
                    "name": record["name"],
                    "sha256": record["sha256"],
                    "packageManifestSha256": "b" * 64,
                }
                for record in artifacts
            ],
            "cargoComponentCount": 77,
            "licenseTextCount": 147,
            "sharedLicenseInventorySha256": "c" * 64,
            "sharedCliSha256": "e" * 64,
            "sharedSidecarSha256": "d" * 64,
            "notCovered": list(artifact_audit.RELEASE_SET_NOT_COVERED),
            "trustAssumptions": list(artifact_audit.RELEASE_SET_TRUST_ASSUMPTIONS),
        }
        return {
            "schemaVersion": 1,
            "reportType": "inex-release-lifecycle",
            "artifactSource": dict(source),
            "auditedArtifactCount": 3,
            "auditedArtifacts": artifacts,
            "authenticatedExpectedBodies": 5,
            "cliAuthFailureSecretNondisclosure": True,
            "cleanRegularFileTreeCopyRestoreVerified": True,
            "covered": list(lifecycle.LIFECYCLE_REPORT_COVERED),
            "sensitiveResidueHitsOutsideDesignatedPlaintextSource": 0,
            "residueContentScanExcludedRoots": ["plaintext-source"],
            "designatedPlaintextSourcePathComponentsScanned": True,
            "driverRelocationVerified": True,
            "fixtureFiles": [
                {"name": name, "sha256": lifecycle.FROZEN_V1_HASHES[name]}
                for name in sorted(lifecycle.FROZEN_V1_HASHES)
            ],
            "frozenV1CompatibilityRead": True,
            "frozenV1ProductBytesUnchanged": True,
            "filesystemType": "ext2/ext3",
            "gitBundleVerified": True,
            "gitVersion": "git version 2.43.0",
            "linuxDescendantControl": "subreaper-procfs-pidfd",
            "lockedGitMergeDriverSecretNondisclosure": True,
            "harnessFiles": [
                {"name": name, "sha256": "a" * 64}
                for name in lifecycle.LIFECYCLE_HARNESS_FILES
            ],
            "harnessSource": dict(source),
            "markdownFiles": 5,
            "maxMarkdownBytes": lifecycle.MAX_MARKDOWN_BYTES,
            "nativePlatform": "linux-x64",
            "nativeRuntime": {
                "machine": "x86_64",
                "release": "test-kernel",
                "system": "Linux",
            },
            "notCovered": list(lifecycle.LIFECYCLE_REPORT_NOT_COVERED),
            "importedVaultPhysicalAllowlistVerified": True,
            "pythonVersion": "3.13.14",
            "releaseLifecycleDrill": "passed",
            "reportScope": "lifecycle-only-non-release-approval",
            "releaseVersion": "0.1.0",
            "releaseSetAudit": release_set_audit,
            "rpcAuthFailureSecretNondisclosure": True,
            "restoredDriverReinstalled": True,
            "sourceHashesUnchanged": True,
            "sourceDirectorySetUnchanged": True,
            "historicalPasswordScopeVerified": True,
            "trustAssumptions": list(lifecycle.LIFECYCLE_REPORT_TRUST_ASSUMPTIONS),
        }

    def test_strict_base64url_requires_unpadded_canonical_input(self) -> None:
        self.assertEqual(strict_base64url_decode("YmluYXJ5AA", "test"), b"binary\0")
        for value in ("YmluYXJ5AA==", "YmluYXJ5AA%", "A"):
            with self.subTest(value=value), self.assertRaises(ReleaseError):
                strict_base64url_decode(value, "test")

    def test_lifecycle_report_is_exact_canonical_and_scans_itself(self) -> None:
        report = self.valid_lifecycle_report()
        lifecycle.validate_lifecycle_report(report)
        encoded = lifecycle.encode_lifecycle_report(report)
        self.assertEqual(json.loads(encoded), report)

        for field, value, message in (
            ("schemaVersion", True, "schema version"),
            ("covered", [], "scope metadata"),
            ("notCovered", [], "scope metadata"),
            ("auditedArtifactCount", 2, "artifact count"),
        ):
            invalid = dict(report)
            invalid[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ReleaseError, message):
                lifecycle.validate_lifecycle_report(invalid)
        unknown = dict(report)
        unknown["unexpected"] = True
        with self.assertRaisesRegex(ReleaseError, "root schema"):
            lifecycle.validate_lifecycle_report(unknown)

        mismatched_digest = json.loads(json.dumps(report))
        mismatched_digest["auditedArtifacts"][0]["sha256"] = "e" * 64
        with self.assertRaisesRegex(ReleaseError, "artifact hashes differ"):
            lifecycle.validate_lifecycle_report(mismatched_digest)

        bool_zero = dict(report)
        bool_zero["sensitiveResidueHitsOutsideDesignatedPlaintextSource"] = False
        with self.assertRaisesRegex(ReleaseError, "counts or exclusions"):
            lifecycle.validate_lifecycle_report(bool_zero)

        wrong_harness = json.loads(json.dumps(report))
        wrong_harness["harnessFiles"][0]["name"] = "scripts/not-the-harness.py"
        wrong_harness["harnessFiles"].sort(key=lambda record: record["name"])
        with self.assertRaisesRegex(ReleaseError, "harness file set"):
            lifecycle.validate_lifecycle_report(wrong_harness)

        secret = b"dynamic-report-secret-0123456789"
        secret_report = dict(report)
        secret_report["filesystemType"] = secret.decode("ascii")
        with self.assertRaisesRegex(ReleaseError, "lifecycle evidence report"):
            lifecycle.encode_lifecycle_report(
                secret_report, sensitive_variants((secret,))
            )

    def test_sensitive_scan_covers_chunk_boundaries_and_utf16(self) -> None:
        secret = b"dynamic-lifecycle-secret"
        needles = sensitive_variants((secret,))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            crossing = root / "crossing.bin"
            crossing.write_bytes(b"x" * (SCAN_CHUNK_BYTES - 3) + secret + b"tail")
            self.assertTrue(file_contains_any(crossing, needles))
            crossing.write_bytes("dynamic-lifecycle-secret".encode("utf-16-le"))
            with self.assertRaisesRegex(ReleaseError, "audited disk root"):
                scan_for_sensitive_data((root,), needles)

    def test_sensitive_variants_cover_ensure_ascii_json_escaping(self) -> None:
        secret = "非秘密\"\\换行\n".encode("utf-8")
        encoded = json.dumps(
            {"value": secret.decode("utf-8")}, ensure_ascii=True, sort_keys=True
        ).encode("ascii")
        self.assertTrue(any(needle in encoded for needle in sensitive_variants((secret,))))

    def test_sensitive_scan_covers_base64_stream_alignments_and_path_names(self) -> None:
        secret = b"alignment-sensitive-secret-0123456789"
        needles = sensitive_variants((secret,))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            encoded = root / "encoded.bin"
            for preceding in range(3):
                value = b"x" * preceding + secret + b"suffix"
                for encoder in (base64.b64encode, base64.urlsafe_b64encode):
                    encoded.write_bytes(encoder(value).rstrip(b"="))
                    with self.subTest(preceding=preceding, encoder=encoder.__name__):
                        self.assertTrue(file_contains_any(encoded, needles))
            encoded.unlink()
            secret_directory = root / secret.decode("ascii")
            secret_directory.mkdir()
            (secret_directory / "empty.bin").write_bytes(b"")
            with self.assertRaisesRegex(ReleaseError, "path component"):
                scan_for_sensitive_data((root,), needles)

    def test_plaintext_markdown_name_is_rejected_even_when_empty(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "empty.md").write_bytes(b"")
            with self.assertRaisesRegex(ReleaseError, "plaintext Markdown"):
                assert_no_plaintext_markdown(root)

    def test_exact_auth_failure_contract_is_required(self) -> None:
        valid = {
            "jsonrpc": "2.0",
            "id": 2,
            "error": {
                "code": -32_000,
                "message": "Authentication failed",
                "data": {"name": "AUTH_FAILED"},
            },
        }
        self.assertTrue(is_auth_failed_response(valid))
        for invalid in (
            {**valid, "id": True},
            {**valid, "id": 3},
            {
                **valid,
                "error": {**valid["error"], "code": -32_001},
            },
            {
                **valid,
                "error": {
                    **valid["error"],
                    "data": {"name": "VAULT_INVALID"},
                },
            },
            {**valid, "result": {}},
        ):
            with self.subTest(invalid=invalid):
                self.assertFalse(is_auth_failed_response(invalid))

    def test_expected_tree_includes_every_parent_and_file(self) -> None:
        self.assertEqual(
            expected_tree_entries({"a/b/c.md": b"x", "root.md": b""}),
            {
                ("directory", "a"),
                ("directory", "a/b"),
                ("file", "a/b/c.md"),
                ("file", "root.md"),
            },
        )

    def test_environment_isolates_temp_and_windows_profile_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "environment"
            environment = controlled_environment(root)
            self.assertEqual(environment["TMP"], environment["TEMP"])
            self.assertEqual(environment["TMP"], environment["TMPDIR"])
            for name in ("HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "TMPDIR"):
                self.assertTrue(Path(environment[name]).is_dir())
                self.assertTrue(Path(environment[name]).is_relative_to(root))

    def test_driver_shell_quote_matches_single_word_contract(self) -> None:
        self.assertEqual(shell_quote("/tmp/it's path/inex"), "'/tmp/it'\\''s path/inex'")

    def test_driver_verifier_rejects_percent_placeholder_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            cli = Path(directory) / "%A" / "inex"
            cli.parent.mkdir()
            cli.write_bytes(b"binary")
            result = subprocess.CompletedProcess(
                [],
                0,
                (shell_quote(str(cli.resolve())) + " merge-driver\n").encode(),
                b"",
            )
            with mock.patch.object(
                lifecycle, "git_command", return_value=result
            ), self.assertRaisesRegex(ReleaseError, "placeholder marker"):
                verify_driver_configuration(
                    Path("git"),
                    Path("repository"),
                    cli,
                    environment={"TMPDIR": "."},
                    needles=(),
                )

    def test_failure_evidence_is_retained_until_explicit_cleanup(self) -> None:
        evidence: Path | None = None
        with self.assertRaises(RuntimeError), contextlib.redirect_stderr(io.StringIO()):
            with EvidenceDirectory() as directory:
                evidence = directory
                (directory / "ciphertext").write_bytes(b"EDRY")
                raise RuntimeError("synthetic failure")
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertTrue((evidence / "ciphertext").is_file())
        shutil.rmtree(evidence)

    def test_tampered_fixture_path_is_rejected_before_destination_creation(self) -> None:
        repository_fixture = Path(__file__).resolve().parents[2] / "fixtures" / "v1-fixed"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            shutil.copytree(repository_fixture, fixture)
            vector_path = fixture / "vector.json"
            vector = json.loads(vector_path.read_text(encoding="utf-8"))
            vector["logicalPath"] = "../../escape.md"
            vector_path.write_text(json.dumps(vector), encoding="utf-8")
            destination = root / "destination"
            with self.assertRaisesRegex(ReleaseError, "identity"):
                prepare_frozen_v1_fixture(fixture, destination)
            self.assertFalse(destination.exists())
            self.assertFalse((root / "escape.md.enc").exists())

    def test_fixture_swap_during_capture_is_rejected(self) -> None:
        repository_fixture = Path(__file__).resolve().parents[2] / "fixtures" / "v1-fixed"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            shutil.copytree(repository_fixture, fixture)
            destination = root / "destination"
            real_read = lifecycle.read_bounded_regular_file
            swapped = False

            def read_and_swap(path: Path, limit: int) -> bytes:
                nonlocal swapped
                content = real_read(path, limit)
                if path.name == "document.md.enc.b64" and not swapped:
                    swapped = True
                    (path.parent / "vault.json").write_bytes(b'{"swapped":true}')
                return content

            with mock.patch.object(
                lifecycle, "read_bounded_regular_file", side_effect=read_and_swap
            ), self.assertRaisesRegex(ReleaseError, "identity"):
                prepare_frozen_v1_fixture(fixture, destination)
            self.assertTrue(swapped)
            self.assertFalse(destination.exists())

    def test_fixture_capture_rejects_per_file_and_total_oversize(self) -> None:
        repository_fixture = Path(__file__).resolve().parents[2] / "fixtures" / "v1-fixed"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "per-file"
            shutil.copytree(repository_fixture, fixture)
            with (fixture / "vector.json").open("wb") as handle:
                handle.truncate(FROZEN_V1_FILE_LIMITS["vector.json"] + 1)
            with self.assertRaisesRegex(ReleaseError, "oversized"):
                prepare_frozen_v1_fixture(fixture, root / "per-file-destination")

            fixture = root / "total"
            shutil.copytree(repository_fixture, fixture)
            with (fixture / "document.md.enc.b64").open("wb") as handle:
                handle.truncate(FROZEN_V1_FILE_LIMITS["document.md.enc.b64"])
            with (fixture / "vector.json").open("wb") as handle:
                handle.truncate(FROZEN_V1_FILE_LIMITS["vector.json"])
            self.assertGreater(
                sum(path.stat().st_size for path in fixture.iterdir()),
                FROZEN_V1_MAX_TOTAL_BYTES,
            )
            with self.assertRaisesRegex(ReleaseError, "total size ceiling"):
                prepare_frozen_v1_fixture(fixture, root / "total-destination")

    def test_fixture_capture_rejects_extra_entry(self) -> None:
        repository_fixture = Path(__file__).resolve().parents[2] / "fixtures" / "v1-fixed"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture = root / "fixture"
            shutil.copytree(repository_fixture, fixture)
            (fixture / "unexpected.txt").write_bytes(b"unexpected")
            destination = root / "destination"
            with self.assertRaisesRegex(ReleaseError, "exactly four reviewed files"):
                prepare_frozen_v1_fixture(fixture, destination)
            self.assertFalse(destination.exists())

    def test_artifact_snapshot_rejects_oversized_input_before_hashing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "SHA256SUMS").write_text("placeholder\n", encoding="ascii")
            (source / "inex-vscode-0.1.0-linux-x64.vsix").write_bytes(b"v")
            (source / "inex-sublime-0.1.0-linux-x64.zip").write_bytes(b"s")
            oversized = source / "inex-rust-0.1.0-linux-x64.zip"
            with oversized.open("wb") as handle:
                handle.truncate(MAX_ARCHIVE_TOTAL_BYTES + 1)
            with self.assertRaisesRegex(ReleaseError, "oversized"):
                snapshot_artifact_directory(source, root / "snapshot")

    def test_artifact_snapshot_rechecks_size_during_actual_capture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "SHA256SUMS").write_bytes(b"s")
            for name in (
                "inex-vscode-0.1.0-linux-x64.vsix",
                "inex-sublime-0.1.0-linux-x64.zip",
                "inex-rust-0.1.0-linux-x64.zip",
            ):
                (source / name).write_bytes(b"x")
            real_copy = lifecycle.copy_bounded_regular_file
            mutated = False

            def mutate_before_copy(path: Path, destination: Path, limit: int) -> int:
                nonlocal mutated
                if path.name.startswith("inex-") and not mutated:
                    mutated = True
                    path.write_bytes(b"x" * 9)
                return real_copy(path, destination, limit)

            with mock.patch.object(
                lifecycle, "MAX_ARCHIVE_TOTAL_BYTES", 8
            ), mock.patch.object(
                lifecycle,
                "copy_bounded_regular_file",
                side_effect=mutate_before_copy,
            ), self.assertRaisesRegex(ReleaseError, "oversized"):
                snapshot_artifact_directory(source, root / "snapshot")
            self.assertTrue(mutated)

    def test_snapshot_rejects_links_and_detects_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file").write_bytes(b"before")
            before = snapshot_regular_tree(root)
            (root / "file").write_bytes(b"after")
            self.assertNotEqual(snapshot_regular_tree(root), before)
            try:
                (root / "link").symlink_to(root / "file")
            except OSError:
                self.skipTest("symbolic links are unavailable")
            with self.assertRaises(ReleaseError):
                snapshot_regular_tree(root)

    def test_filesystem_snapshot_preserves_regular_files_and_empty_directories(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "empty").mkdir()
            (source / "nested").mkdir()
            (source / "nested" / "ciphertext").write_bytes(b"EDRY\0test")
            backup = root / "backup"
            copy_regular_tree(source, backup)
            self.assertTrue((backup / "empty").is_dir())
            self.assertEqual((backup / "nested" / "ciphertext").read_bytes(), b"EDRY\0test")

    def test_imported_vault_requires_exact_ciphertext_physical_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "vault"
            (root / ".vault-local").mkdir(parents=True)
            (root / "nested").mkdir()
            (root / "vault.json").write_bytes(b"{}")
            (root / ".vault-local" / "mutation.lock").write_bytes(b"")
            (root / "nested" / "entry.md.enc").write_bytes(b"EDRY\0ciphertext")
            expected = {"nested/entry.md": b"plaintext"}
            assert_imported_vault_physical_layout(root, expected)
            (root / "leak.bin").write_bytes(b"plaintext")
            with self.assertRaisesRegex(ReleaseError, "ciphertext allowlist"):
                assert_imported_vault_physical_layout(root, expected)

    def test_plaintext_fixture_normalizes_paths_and_hits_exact_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            expected = create_plaintext_source(source, b"canary", max_markdown_bytes=128)
            self.assertIn("unicode/é.md", expected)
            self.assertNotIn("unicode/e\u0301.md", expected)
            self.assertEqual(len(expected["maximum/boundary.md"]), 128)
            self.assertEqual(len(expected), 5)
            self.assertEqual((source / "empty.md").read_bytes(), b"")

    def test_plaintext_source_preservation_includes_empty_directories(self) -> None:
        secret = b"source-path-secret-0123456789"
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            (source / "entry.md").write_bytes(b"plaintext")
            files = snapshot_regular_tree(source)
            directories = lifecycle.directory_manifest(source)
            (source / secret.decode("ascii")).mkdir()
            with self.assertRaisesRegex(ReleaseError, "directory set"):
                assert_plaintext_source_preserved(
                    source,
                    files,
                    directories,
                    sensitive_variants((secret,)),
                )

    def test_harness_provenance_is_rechecked_after_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            harness = root / "harness.py"
            harness.write_bytes(b"stable")
            hashes = {"harness.py": lifecycle.sha256_file(harness)}
            initial = {
                "commit": "1" * 40,
                "dirtySourceTree": False,
                "repository": "https://github.com/JekYUlll/Inex",
            }
            changed = {**initial, "commit": "2" * 40}
            with mock.patch.object(
                lifecycle, "source_revision", return_value=changed
            ), self.assertRaisesRegex(ReleaseError, "provenance changed"):
                assert_harness_source_unchanged(root, hashes, initial)

    def test_frozen_product_check_allows_only_local_runtime_additions(self) -> None:
        before = {"vault.json": "a", "entry.md.enc": "b"}
        assert_frozen_product_unchanged(
            before,
            {**before, ".vault-local/mutation.lock": "c"},
        )
        with self.assertRaisesRegex(ReleaseError, "rewrote"):
            assert_frozen_product_unchanged(before, {"vault.json": "x", "entry.md.enc": "b"})
        with self.assertRaisesRegex(ReleaseError, "unexpected frozen-v1 runtime"):
            assert_frozen_product_unchanged(before, {**before, "unexpected": "c"})
        with self.assertRaisesRegex(ReleaseError, "unexpected frozen-v1 runtime"):
            assert_frozen_product_unchanged(
                before,
                {
                    **before,
                    ".vault-local/mutation.lock": "c",
                    ".vault-local/leak.bin": "d",
                },
            )

    def test_rpc_response_parser_accepts_only_canonical_bounded_frame(self) -> None:
        response = {"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}
        body = json.dumps(response, separators=(",", ":")).encode()
        framed = io.BufferedReader(
            io.BytesIO(f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        )
        self.assertEqual(read_rpc_response(framed, 7), response)
        for header in (
            b"content-length: 2\r\n\r\n{}",
            b"Content-Length: +2\r\n\r\n{}",
            b"Content-Length: 2\r\nOther: x\r\n\r\n{}",
        ):
            with self.subTest(header=header), self.assertRaises(ReleaseError):
                read_rpc_response(io.BufferedReader(io.BytesIO(header)), 7)

        invalid_bodies = (
            b'{"jsonrpc":"2.0","id":7,"id":7,"result":{}}',
            b'{"jsonrpc":"2.0","id":true,"result":{}}',
            b'{"jsonrpc":"2.0","id":7,"result":{},"extra":0}',
        )
        for invalid_body in invalid_bodies:
            framed = io.BufferedReader(
                io.BytesIO(
                    f"Content-Length: {len(invalid_body)}\r\n\r\n".encode()
                    + invalid_body
                )
            )
            with self.subTest(body=invalid_body), self.assertRaises(ReleaseError):
                read_rpc_response(framed, 7)

        response_text = '{"jsonrpc":"2.0","id":7,"result":{}}'
        for encoded_body in (
            response_text.encode("utf-16"),
            response_text.encode("utf-32"),
        ):
            framed = io.BufferedReader(
                io.BytesIO(
                    f"Content-Length: {len(encoded_body)}\r\n\r\n".encode()
                    + encoded_body
                )
            )
            with self.subTest(encoding=encoded_body[:4]), self.assertRaisesRegex(
                ReleaseError, "invalid RPC JSON"
            ):
                read_rpc_response(framed, 7)

        secret = b"forbidden-response-secret"
        secret_body = json.dumps(
            {"jsonrpc": "2.0", "id": 7, "result": {"echo": secret.decode()}},
            separators=(",", ":"),
        ).encode()
        framed = io.BufferedReader(
            io.BytesIO(
                f"Content-Length: {len(secret_body)}\r\n\r\n".encode()
                + secret_body
            )
        )
        with self.assertRaisesRegex(ReleaseError, "framed daemon response"):
            read_rpc_response(framed, 7, sensitive_variants((secret,)))

    @unittest.skipIf(os.name == "nt", "POSIX process-group regression")
    def test_run_process_kills_descendant_holding_output_pipes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            environment = controlled_environment(Path(directory) / "environment")
            program = (
                "import subprocess,sys;"
                "subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'],"
                "stdout=sys.stdout,stderr=sys.stderr)"
            )
            started = time.monotonic()
            result = run_process(
                [Path(sys.executable).resolve(), "-c", program],
                environment=environment,
                needles=(b"never-present-sensitive-value",),
                timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            self.assertLess(time.monotonic() - started, 10)

    @unittest.skipIf(os.name == "nt", "Linux subreaper regression")
    def test_run_process_kills_setsid_descendant_after_leader_exit(self) -> None:
        if sys.platform != "linux":
            self.skipTest("Linux procfs/pidfd regression")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = controlled_environment(root / "environment")
            marker = root / "escaped-pid"
            child_program = (
                "import os,pathlib,sys,time;"
                "os.setsid();"
                "pathlib.Path(sys.argv[1]).write_text(str(os.getpid()));"
                "time.sleep(60)"
            )
            parent_program = "\n".join(
                (
                    "import pathlib,subprocess,sys,time",
                    f"child_program = {child_program!r}",
                    "marker = pathlib.Path(sys.argv[1])",
                    "subprocess.Popen([sys.executable, '-c', child_program, str(marker)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)",
                    "deadline = time.monotonic() + 5",
                    "while not marker.exists() and time.monotonic() < deadline:",
                    "    time.sleep(0.01)",
                    "raise SystemExit(0 if marker.exists() else 2)",
                )
            )
            result = run_process(
                [Path(sys.executable).resolve(), "-c", parent_program, marker],
                environment=environment,
                needles=(b"never-present-sensitive-value",),
                timeout=10,
            )
            self.assertEqual(result.returncode, 0)
            escaped_pid = int(marker.read_text(encoding="ascii"))
            self.assertFalse(Path("/proc", str(escaped_pid)).exists())

    def test_verify_output_rejects_extra_or_contradictory_lines(self) -> None:
        valid_lines = [
            b"verification-mode: locked-structural",
            b"mutation-lock: acquired",
            b"pending-ciphertext-transaction: none",
            b"vault-metadata: structurally-valid-untrusted",
            b"directories: 2",
            b"documents: 1",
            b"weak-kdf-slots: 0",
            b"authenticated-content: not-performed",
            b"pending-git-merge-transaction: none",
            b"result: locked structure valid; unlock is required for authenticity",
        ]
        valid = subprocess.CompletedProcess([], 0, b"\n".join(valid_lines) + b"\n", b"")
        with mock.patch.object(lifecycle, "run_cli", return_value=valid):
            verify_locked_structure(
                Path("inex"),
                Path("vault"),
                environment={"TMPDIR": "."},
                needles=(),
            )
        invalid = subprocess.CompletedProcess(
            [], 0, b"\n".join([*valid_lines, b"authenticated-content: performed"]) + b"\n", b""
        )
        with mock.patch.object(lifecycle, "run_cli", return_value=invalid), self.assertRaisesRegex(
            ReleaseError, "not exact"
        ):
            verify_locked_structure(
                Path("inex"),
                Path("vault"),
                environment={"TMPDIR": "."},
                needles=(),
            )

    def test_single_commit_git_identity_rejects_hidden_refs_and_objects(self) -> None:
        git_path = shutil.which("git")
        if git_path is None:
            self.skipTest("Git unavailable")
        git = Path(git_path).resolve()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            environment = controlled_environment(root / "environment")
            repository = root / "repository"
            subprocess.run(
                [git, "init", "--initial-branch=main", repository],
                env=environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            (repository / "ciphertext").write_bytes(b"EDRY")
            commit_environment = {
                **environment,
                "GIT_AUTHOR_NAME": "test",
                "GIT_AUTHOR_EMAIL": "test@example.invalid",
                "GIT_COMMITTER_NAME": "test",
                "GIT_COMMITTER_EMAIL": "test@example.invalid",
            }
            subprocess.run(
                [git, "-C", repository, "add", "--all"],
                env=commit_environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            subprocess.run(
                [git, "-C", repository, "commit", "-m", "one"],
                env=commit_environment,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            head = assert_single_commit_repository(
                git,
                repository,
                environment=environment,
                needles=(),
            )
            subprocess.run(
                [git, "-C", repository, "update-ref", "refs/heads/hidden", head],
                env=environment,
                check=True,
            )
            with self.assertRaisesRegex(ReleaseError, "hidden"):
                assert_single_commit_repository(
                    git,
                    repository,
                    environment=environment,
                    needles=(),
                )
            subprocess.run(
                [git, "-C", repository, "update-ref", "-d", "refs/heads/hidden"],
                env=environment,
                check=True,
            )
            subprocess.run(
                [git, "-C", repository, "hash-object", "-w", "--stdin"],
                env=environment,
                input=b"unreachable plaintext",
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            with self.assertRaisesRegex(ReleaseError, "unreachable"):
                assert_single_commit_repository(
                    git,
                    repository,
                    environment=environment,
                    needles=(),
                )

    @unittest.skipIf(os.name == "nt", "Windows is rejected before source inspection")
    def test_lifecycle_evidence_rejects_dirty_harness_before_artifact_use(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "artifact"
            fixture = root / "fixture"
            artifact.mkdir()
            fixture.mkdir()
            revision = {
                "commit": "0" * 40,
                "dirtySourceTree": True,
                "repository": "https://github.com/horebese/inex",
            }
            with mock.patch.object(
                lifecycle, "source_revision", return_value=revision
            ), self.assertRaisesRegex(ReleaseError, "clean harness"):
                run_lifecycle_drill(artifact, fixture)


if __name__ == "__main__":
    unittest.main()
