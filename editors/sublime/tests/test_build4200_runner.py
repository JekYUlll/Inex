from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
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


def _digest(character: str) -> str:
    return character * 64


def _seal(name: str, digest: str, *, size: int, mode: int) -> dict:
    return {
        "name": name,
        "device": 1,
        "inode": len(name) + 100,
        "mode": mode,
        "linkCount": 1,
        "size": size,
        "mtimeNs": 10,
        "ctimeNs": 11,
        "sha256": digest,
    }


def _restart_token_fingerprints() -> list[dict]:
    return [
        {"byteCount": 47, "contentSha256": _digest("1")},
        {"byteCount": 50, "contentSha256": _digest("2")},
    ]


def _restart_token_fingerprint_digest() -> str:
    return runner.token_fingerprint_set_digest(
        (item["byteCount"], item["contentSha256"])
        for item in _restart_token_fingerprints()
    )


def _helper_observations(scenario: str) -> list[dict]:
    common = [
        {"event": "loaded", "build": "4200", "gate_ok": True, "issue_count": 0},
        {
            "event": "unlock_dispatched",
            "plugin_active": True,
            "in_progress": True,
        },
        {"event": "password_prompt_answered", "masked": True},
        {"event": "ui", "action": "select_tree"},
        {
            "event": "opened",
            "scratch": True,
            "unnamed": True,
            "initial_ok": True,
            "initial_clean": True,
            "byte_count": 10,
            "content_sha256": _digest("a"),
        },
        {
            "event": "saved",
            "persisted_shape": True,
            "scratch": True,
            "unnamed": True,
            "byte_count": 20,
            "content_sha256": _digest("b"),
        },
    ]
    if scenario == "plugin-host-crash":
        return common + [
            {
                "event": "plugin_host_crash_ready",
                "view_id": 7,
                "byte_count": 20,
                "content_sha256": _digest("b"),
                "marker": True,
            },
            {
                "event": "plugin_host_dead_clipboard_checked",
                "byte_count": 10,
                "content_sha256": _digest("a"),
                "same_length_and_hash": True,
                "host_dead_plaintext_copyable": True,
                "clipboard_read_ok": True,
                "selection_channel": "primary",
            },
            {
                "event": "plugin_host_restart_required",
                "documented_platform_boundary": True,
            },
        ]
    if scenario == "full-application-kill-restart":
        return common + [
            {
                "event": "full_application_restart_ready",
                "view_id": 7,
                "logical_path": "qa.md",
                "byte_count": 20,
                "content_sha256": _digest("b"),
                "marker": True,
                "state_written": True,
                "token_fingerprint_count": 2,
                "token_fingerprint_set_sha256": _restart_token_fingerprint_digest(),
            },
            {
                "event": "restart_loaded",
                "build": "4200",
                "gate_ok": True,
                "issue_count": 0,
            },
            {
                "event": "restart_preunlock_checked",
                "view_count": 0,
                "managed_count": 0,
                "client_present": False,
                "session_active": False,
                "vault_id_present": False,
                "vault_path_present": False,
                "unlock_in_progress": False,
                "pending_plaintext_count": 0,
                "handoff_count": 0,
                "scrubbing_count": 0,
                "fixed_scrub_ack_count": 0,
                "orphan_scrub_blocked": False,
                "marker_count": 0,
                "known_fingerprint_count": 0,
                "token_window_match_count": 0,
                "clean": True,
                "stable_duration_ms": 2000,
            },
            {
                "event": "restart_unlock_dispatched",
                "plugin_active": True,
                "in_progress": True,
            },
            {"event": "password_prompt_answered", "masked": True},
            {"event": "ui", "action": "select_tree_after_restart"},
            {
                "event": "restart_reopened",
                "scratch": True,
                "unnamed": True,
                "clean": True,
                "marker": True,
                "session_active": True,
                "logical_path_matches": True,
                "fingerprint_matches": True,
                "byte_count": 20,
                "content_sha256": _digest("b"),
            },
            {
                "event": "restart_closed",
                "managed_count": 0,
                "view_absent": True,
                "normal_close": True,
            },
            {"event": "complete", "restarted": True, "managed_count": 0},
        ]
    return common + [
        {"event": "ui", "action": "crud_new_folder"},
        {"event": "crud_folder_created", "exists": True},
        {"event": "ui", "action": "crud_new_markdown"},
        {
            "event": "crud_markdown_created",
            "clean": True,
            "scratch": True,
            "unnamed": True,
            "empty": True,
        },
        {"event": "ui", "action": "crud_rename"},
        {"event": "crud_markdown_renamed", "clean": True},
        {"event": "ui", "action": "crud_delete_confirm"},
        {"event": "crud_markdown_deleted", "absent": True},
        {"event": "minimal_complete", "managed_count": 0, "crud_complete": True},
        {"event": "complete", "managed_count": 0, "crud_complete": True},
    ]


def _valid_report(scenario: str = "normal") -> dict:
    artifact_source = {
        "commit": "1" * 40,
        "dirtySourceTree": False,
        "repository": "https://github.com/JekYUlll/Inex",
    }
    harness_source = {
        "commit": "2" * 40,
        "dirtySourceTree": False,
        "repository": "https://github.com/JekYUlll/Inex",
    }
    rust_manifest = {
        "schemaVersion": 1,
        "package": "rust-binaries",
        "platform": "linux-x64",
        "version": "0.1.0",
        "installFormat": "portable ZIP with bin/inex and bin/inexd",
        "source": artifact_source,
        "files": [
            {
                "path": "inex-0.1.0-linux-x64/bin/inex",
                "sha256": _digest("c"),
                "size": 3,
            },
            {
                "path": "inex-0.1.0-linux-x64/bin/inexd",
                "sha256": _digest("d"),
                "size": 4,
            },
        ],
    }
    sublime_manifest = {
        "schemaVersion": 1,
        "package": "sublime-unpacked-package",
        "platform": "linux-x64",
        "version": "0.1.0",
        "installFormat": "extract the Inex directory into the Sublime Text Packages directory",
        "source": artifact_source,
        "files": [
            {"path": "Inex/Inex.py", "sha256": _digest("b"), "size": 5},
            {"path": "Inex/bin/inexd", "sha256": _digest("d"), "size": 4},
        ],
    }
    manifest_bytes = {
        kind: (
            json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
        for kind, manifest in {
            "rust": rust_manifest,
            "sublime": sublime_manifest,
        }.items()
    }
    artifact_records = [
        {
            "name": "inex-rust-0.1.0-linux-x64.zip",
            "sha256": _digest("3"),
            "packageManifestSha256": runner.sha256_bytes(manifest_bytes["rust"]),
        },
        {
            "name": "inex-sublime-0.1.0-linux-x64.zip",
            "sha256": _digest("4"),
            "packageManifestSha256": runner.sha256_bytes(manifest_bytes["sublime"]),
        },
        {
            "name": "inex-vscode-0.1.0-linux-x64.vsix",
            "sha256": _digest("5"),
            "packageManifestSha256": _digest("8"),
        },
    ]
    checksum_bytes = "".join(
        f"{record['sha256']}  {record['name']}\n" for record in artifact_records
    ).encode("ascii")
    release_audit = {
        "schemaVersion": 1,
        "reportType": "inex-release-set-audit",
        "reportScope": "artifact-structure-cross-package-consistency-not-release-approval",
        "releaseVersion": "0.1.0",
        "platform": "linux-x64",
        "source": artifact_source,
        "artifactCount": 3,
        "artifacts": artifact_records,
        "cargoComponentCount": 1,
        "licenseTextCount": 1,
        "sharedLicenseInventorySha256": _digest("e"),
        "sharedCliSha256": _digest("c"),
        "sharedSidecarSha256": _digest("d"),
        "notCovered": [
            "artifact-signing-and-publication",
            "independent-legal-review",
            "native-runtime-install-and-editor-behavior",
        ],
        "trustAssumptions": [
            "artifact-directory-remains-stable-during-audit",
            "auditor-source-and-runtime-are-trusted",
        ],
    }
    materialized = [
        {
            "archiveKind": "rust",
            "memberName": "inex-0.1.0-linux-x64/bin/inex",
            "mode": 0o555,
            "size": 3,
            "sha256": _digest("c"),
        },
        {
            "archiveKind": "sublime",
            "memberName": "Inex/Inex.py",
            "mode": 0o644,
            "size": 5,
            "sha256": _digest("b"),
        },
        {
            "archiveKind": "sublime",
            "memberName": "Inex/PACKAGE-MANIFEST.json",
            "mode": 0o644,
            "size": len(manifest_bytes["sublime"]),
            "sha256": runner.sha256_bytes(manifest_bytes["sublime"]),
        },
        {
            "archiveKind": "sublime",
            "memberName": "Inex/bin/inexd",
            "mode": 0o555,
            "size": 4,
            "sha256": _digest("d"),
        },
    ]
    tree_files = [
        _seal("Inex.py", _digest("b"), size=5, mode=0o644),
        _seal(
            "PACKAGE-MANIFEST.json",
            runner.sha256_bytes(manifest_bytes["sublime"]),
            size=len(manifest_bytes["sublime"]),
            mode=0o644,
        ),
        _seal("bin/inexd", _digest("d"), size=4, mode=0o555),
    ]
    tree_digest = runner.sha256_bytes(
        json.dumps(
            tree_files,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    normalized = _helper_observations(scenario)
    normalized_bytes = json.dumps(
        normalized,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    events = [record["event"] for record in normalized]
    event_counts = {event: events.count(event) for event in sorted(set(events))}
    result_value = (
        "PASS_WITH_DOCUMENTED_BOUNDARY"
        if scenario == "plugin-host-crash"
        else "PASS"
    )
    tool_names = sorted(
        {"sublime-text", "zenity", "xdotool", "Xvfb", "dbus-daemon", "metacity", "xauth"}
        | ({"xclip"} if scenario == "plugin-host-crash" else set())
    )
    tools = [
        {
            "name": name,
            "path": "/opt/sublime_text/sublime_text"
            if name == "sublime-text"
            else "/usr/bin/" + name,
            "version": "Sublime Text Build 4200"
            if name == "sublime-text"
            else ("xdotool version 1" if name == "xdotool" else None),
            "seal": _seal(name, _digest("f"), size=5, mode=0o755),
        }
        for name in tool_names
    ]
    sidecar_seal = _seal("inexd", _digest("d"), size=4, mode=0o555)
    report = {
        "schemaVersion": 2,
        "reportType": "inex-sublime-build4200-evidence",
        "reportScope": runner.ARTIFACT_REPORT_SCOPE,
        "artifactSource": artifact_source,
        "harnessSource": harness_source,
        "harnessFiles": [
            {"name": name, "sha256": _digest("f")}
            for name in runner.ARTIFACT_HARNESS_FILES
        ],
        "helperReport": {
            "seal": _seal("control/report.jsonl", _digest("f"), size=100, mode=0o600),
            "recordCount": len(normalized),
            "eventCounts": event_counts,
            "normalizedSha256": runner.sha256_bytes(normalized_bytes),
            "normalizedObservations": normalized,
        },
        "releaseSetAudit": release_audit,
        "packageManifests": {
            "rust": rust_manifest,
            "sublime": sublime_manifest,
        },
        "releaseVersion": "0.1.0",
        "nativePlatform": "linux-x64",
        "scenario": scenario,
        "importProcess": {
            "exitStatus": 0,
            "stdoutBytes": 10,
            "stdoutSha256": _digest("a"),
            "stderrBytes": 0,
            "stderrSha256": runner.sha256_bytes(b""),
            "dynamicSensitiveOutput": False,
        },
        "build4200": {
            "build": "4200",
            "path": "/opt/sublime_text/sublime_text",
            "version": "Sublime Text Build 4200",
            "seal": next(tool["seal"] for tool in tools if tool["name"] == "sublime-text"),
        },
        "artifactSetFiles": [
            _seal(
                "SHA256SUMS",
                runner.sha256_bytes(checksum_bytes),
                size=len(checksum_bytes),
                mode=0o644,
            ),
            *[
                _seal(record["name"], record["sha256"], size=10, mode=0o644)
                for record in artifact_records
            ],
        ],
        "materializedMembers": materialized,
        "installedInexTree": {
            "directoryCount": 2,
            "fileCount": len(tree_files),
            "treeSha256": tree_digest,
            "files": tree_files,
        },
        "packagedExecutables": [
            {
                "product": "inex",
                "memberName": "inex-0.1.0-linux-x64/bin/inex",
                "productionResolution": "rust-portable-package",
                "seal": _seal("inex", _digest("c"), size=3, mode=0o555),
            },
            {
                "product": "inexd",
                "memberName": "Inex/bin/inexd",
                "productionResolution": "package-owned-default-empty-setting",
                "seal": sidecar_seal,
            },
        ],
        "tools": tools,
        "harnessRuntime": {"implementation": "CPython", "pythonVersion": "3.13.14"},
        "childEnvironmentPolicy": {
            "policy": "fixed-allowlist",
            "allowedVariables": sorted(runner.fixed_child_environment(Path("/unused"))),
            "explicitScenarioVariables": [
                "DBUS_SESSION_BUS_ADDRESS",
                "DISPLAY",
                "INEX_PASSWORD_STDIN",
                "XAUTHORITY",
            ],
            "removedCategories": ["GIT", "INEX-nonessential", "LD", "proxy", "PYTHON"],
        },
        "x11Isolation": {
            "authentication": "isolated-root-xauthority-cookie",
            "tcpListening": False,
            "dbusAddress": "isolated-root-runtime-path",
        },
        "residueScan": {
            "roots": ["isolated-root"],
            "excludedRoots": [],
            "pathScope": "all-relative-path-components",
            "contentScope": "all-nonlink-regular-files-fail-closed",
            "encodings": list(runner.SCAN_ENCODINGS),
            "randomFilenameCanaryScanned": True,
            "entropyFragmentsScanned": True,
            "entropyFragmentMinimumCharacters": 16,
            "hits": 0,
        },
        "scenarioResult": {
            "scenario": scenario,
            "result": result_value,
            "events": events,
            "rootScanHits": 0,
            "vaultEnvelope": "EDRY",
            "crudComplete": scenario == "normal",
            "pluginHostRestarted": None if scenario == "normal" else False,
            "sublimeRestartRequired": None if scenario == "normal" else True,
            "hostDeadPlaintextCopyable": None if scenario == "normal" else True,
            "hostDeadClipboardReadOk": None if scenario == "normal" else True,
            "packagedSidecarObserved": True,
            "packagedSidecarMatchCount": 1,
            "packagedSidecarExeSeal": sidecar_seal,
        },
        "reportProtection": "create-new-posix-mode-0600",
        "rootDeletionVerified": True,
        "notCovered": runner.report_not_covered(scenario, result_value),
        "trustAssumptions": list(runner.REPORT_TRUST_ASSUMPTIONS),
    }
    if scenario == "full-application-kill-restart":
        restart_environment = runner.restart_child_environment(Path("/private"))
        isolated_environment = {
            key: restart_environment[key]
            for key in runner.PROCESS_IDENTITY_ENVIRONMENT_KEYS
        }
        environment_digest = runner.sha256_bytes(
            json.dumps(
                isolated_environment,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        )
        profile_path = "/private/config/sublime-text"
        sidecar_path = profile_path + "/Packages/Inex/bin/inexd"
        report["childEnvironmentPolicy"]["allowedVariables"] = sorted(
            restart_environment
        )
        report["x11Isolation"].update(
            {
                "gtkUsePortal": "0",
                "dbusServiceActivation": "disabled-private-config",
            }
        )
        main_seal = copy.deepcopy(report["build4200"]["seal"])
        main_seal["name"] = "sublime-main"
        first_sidecar_seal = copy.deepcopy(sidecar_seal)
        first_sidecar_seal["name"] = "packaged-inexd"
        plugin_seal = _seal(
            "plugin-host-3.8", _digest("7"), size=7, mode=0o755
        )

        def identity(
            role: str,
            pid: int,
            session_id: int,
            executable_path: str,
            executable_seal: dict,
        ) -> dict:
            return {
                "role": role,
                "pid": pid,
                "parentPid": 1,
                "processGroupId": session_id,
                "sessionId": session_id,
                "startTimeTicks": pid * 10,
                "commandSha256": _digest("6"),
                "environmentBindingSha256": environment_digest,
                "isolatedEnvironmentBound": True,
                "executablePath": executable_path,
                "executableSeal": copy.deepcopy(executable_seal),
            }

        first_identities = [
            identity(
                "sublime-main",
                101,
                100,
                "/opt/sublime_text/sublime_text",
                main_seal,
            ),
            identity(
                "plugin-host-3.8",
                102,
                100,
                "/opt/sublime_text/plugin_host-3.8",
                plugin_seal,
            ),
            identity(
                "packaged-inexd",
                103,
                100,
                sidecar_path,
                first_sidecar_seal,
            ),
        ]
        second_identities = copy.deepcopy(first_identities)
        for offset, record in enumerate(second_identities, start=1):
            record["pid"] = 200 + offset
            record["processGroupId"] = 200
            record["sessionId"] = 200
            record["startTimeTicks"] = (200 + offset) * 10
        state_binding = {
            "schemaVersion": 1,
            "phase": "await_full_application_restart",
            "logicalPath": "qa.md",
            "opened": {"byteCount": 10, "contentSha256": _digest("a")},
            "saved": {"byteCount": 20, "contentSha256": _digest("b")},
            "tokenFingerprints": _restart_token_fingerprints(),
            "tokenFingerprintSetSha256": _restart_token_fingerprint_digest(),
            "plaintextFieldsAbsent": True,
        }
        state_value = {
            "schema_version": 1,
            "phase": "await_full_application_restart",
            "logical_path": "qa.md",
            "opened_byte_count": 10,
            "opened_content_sha256": _digest("a"),
            "saved_byte_count": 20,
            "saved_content_sha256": _digest("b"),
            "token_fingerprints": [
                {"byte_count": 47, "content_sha256": _digest("1")},
                {"byte_count": 50, "content_sha256": _digest("2")},
            ],
        }
        state_bytes = (
            json.dumps(state_value, ensure_ascii=True, sort_keys=True) + "\n"
        ).encode("utf-8")
        checkpoint_scan = copy.deepcopy(report["residueScan"])
        checkpoint_scan["roots"] = [
            "isolated-root-after-sigkill-before-second-launch"
        ]
        report.update(
            {
                "schemaVersion": 4,
                "reportScope": runner.RESTART_ARTIFACT_REPORT_SCOPE,
                "scenarioResult": {
                    "scenario": scenario,
                    "result": "PASS",
                    "events": events,
                    "rootScanHits": 0,
                    "vaultEnvelope": "EDRY",
                    "packagedSidecarObserved": True,
                    "packagedSidecarMatchCount": 2,
                    "packagedSidecarExeSeal": sidecar_seal,
                    "applicationRestarted": True,
                    "sameProfileAndInstalledPackage": True,
                    "oldProcessIdentitiesDead": True,
                    "preUnlockClean": True,
                    "reopenedFingerprintMatches": True,
                    "normalCloseComplete": True,
                },
                "restartLifecycle": {
                    "launchCount": 2,
                    "sameProfilePath": True,
                    "sameInstalledPackageTree": True,
                    "childSubreaperConfirmed": True,
                    "processClosurePolicy": {
                        "stablePidfdIdentity": True,
                        "sessionAndDescendantClosure": True,
                        "subreaperAdoptionSweep": True,
                        "rootBindingSources": [
                            "cwd",
                            "environment",
                            "exe",
                            "fd",
                            "root",
                        ],
                        "argvOnlyIsNotBinding": True,
                        "unverifiedRootBoundSurvivors": 0,
                    },
                    "mountPolicy": {
                        "source": "/proc/self/mountinfo",
                        "boundedParser": True,
                        "checkpointRootMounts": 0,
                        "finalRootMounts": 0,
                        "successPathUnmounts": False,
                        "failurePortalUnmount": "exact-dead-fuse.portal-non-lazy-only",
                    },
                    "signalDelivery": "pidfd-per-stable-session-descendant-closure",
                    "killSignal": "SIGKILL",
                    "killedProcessClosureCount": 4,
                    "isolatedEnvironment": isolated_environment,
                    "profileDirectoryBindings": [
                        {
                            "device": 1,
                            "inode": 99,
                            "mode": 0o700,
                            "path": profile_path,
                            "pathSha256": runner.sha256_bytes(
                                profile_path.encode("utf-8")
                            ),
                        },
                        {
                            "device": 1,
                            "inode": 99,
                            "mode": 0o700,
                            "path": profile_path,
                            "pathSha256": runner.sha256_bytes(
                                profile_path.encode("utf-8")
                            ),
                        },
                    ],
                    "installedPackageTreeSha256ByLaunch": [
                        tree_digest,
                        tree_digest,
                    ],
                    "canaryFingerprintSetSha256": _restart_token_fingerprint_digest(),
                    "pluginHostExecutable": {
                        "path": "/opt/sublime_text/plugin_host-3.8",
                        "seal": plugin_seal,
                    },
                    "firstLaunchProcessIdentities": first_identities,
                    "oldProcessIdentitiesDead": True,
                    "checkpoint": {
                        "stateSeal": _seal(
                            "control/state.json",
                            runner.sha256_bytes(state_bytes),
                            size=len(state_bytes),
                            mode=0o600,
                        ),
                        "stateBinding": state_binding,
                        "runtimeAndSocketsStopped": True,
                        "residueScan": checkpoint_scan,
                    },
                    "secondLaunchProcessIdentities": second_identities,
                    "secondLaunchIdentitiesDistinct": True,
                },
            }
        )
    return report


class Build4200RunnerFoundationTests(unittest.TestCase):
    @unittest.skipUnless(
        sys.platform == "linux" and hasattr(os, "pidfd_open"),
        "Linux subreaper and pidfd regression",
    )
    def test_verified_closure_kills_real_setsid_daemon_escape(self) -> None:
        runner.enable_and_verify_child_subreaper()
        daemon_pid = None
        launcher = None
        observed = {}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected_environment = runner.expected_root_environment(root)
            for value in expected_environment.values():
                Path(value).mkdir(parents=True, exist_ok=True)
            environment = {
                "PATH": "/usr/bin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                **expected_environment,
            }
            script = """
import os
import signal
import time

signal.signal(signal.SIGCHLD, signal.SIG_IGN)
normal = []
for _index in range(2):
    pid = os.fork()
    if pid == 0:
        time.sleep(60)
        os._exit(0)
    normal.append(pid)
daemonizer = os.fork()
if daemonizer == 0:
    os.setsid()
    daemon = os.fork()
    if daemon > 0:
        os._exit(0)
    print("daemon:%d" % os.getpid(), flush=True)
    time.sleep(60)
    os._exit(0)
for pid in normal:
    print("normal:%d" % pid, flush=True)
time.sleep(60)
"""
            launcher = subprocess.Popen(
                [sys.executable, "-u", "-c", script],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
            try:
                deadline = time.monotonic() + 5
                while len(observed.get("normal", [])) < 2 or "daemon" not in observed:
                    if time.monotonic() >= deadline:
                        self.fail("setsid regression children did not start")
                    line = launcher.stdout.readline().strip()
                    if not line:
                        continue
                    kind, raw_pid = line.split(":", 1)
                    if kind == "normal":
                        observed.setdefault(kind, []).append(int(raw_pid))
                    else:
                        observed[kind] = int(raw_pid)
                daemon_pid = observed["daemon"]
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    try:
                        if runner.process_snapshot(daemon_pid).parent_pid == os.getpid():
                            break
                    except runner.QaFailure:
                        pass
                    time.sleep(0.02)
                else:
                    self.fail("setsid daemon was not adopted by the test subreaper")

                role_pids = [launcher.pid, *observed["normal"]]
                identities = []
                for index, pid in enumerate(role_pids):
                    snapshot = runner.process_snapshot(pid)
                    executable = (Path("/proc") / str(pid) / "exe").stat()
                    identities.append(
                        {
                            "role": "test-%d" % index,
                            "pid": pid,
                            "parentPid": snapshot.parent_pid,
                            "processGroupId": snapshot.process_group_id,
                            "sessionId": snapshot.session_id,
                            "startTimeTicks": snapshot.start_time_ticks,
                            "executableSeal": {
                                "device": executable.st_dev,
                                "inode": executable.st_ino,
                            },
                        }
                    )
                killed = runner.kill_verified_application_session(
                    identities,
                    launcher,
                    root,
                    expected_environment,
                    (),
                )
                self.assertGreaterEqual(killed, 4)
                self.assertFalse((Path("/proc") / str(daemon_pid)).exists())
                self.assertEqual(
                    runner.stable_root_binding_census(
                        root, expected_environment
                    ),
                    (),
                )
            finally:
                if launcher.poll() is None:
                    launcher.kill()
                    launcher.wait(timeout=5)
                spawned_pids = list(observed.get("normal", []))
                if daemon_pid is not None:
                    spawned_pids.append(daemon_pid)
                for spawned_pid in spawned_pids:
                    try:
                        snapshot = runner.process_snapshot(spawned_pid)
                    except runner.QaFailure:
                        pass
                    else:
                        runner.terminate_process_snapshot(snapshot, 0.1)
                        try:
                            os.waitpid(spawned_pid, os.WNOHANG)
                        except ChildProcessError:
                            pass
                launcher.communicate(timeout=5)

    @unittest.skipUnless(sys.platform == "linux", "Linux procfs regression")
    def test_argv_root_mention_is_not_a_process_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected_environment = runner.expected_root_environment(root)
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    "import time; time.sleep(30)",
                    str(root / "mentioned-only"),
                ],
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                time.sleep(0.05)
                observations = runner.stable_root_binding_census(
                    root, expected_environment
                )
                self.assertNotIn(
                    process.pid,
                    {observation.snapshot.pid for observation in observations},
                )
                self.assertIn(str(root), "\0".join(runner.process_cmdline(process.pid)))
            finally:
                process.terminate()
                process.wait(timeout=5)

    @unittest.skipUnless(sys.platform == "linux", "Linux procfs regression")
    def test_procfs_census_binds_environment_cwd_and_open_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected_environment = runner.expected_root_environment(root)
            for value in expected_environment.values():
                Path(value).mkdir(parents=True, exist_ok=True)
            held_file = root / "held.bin"
            held_file.write_bytes(b"public")
            script = (
                "import os,sys,time; "
                "os.chdir(sys.argv[1]); "
                "handle=open(sys.argv[2], 'rb'); "
                "time.sleep(30)"
            )
            process = subprocess.Popen(
                [sys.executable, "-c", script, str(root), str(held_file)],
                env={
                    "PATH": "/usr/bin:/bin",
                    "LANG": "C.UTF-8",
                    **expected_environment,
                },
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                deadline = time.monotonic() + 5
                observation = None
                while time.monotonic() < deadline:
                    observation = next(
                        (
                            item
                            for item in runner.stable_root_binding_census(
                                root, expected_environment
                            )
                            if item.snapshot.pid == process.pid
                        ),
                        None,
                    )
                    if observation is not None:
                        break
                    time.sleep(0.02)
                self.assertIsNotNone(observation)
                self.assertTrue(
                    {"cwd", "environment", "fd"}.issubset(observation.sources)
                )
                self.assertEqual(
                    observation.environment_keys,
                    tuple(sorted(expected_environment)),
                )
            finally:
                process.terminate()
                process.wait(timeout=5)

    @unittest.skipUnless(sys.platform == "linux", "Linux procfs regression")
    def test_procfs_permission_denial_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock.patch.object(
                runner.os, "readlink", side_effect=PermissionError("denied")
            ):
                with self.assertRaisesRegex(
                    runner.QaFailure, "path binding is unavailable"
                ):
                    runner.capture_root_binding_observation(
                        os.getpid(), root, runner.expected_root_environment(root)
                    )

    def test_mountinfo_parser_is_bounded_and_decodes_paths(self) -> None:
        encoded = (
            b"36 31 0:65 / /tmp/inex\\040root/runtime/doc rw,nosuid,nodev "
            b"shared:642 - fuse.portal portal rw,user_id=1000,group_id=1000\n"
        )
        records = runner.parse_mountinfo(encoded)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].mount_point, "/tmp/inex root/runtime/doc")
        self.assertEqual(records[0].filesystem_type, "fuse.portal")
        self.assertEqual(records[0].mount_source, "portal")
        self.assertEqual(records[0].optional_fields, ("shared:642",))
        for malformed in (
            encoded.rstrip(b"\n"),
            encoded.replace(b"\\040", b"\\999"),
            b"36 31 malformed / /tmp rw - tmpfs tmpfs rw\n",
        ):
            with self.subTest(malformed=malformed), self.assertRaises(
                runner.QaFailure
            ):
                runner.parse_mountinfo(malformed)

        with mock.patch.object(runner.os, "open", return_value=91), mock.patch.object(
            runner.os, "read", side_effect=[encoded[:20], encoded[20:], b""]
        ), mock.patch.object(runner.os, "close") as close:
            self.assertEqual(runner.read_mountinfo(Path("/proc/test")), encoded)
            close.assert_called_once_with(91)

    def test_restart_environment_and_dbus_config_disable_portals(self) -> None:
        root = Path("/private/root")
        environment = runner.restart_child_environment(root)
        self.assertEqual(environment["GTK_USE_PORTAL"], "0")
        self.assertNotIn("GTK_USE_PORTAL", runner.fixed_child_environment(root))
        encoded = runner.private_dbus_config_bytes(
            root / "runtime" / "dbus-session-bus"
        )
        self.assertIn(
            b"<listen>unix:path=/private/root/runtime/dbus-session-bus</listen>",
            encoded,
        )
        self.assertNotIn(b"servicedir", encoded)
        self.assertNotIn(b"<include", encoded)

    def test_artifact_cleanup_never_hides_success_mounts(self) -> None:
        previous = runner._ACTIVE_ARTIFACT_ROOT
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir(mode=0o700)
                record = runner.MountInfoRecord(
                    mount_id=36,
                    parent_id=31,
                    major_minor="0:65",
                    root="/",
                    mount_point=str(root / "runtime" / "doc"),
                    mount_options="rw",
                    optional_fields=(),
                    filesystem_type="fuse.portal",
                    mount_source="portal",
                    super_options="rw",
                )
                runner._ACTIVE_ARTIFACT_ROOT = (root, root.lstat())
                with mock.patch.object(
                    runner, "stable_root_binding_census", return_value=()
                ), mock.patch.object(
                    runner, "root_mounts", return_value=(record,)
                ), mock.patch.object(
                    runner, "unmount_exact_dead_failure_portal"
                ) as unmount:
                    with self.assertRaisesRegex(runner.QaFailure, "retains a mount"):
                        runner.cleanup_active_artifact_root(
                            allow_dead_failure_portal_unmount=False
                        )
                    unmount.assert_not_called()
        finally:
            runner._ACTIVE_ARTIFACT_ROOT = previous

    def test_failure_cleanup_unmounts_only_exact_dead_portal(self) -> None:
        previous = runner._ACTIVE_ARTIFACT_ROOT
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                root.mkdir(mode=0o700)
                exact = runner.MountInfoRecord(
                    mount_id=36,
                    parent_id=31,
                    major_minor="0:65",
                    root="/",
                    mount_point=str(root / "runtime" / "doc"),
                    mount_options="rw",
                    optional_fields=(),
                    filesystem_type="fuse.portal",
                    mount_source="portal",
                    super_options="rw",
                )
                runner._ACTIVE_ARTIFACT_ROOT = (root, root.lstat())
                with mock.patch.object(
                    runner, "stable_root_binding_census", return_value=()
                ), mock.patch.object(
                    runner, "root_mounts", return_value=(exact,)
                ), mock.patch.object(
                    runner, "unmount_exact_dead_failure_portal"
                ) as unmount:
                    runner.cleanup_active_artifact_root(
                        allow_dead_failure_portal_unmount=True
                    )
                    unmount.assert_called_once_with(root, (exact,))
                    self.assertFalse(root.exists())

            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                unknown = runner.MountInfoRecord(
                    mount_id=37,
                    parent_id=31,
                    major_minor="0:66",
                    root="/",
                    mount_point=str(root / "other"),
                    mount_options="rw",
                    optional_fields=(),
                    filesystem_type="tmpfs",
                    mount_source="tmpfs",
                    super_options="rw",
                )
                with self.assertRaisesRegex(runner.QaFailure, "unknown or live"):
                    runner.unmount_exact_dead_failure_portal(root, (unknown,))
        finally:
            runner._ACTIVE_ARTIFACT_ROOT = previous

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

    def test_scenarios_are_mutually_exclusive(self) -> None:
        restart = runner.parse_arguments(["--full-application-kill-restart"])
        self.assertTrue(restart.full_application_kill_restart)
        self.assertFalse(restart.plugin_host_crash)
        with self.assertRaises(SystemExit):
            runner.parse_arguments(
                ["--plugin-host-crash", "--full-application-kill-restart"]
            )

    def test_restart_helper_contract_requires_stable_clean_preunlock(self) -> None:
        observations = _helper_observations("full-application-kill-restart")
        reconstructed = [
            dict(record, **({} if record["event"] == "password_prompt_answered" else {"time": 0.0}))
            for record in observations
        ]
        self.assertEqual(
            runner.normalize_helper_records(
                reconstructed, "full-application-kill-restart"
            ),
            observations,
        )
        for field, value in (
            ("clean", False),
            ("client_present", True),
            ("marker_count", 1),
            ("known_fingerprint_count", 1),
            ("token_window_match_count", 1),
            ("stable_duration_ms", 1900),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(reconstructed)
                next(
                    record
                    for record in candidate
                    if record["event"] == "restart_preunlock_checked"
                )[field] = value
                with self.assertRaises(runner.QaFailure):
                    runner.normalize_helper_records(
                        candidate, "full-application-kill-restart"
                    )

    def test_restart_checkpoint_state_is_canonical_and_observation_bound(self) -> None:
        content_tokens = ["INEXQA_INITIAL_" + "1" * 32, "INEXQA_EDIT_" + "2" * 32]
        observations = _helper_observations("full-application-kill-restart")
        token_pairs = sorted(
            (
                len(token.encode("utf-8")),
                runner.sha256_bytes(token.encode("utf-8")),
            )
            for token in content_tokens
        )
        next(
            record
            for record in observations
            if record["event"] == "full_application_restart_ready"
        )["token_fingerprint_set_sha256"] = runner.token_fingerprint_set_digest(
            token_pairs
        )
        state = {
            "schema_version": 1,
            "phase": "await_full_application_restart",
            "logical_path": "qa.md",
            "opened_byte_count": 10,
            "opened_content_sha256": _digest("a"),
            "saved_byte_count": 20,
            "saved_content_sha256": _digest("b"),
            "token_fingerprints": [
                {
                    "byte_count": byte_count,
                    "content_sha256": digest,
                }
                for byte_count, digest in token_pairs
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state.json"
            path.write_text(
                json.dumps(state, ensure_ascii=True, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            binding = runner.validate_restart_checkpoint_state(
                path, observations, content_tokens
            )
            self.assertEqual(binding["schemaVersion"], 1)
            self.assertTrue(binding["plaintextFieldsAbsent"])

            path.write_text(
                json.dumps(state, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(runner.QaFailure, "canonical"):
                runner.validate_restart_checkpoint_state(
                    path, observations, content_tokens
                )

    def test_report_validator_rejects_restart_lifecycle_mutations(self) -> None:
        baseline = _valid_report("full-application-kill-restart")
        runner.validate_artifact_report(baseline)

        def predecessor_v3_schema(report: dict) -> None:
            report["schemaVersion"] = 3

        def weaker_signal_delivery(report: dict) -> None:
            report["restartLifecycle"]["signalDelivery"] = "killpg"

        def portal_reenabled(report: dict) -> None:
            report["restartLifecycle"]["isolatedEnvironment"][
                "GTK_USE_PORTAL"
            ] = "1"

        def hidden_checkpoint_mount(report: dict) -> None:
            report["restartLifecycle"]["mountPolicy"][
                "checkpointRootMounts"
            ] = 1

        def profile_rebound(report: dict) -> None:
            report["restartLifecycle"]["profileDirectoryBindings"][1]["inode"] += 1

        def jointly_forged_profile_bindings(report: dict) -> None:
            for binding in report["restartLifecycle"]["profileDirectoryBindings"]:
                binding["device"] = 999
                binding["inode"] = 999
                binding["path"] = "/forged/profile"
                binding["pathSha256"] = runner.sha256_bytes(
                    binding["path"].encode("utf-8")
                )

        def package_tree_changed(report: dict) -> None:
            report["restartLifecycle"]["installedPackageTreeSha256ByLaunch"][1] = _digest("0")

        def plugin_host_rebound(report: dict) -> None:
            report["restartLifecycle"]["secondLaunchProcessIdentities"][1][
                "executableSeal"
            ]["inode"] += 1

        def non_newer_second_launch(report: dict) -> None:
            first = report["restartLifecycle"]["firstLaunchProcessIdentities"][0]
            second = report["restartLifecycle"]["secondLaunchProcessIdentities"][0]
            second["startTimeTicks"] = first["startTimeTicks"]

        def second_role_escaped_session(report: dict) -> None:
            report["restartLifecycle"]["secondLaunchProcessIdentities"][2][
                "sessionId"
            ] += 1

        def jointly_forged_sidecar_paths(report: dict) -> None:
            for identities in (
                report["restartLifecycle"]["firstLaunchProcessIdentities"],
                report["restartLifecycle"]["secondLaunchProcessIdentities"],
            ):
                identities[2]["executablePath"] = "/unrelated/forged/inexd"

        def forged_state_binding(report: dict) -> None:
            report["restartLifecycle"]["checkpoint"]["stateBinding"]["saved"][
                "contentSha256"
            ] = _digest("0")

        def forged_state_seal(report: dict) -> None:
            report["restartLifecycle"]["checkpoint"]["stateSeal"]["size"] += 1

        def jointly_forged_tokens_and_state_seal(report: dict) -> None:
            lifecycle = report["restartLifecycle"]
            binding = lifecycle["checkpoint"]["stateBinding"]
            binding["tokenFingerprints"] = [
                {"byteCount": 1, "contentSha256": _digest("3")},
                {"byteCount": 2, "contentSha256": _digest("4")},
            ]
            forged_digest = runner.token_fingerprint_set_digest(
                (token["byteCount"], token["contentSha256"])
                for token in binding["tokenFingerprints"]
            )
            binding["tokenFingerprintSetSha256"] = forged_digest
            lifecycle["canaryFingerprintSetSha256"] = forged_digest
            state_value = {
                "schema_version": binding["schemaVersion"],
                "phase": binding["phase"],
                "logical_path": binding["logicalPath"],
                "opened_byte_count": binding["opened"]["byteCount"],
                "opened_content_sha256": binding["opened"]["contentSha256"],
                "saved_byte_count": binding["saved"]["byteCount"],
                "saved_content_sha256": binding["saved"]["contentSha256"],
                "token_fingerprints": [
                    {
                        "byte_count": token["byteCount"],
                        "content_sha256": token["contentSha256"],
                    }
                    for token in binding["tokenFingerprints"]
                ],
            }
            encoded = (
                json.dumps(state_value, ensure_ascii=True, sort_keys=True) + "\n"
            ).encode("utf-8")
            lifecycle["checkpoint"]["stateSeal"]["size"] = len(encoded)
            lifecycle["checkpoint"]["stateSeal"]["sha256"] = (
                runner.sha256_bytes(encoded)
            )

        def checkpoint_residue(report: dict) -> None:
            report["restartLifecycle"]["checkpoint"]["residueScan"]["hits"] = 1

        def false_preunlock_result(report: dict) -> None:
            report["scenarioResult"]["preUnlockClean"] = False

        def only_one_sidecar_observation(report: dict) -> None:
            report["scenarioResult"]["packagedSidecarMatchCount"] = 1

        for mutation in (
            predecessor_v3_schema,
            weaker_signal_delivery,
            portal_reenabled,
            hidden_checkpoint_mount,
            profile_rebound,
            jointly_forged_profile_bindings,
            package_tree_changed,
            plugin_host_rebound,
            non_newer_second_launch,
            second_role_escaped_session,
            jointly_forged_sidecar_paths,
            forged_state_binding,
            forged_state_seal,
            jointly_forged_tokens_and_state_seal,
            checkpoint_residue,
            false_preunlock_result,
            only_one_sidecar_observation,
        ):
            with self.subTest(mutation=mutation.__name__):
                candidate = copy.deepcopy(baseline)
                mutation(candidate)
                with self.assertRaises(runner.QaFailure):
                    runner.validate_artifact_report(candidate)

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

    def test_report_validator_accepts_distinct_clean_sources_and_all_scenarios(self) -> None:
        for scenario in (
            "normal",
            "plugin-host-crash",
            "full-application-kill-restart",
        ):
            with self.subTest(scenario=scenario):
                report = _valid_report(scenario)
                self.assertNotEqual(
                    report["artifactSource"]["commit"],
                    report["harnessSource"]["commit"],
                )
                encoded = runner.encode_artifact_report(report)
                self.assertEqual(json.loads(encoded), report)

    def test_report_validator_rejects_cross_binding_and_schema_mutations(self) -> None:
        def duplicate_member(report: dict) -> None:
            report["materializedMembers"].append(
                copy.deepcopy(report["materializedMembers"][0])
            )

        def reverse_members(report: dict) -> None:
            report["materializedMembers"].reverse()

        def wrong_tree_digest(report: dict) -> None:
            report["installedInexTree"]["treeSha256"] = _digest("0")

        def wrong_sidecar_digest(report: dict) -> None:
            report["releaseSetAudit"]["sharedSidecarSha256"] = _digest("0")

        def wrong_cli_digest(report: dict) -> None:
            report["releaseSetAudit"]["sharedCliSha256"] = _digest("0")

        def missing_tool(report: dict) -> None:
            report["tools"].pop()

        def wrong_helper_digest(report: dict) -> None:
            report["helperReport"]["normalizedSha256"] = _digest("0")

        def extra_residue_field(report: dict) -> None:
            report["residueScan"]["unexpected"] = True

        def wrong_archive_digest(report: dict) -> None:
            report["artifactSetFiles"][1]["sha256"] = _digest("0")

        def wrong_checksum_manifest_digest(report: dict) -> None:
            report["artifactSetFiles"][0]["sha256"] = _digest("0")

        def omit_sublime_product_module(report: dict) -> None:
            report["materializedMembers"] = [
                record
                for record in report["materializedMembers"]
                if record["memberName"] != "Inex/Inex.py"
            ]
            tree = report["installedInexTree"]
            tree["files"] = [
                record for record in tree["files"] if record["name"] != "Inex.py"
            ]
            tree["fileCount"] = len(tree["files"])
            tree["treeSha256"] = runner.sha256_bytes(
                json.dumps(
                    tree["files"],
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
            )

        def arbitrary_cli_digest(report: dict) -> None:
            next(
                record
                for record in report["materializedMembers"]
                if record["archiveKind"] == "rust"
            )["sha256"] = _digest("0")
            next(
                record
                for record in report["packagedExecutables"]
                if record["product"] == "inex"
            )["seal"]["sha256"] = _digest("0")

        def extra_root_field(report: dict) -> None:
            report["unexpected"] = True

        def legacy_schema_version(report: dict) -> None:
            report["schemaVersion"] = 1

        mutations = (
            duplicate_member,
            reverse_members,
            wrong_tree_digest,
            wrong_cli_digest,
            wrong_sidecar_digest,
            missing_tool,
            wrong_helper_digest,
            extra_residue_field,
            wrong_archive_digest,
            wrong_checksum_manifest_digest,
            omit_sublime_product_module,
            arbitrary_cli_digest,
            extra_root_field,
            legacy_schema_version,
        )
        baseline = _valid_report()
        runner.validate_artifact_report(baseline)
        for mutation in mutations:
            with self.subTest(mutation=mutation.__name__):
                candidate = copy.deepcopy(baseline)
                mutation(candidate)
                with self.assertRaises(runner.QaFailure):
                    runner.validate_artifact_report(candidate)

    def test_report_validator_rejects_false_crash_boundary(self) -> None:
        baseline = _valid_report("plugin-host-crash")
        runner.validate_artifact_report(baseline)
        for field, value in (
            ("result", "PASS"),
            ("pluginHostRestarted", True),
            ("sublimeRestartRequired", False),
            ("hostDeadPlaintextCopyable", False),
            ("hostDeadClipboardReadOk", False),
            ("packagedSidecarMatchCount", 0),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(baseline)
                candidate["scenarioResult"][field] = value
                if field == "result":
                    candidate["notCovered"] = runner.report_not_covered(
                        "plugin-host-crash", value
                    )
                with self.assertRaises(runner.QaFailure):
                    runner.validate_artifact_report(candidate)

    def test_report_validator_rejects_self_attested_crash_ready_fingerprint(self) -> None:
        candidate = _valid_report("plugin-host-crash")
        forged_fingerprint = {"byte_count": 99, "content_sha256": _digest("a")}
        observations = candidate["helperReport"]["normalizedObservations"]
        for observation in observations:
            if observation["event"] in {
                "plugin_host_crash_ready",
                "plugin_host_dead_clipboard_checked",
            }:
                observation.update(forged_fingerprint)
        normalized_bytes = json.dumps(
            observations,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        candidate["helperReport"]["normalizedSha256"] = runner.sha256_bytes(
            normalized_bytes
        )
        with self.assertRaises(runner.QaFailure):
            runner.validate_artifact_report(candidate)


if __name__ == "__main__":
    unittest.main()
