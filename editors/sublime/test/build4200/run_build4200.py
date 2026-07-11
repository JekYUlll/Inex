#!/usr/bin/env python3
"""Bounded Build 4200 isolated-profile smoke test for the Inex package."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


BUILD = "4200"
FLOW_TIMEOUT_SECONDS = 75


class QaFailure(RuntimeError):
    pass


def raise_on_termination(signum: int, _frame: object) -> None:
    raise QaFailure("received termination signal %d" % signum)


def run_checked(argv: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess:
    options = dict(kwargs)
    options.setdefault("check", True)
    options.setdefault("timeout", 20)
    return subprocess.run(list(argv), **options)


def wait_until(label: str, predicate, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise QaFailure("timed out: " + label)


def child_pids(parent: int) -> List[int]:
    result: List[int] = []
    frontier = [parent]
    while frontier:
        current = frontier.pop()
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                fields = (entry / "stat").read_text().split()
                ppid = int(fields[3])
            except (OSError, ValueError, IndexError, UnicodeError):
                continue
            pid = int(entry.name)
            if ppid == current and pid not in result:
                result.append(pid)
                frontier.append(pid)
    return result


def process_cmdline(pid: int) -> List[str]:
    try:
        raw = (Path("/proc") / str(pid) / "cmdline").read_bytes()
    except OSError:
        return []
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def sublime_multiinstance_pids(binary: Path) -> List[int]:
    matches: List[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        command = process_cmdline(int(entry.name))
        if command[:2] == [str(binary), "--multiinstance"]:
            matches.append(int(entry.name))
    return matches


def command_pids(executable_name: str, required_argument: str) -> List[int]:
    matches: List[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        command = process_cmdline(int(entry.name))
        if (
            command
            and Path(command[0]).name == executable_name
            and required_argument in command
        ):
            matches.append(int(entry.name))
    return matches


def ancestor_pids(pid: int) -> List[int]:
    ancestors: List[int] = []
    current = pid
    while current > 1:
        try:
            fields = (Path("/proc") / str(current) / "stat").read_text().split()
            parent = int(fields[3])
        except (OSError, ValueError, IndexError, UnicodeError):
            break
        if parent <= 1 or parent in ancestors:
            break
        ancestors.append(parent)
        current = parent
    return ancestors


def root_bound_pids(root: Path) -> List[int]:
    fragment = str(root)
    excluded = {os.getpid(), *ancestor_pids(os.getpid())}
    matches: List[int] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in excluded:
            continue
        command = process_cmdline(pid)
        if any(fragment in argument for argument in command):
            matches.append(pid)
    return matches


def terminate_pid(pid: Optional[int], grace: float = 2.0) -> None:
    if pid is None:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.05)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def terminate_sublime_tree(
    main_pid: Optional[int], launcher: Optional[subprocess.Popen], root: Path
) -> None:
    descendants = child_pids(main_pid) if main_pid is not None else []
    terminate_pid(main_pid, 0.5)
    for pid in reversed(descendants):
        terminate_pid(pid, 0.2)
    if launcher is not None:
        terminate_pid(launcher.pid, 0.2)
    for pid in root_bound_pids(root):
        terminate_pid(pid, 0.2)
    wait_until(
        "isolated Sublime process-tree cleanup",
        lambda: not root_bound_pids(root),
        5,
    )


def read_new_reports(path: Path, offset: int) -> Tuple[int, List[Dict[str, object]]]:
    if not path.exists():
        return offset, []
    with path.open("rb") as stream:
        stream.seek(offset)
        data = stream.read()
        new_offset = stream.tell()
    records: List[Dict[str, object]] = []
    for line in data.splitlines():
        try:
            value = json.loads(line.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            records.append(value)
    return new_offset, records


def append_report(path: Path, value: Dict[str, object]) -> None:
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)


def encoded_needles(tokens: Iterable[str]) -> List[Tuple[str, bytes]]:
    needles: List[Tuple[str, bytes]] = []
    for token in tokens:
        raw = token.encode("utf-8")
        needles.extend(
            [
                ("utf8", raw),
                ("utf16le", token.encode("utf-16le")),
                ("utf16be", token.encode("utf-16be")),
                ("hex", raw.hex().encode("ascii")),
                ("base64", base64.b64encode(raw)),
            ]
        )
    return needles


def scan_for_tokens(roots: Iterable[Path], tokens: Sequence[str]) -> List[str]:
    needles = encoded_needles(tokens)
    hits: List[str] = []
    for root in roots:
        if not root.exists():
            continue
        for path in [root] if root.is_file() else root.rglob("*"):
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            for _label, needle in needles:
                if needle.decode("ascii", "ignore") and needle.decode("ascii", "ignore") in path.name:
                    hits.append(str(path) + ":filename")
                    break
            try:
                overlap = max(len(needle) for _label, needle in needles) - 1
                tail = b""
                with path.open("rb") as stream:
                    while True:
                        chunk = stream.read(1024 * 1024)
                        if not chunk:
                            break
                        window = tail + chunk
                        found = next((label for label, needle in needles if needle in window), None)
                        if found is not None:
                            hits.append(str(path) + ":" + found)
                            break
                        tail = window[-overlap:] if overlap > 0 else b""
            except OSError:
                continue
    return sorted(set(hits))


def assert_ciphertext(vault: Path, tokens: Sequence[str]) -> None:
    documents = list(vault.rglob("*.md.enc"))
    if len(documents) != 1:
        raise QaFailure("expected exactly one encrypted Markdown document")
    data = documents[0].read_bytes()
    if not data.startswith(b"EDRY"):
        raise QaFailure("vault document does not start with EDRY")
    for token in tokens:
        if token.encode("utf-8") in data:
            raise QaFailure("vault document contains a plaintext QA token")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="retain the isolated root")
    parser.add_argument(
        "--plugin-host-crash",
        action="store_true",
        help="kill and restart the isolated Python 3.8 plugin host with plaintext open",
    )
    parser.add_argument("--root", type=Path, help="use an explicit empty test root")
    args = parser.parse_args()

    repo = Path(__file__).resolve().parents[4]
    sublime_binary = Path("/opt/sublime_text/sublime_text")
    xdotool = shutil.which("xdotool")
    xclip = shutil.which("xclip")
    xvfb = shutil.which("Xvfb")
    dbus_daemon = shutil.which("dbus-daemon")
    window_manager = shutil.which("metacity")
    inex = repo / "target" / "debug" / "inex"
    inexd = repo / "target" / "debug" / "inexd"
    for binary in (sublime_binary, inex, inexd):
        if not binary.is_file():
            raise QaFailure("missing executable: " + str(binary))
    if not xdotool or not xvfb or not dbus_daemon or not window_manager:
        raise QaFailure("Xvfb, xdotool, metacity, and dbus-daemon are required")
    if args.plugin_host_crash and not xclip:
        raise QaFailure("xclip is required for the plugin-host crash fallback probe")
    version = run_checked([str(sublime_binary), "--version"], capture_output=True, text=True).stdout
    if ("Build " + BUILD) not in version:
        raise QaFailure("Sublime Text Build 4200 is required")

    if args.root is not None:
        root = args.root.resolve()
        root.mkdir(parents=True, exist_ok=False)
    else:
        root = Path(tempfile.mkdtemp(prefix="inex-build4200-"))
    os.chmod(root, 0o700)
    print("isolated-root=" + str(root), flush=True)

    home = root / "home"
    config = root / "config"
    cache = root / "cache"
    runtime = root / "runtime"
    isolated_tmp = root / "tmp"
    control = root / "control"
    source = root / "plaintext-source"
    vault = root / "vault"
    for path in (home, config, cache, runtime, isolated_tmp, control, source):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)

    tokens = [
        "INEXQA_INITIAL_" + secrets.token_hex(16),
        "INEXQA_EDIT_" + secrets.token_hex(16),
    ]
    document = "# Build 4200 QA\n\nINITIAL_TOKEN: %s\nEDIT_TOKEN: %s\n" % tuple(tokens)
    (source / "qa.md").write_text(document, encoding="utf-8")
    password = secrets.token_hex(20)
    import_env = os.environ.copy()
    import_env.pop("SESSION_ID", None)
    import_env["INEX_PASSWORD_STDIN"] = "1"
    import_env.update(
        {
            "TMPDIR": str(isolated_tmp),
            "TMP": str(isolated_tmp),
            "TEMP": str(isolated_tmp),
        }
    )
    imported = run_checked(
        [str(inex), "import", str(source), str(vault)],
        env=import_env,
        input=(password + "\n" + password + "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )
    if imported.returncode != 0:
        raise QaFailure("vault import failed")
    shutil.rmtree(source)
    assert_ciphertext(vault, tokens)

    fake_zenity = control / "zenity"
    fake_zenity.write_text("#!/bin/sh\nprintf '%s\\n' '" + password + "'\n", encoding="utf-8")
    os.chmod(fake_zenity, 0o700)
    report = control / "report.jsonl"
    state = control / "state.json"
    write_json(state, {"phase": "initial"})
    bootstrap = control / "bootstrap.txt"
    bootstrap.touch()

    # Normal Build 4200 mode with a brand-new XDG data directory is the
    # deterministic isolated-profile path. Safe Mode intentionally clears
    # third-party packages at startup and does not reliably hot-load them.
    profile = config / "sublime-text"
    packages = profile / "Packages"
    user = packages / "User"
    user.mkdir(parents=True)
    write_json(
        user / "Preferences.sublime-settings",
        {
            "hot_exit": "disabled",
            "hot_exit_projects": False,
            "update_system_recent_files": False,
        },
    )
    write_json(
        user / "Inex.sublime-settings",
        {
            "vault_path": str(vault),
            "sidecar_path": str(inexd),
            "zenity_path": str(fake_zenity),
            "draft_debounce_ms": 100,
        },
    )
    write_json(
        user / "InexQA.sublime-settings",
        {
            "report_path": str(report),
            "state_path": str(state),
            "plugin_host_crash": args.plugin_host_crash,
        },
    )
    shutil.copytree(
        repo / "editors" / "sublime",
        packages / "Inex",
        ignore=shutil.ignore_patterns("test", "tests", "__pycache__", "*.pyc"),
    )
    qa_package = packages / "InexQA"
    qa_package.mkdir()
    shutil.copy2(Path(__file__).with_name("InexQA.py"), qa_package / "InexQA.py")
    shutil.copy2(repo / "editors" / "sublime" / ".python-version", qa_package / ".python-version")

    env = os.environ.copy()
    # This harness and every child emit only the explicit result records below.
    # Some orchestration shells define/echo SESSION_ID themselves; do not pass
    # that unrelated value into any Build 4200 subprocess.
    env.pop("SESSION_ID", None)
    env.update(
        {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_CACHE_HOME": str(cache),
            "XDG_RUNTIME_DIR": str(runtime),
            "TMPDIR": str(isolated_tmp),
            "TMP": str(isolated_tmp),
            "TEMP": str(isolated_tmp),
        }
    )
    display_number = 120 + (os.getpid() % 70)
    while Path("/tmp/.X11-unix/X%d" % display_number).exists():
        display_number += 1
    display = ":%d" % display_number
    xvfb_process: Optional[subprocess.Popen] = None
    window_manager_process: Optional[subprocess.Popen] = None
    sublime_process: Optional[subprocess.Popen] = None
    dbus_pid: Optional[int] = None
    sublime_main_pid: Optional[int] = None
    final_success = False
    flow_complete = False
    minimal_complete = False
    plugin_host_restarted = False
    plugin_host_checked = False
    plugin_host_restart_required = False
    host_dead_plaintext_copyable: Optional[bool] = None
    host_dead_clipboard_read_ok: Optional[bool] = None
    qa_window_id: Optional[str] = None
    crud_folder_created = False
    crud_markdown_created = False
    crud_markdown_renamed = False
    crud_markdown_deleted = False
    events: List[str] = []

    signal.signal(signal.SIGTERM, raise_on_termination)
    signal.signal(signal.SIGINT, raise_on_termination)

    try:
        dbus = run_checked(
            [dbus_daemon, "--session", "--fork", "--print-address=1", "--print-pid=1"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        dbus_lines = [line.strip() for line in dbus.stdout.splitlines() if line.strip()]
        if len(dbus_lines) < 2 or not dbus_lines[-1].isdigit():
            raise QaFailure("dbus-daemon did not return address and pid")
        env["DBUS_SESSION_BUS_ADDRESS"] = dbus_lines[0]
        dbus_pid = int(dbus_lines[-1])

        xvfb_process = subprocess.Popen(
            [xvfb, display, "-screen", "0", "1280x800x24", "-nolisten", "tcp", "-ac"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        env["DISPLAY"] = display
        wait_until("Xvfb", lambda: Path("/tmp/.X11-unix/X%d" % display_number).exists(), 5)
        window_manager_process = subprocess.Popen(
            [window_manager, "--sm-disable", "--replace"],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.5)
        if window_manager_process.poll() is not None:
            raise QaFailure("isolated metacity process failed to start")

        preexisting_sublime = set(sublime_multiinstance_pids(sublime_binary))
        sublime_process = subprocess.Popen(
            [
                str(sublime_binary),
                "--new-window",
                "--wait",
                str(bootstrap),
            ],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )

        def find_sublime_main() -> Optional[int]:
            # Build 4200 reparents the multiinstance process to PID 1 before
            # the --wait launcher returns.  Bind discovery to the exact new
            # PID set created after this isolated launch, never to an existing
            # user process.
            candidates = set(sublime_multiinstance_pids(sublime_binary)) - preexisting_sublime
            return next(iter(candidates)) if len(candidates) == 1 else None

        wait_until("Sublime main process", lambda: find_sublime_main() is not None, 10)
        sublime_main_pid = find_sublime_main()
        if sublime_main_pid is None:
            raise QaFailure("Sublime main process disappeared")
        def isolated_window_ids() -> List[str]:
            # Build 4200 may create a separate initial untitled top-level in a
            # fresh profile. The Quick Panel belongs to the window holding the
            # non-secret bootstrap file, so bind by that unique title instead
            # of a generic Sublime class/name query.
            found = subprocess.run(
                [xdotool, "search", "--onlyvisible", "--name", bootstrap.name],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=5,
            )
            if found.returncode != 0:
                return []
            return [line.strip() for line in found.stdout.splitlines() if line.strip()]

        offset = 0
        deadline = time.monotonic() + FLOW_TIMEOUT_SECONDS
        while time.monotonic() < deadline:
            if sublime_process.poll() is not None:
                raise QaFailure("Sublime launcher exited before QA completion")
            offset, records = read_new_reports(report, offset)
            for record in records:
                event = record.get("event")
                if isinstance(event, str):
                    events.append(event)
                if event == "fatal":
                    raise QaFailure("QA helper failed at " + str(record.get("step")))
                if event == "loaded" and not record.get("gate_ok"):
                    raise QaFailure("strict preferences gate failed")
                if event == "opened" and not (
                    record.get("scratch") and record.get("unnamed") and record.get("initial_ok")
                ):
                    raise QaFailure("managed open invariants failed")
                if event == "saved" and not record.get("persisted_shape"):
                    raise QaFailure("encrypted save shape failed")
                if event == "crud_folder_created":
                    if record.get("exists") is not True:
                        raise QaFailure("encrypted folder create was not observed")
                    crud_folder_created = True
                if event == "crud_markdown_created":
                    if not (
                        record.get("clean") is True
                        and record.get("scratch") is True
                        and record.get("unnamed") is True
                        and record.get("empty") is True
                    ):
                        raise QaFailure("encrypted Markdown create invariants failed")
                    crud_markdown_created = True
                if event == "crud_markdown_renamed":
                    if record.get("clean") is not True:
                        raise QaFailure("encrypted Markdown rename invariants failed")
                    crud_markdown_renamed = True
                if event == "crud_markdown_deleted":
                    if record.get("absent") is not True:
                        raise QaFailure("encrypted Markdown delete was not observed")
                    crud_markdown_deleted = True
                if event == "ui" and record.get("action") in (
                    "select_tree",
                    "select_tree_for_plugin_host_crash",
                ):
                    wait_until(
                        "isolated Sublime window",
                        lambda: bool(isolated_window_ids()),
                        20,
                    )
                    window_ids = isolated_window_ids()
                    if not window_ids:
                        raise QaFailure("isolated Sublime window disappeared")
                    window_id = window_ids[0]
                    qa_window_id = window_id
                    run_checked(
                        [xdotool, "windowactivate", "--sync", window_id],
                        env=env,
                        timeout=5,
                    )
                    time.sleep(0.6)
                    run_checked(
                        [
                            xdotool,
                            "key",
                            "--clearmodifiers",
                            "Down",
                        ],
                        env=env,
                        timeout=5,
                    )
                    time.sleep(0.15)
                    run_checked(
                        [xdotool, "key", "--clearmodifiers", "Return"],
                        env=env,
                        timeout=5,
                    )
                if event == "ui" and record.get("action") in (
                    "crud_new_folder",
                    "crud_new_markdown",
                    "crud_rename",
                    "crud_delete_confirm",
                ):
                    if qa_window_id is None:
                        raise QaFailure("isolated CRUD window id is unavailable")
                    run_checked(
                        [xdotool, "windowactivate", "--sync", qa_window_id],
                        env=env,
                        timeout=5,
                    )
                    time.sleep(0.3)
                    action = record.get("action")
                    inputs = {
                        "crud_new_folder": "qa-crud",
                        "crud_new_markdown": "qa-crud/new.md",
                        "crud_rename": "qa-crud/renamed.md",
                    }
                    if action in inputs:
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "ctrl+a"],
                            env=env,
                            timeout=5,
                        )
                        run_checked(
                            [
                                xdotool,
                                "type",
                                "--clearmodifiers",
                                "--delay",
                                "1",
                                inputs[action],
                            ],
                            env=env,
                            timeout=5,
                        )
                    else:
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "Home"],
                            env=env,
                            timeout=5,
                        )
                    time.sleep(0.15)
                    run_checked(
                        [xdotool, "key", "--clearmodifiers", "Return"],
                        env=env,
                        timeout=5,
                    )
                if event == "minimal_complete":
                    if not args.plugin_host_crash and record.get("crud_complete") is not True:
                        raise QaFailure("normal completion omitted the CRUD scenario")
                    minimal_complete = True
                if event == "plugin_host_crash_ready":
                    if not args.plugin_host_crash:
                        raise QaFailure("unexpected plugin-host crash scenario")
                    if record.get("marker") is not True:
                        raise QaFailure("plugin-host probe marker was not installed")
                    active_window_result = run_checked(
                        [xdotool, "getactivewindow"],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    active_window_id = active_window_result.stdout.strip()
                    if not active_window_id.isdigit():
                        raise QaFailure("isolated active window id is unavailable")
                    hosts = command_pids("plugin_host-3.8", str(profile))
                    if len(hosts) != 1:
                        raise QaFailure(
                            "expected one isolated Python 3.8 plugin host, found %d"
                            % len(hosts)
                        )
                    old_host = hosts[0]
                    os.kill(old_host, signal.SIGKILL)

                    def replacement_host_ready() -> bool:
                        hosts_now = command_pids("plugin_host-3.8", str(profile))
                        return len(hosts_now) == 1 and hosts_now[0] != old_host

                    try:
                        wait_until(
                            "automatic Python 3.8 plugin host restart",
                            replacement_host_ready,
                            2,
                        )
                    except QaFailure:
                        if replacement_host_ready():
                            plugin_host_restarted = True
                            continue
                        # Build 4200 does not automatically restart a killed
                        # plugin host. The official platform recovery is to
                        # restart Sublime Text, so characterize the still-dead
                        # host without pretending that plugin code can run.
                        expected_bytes = record.get("byte_count")
                        expected_digest = record.get("content_sha256")
                        post_crash_active = run_checked(
                            [xdotool, "getactivewindow"],
                            env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            text=True,
                            check=False,
                            timeout=5,
                        )
                        post_crash_window_id = post_crash_active.stdout.strip()
                        if (
                            post_crash_active.returncode == 0
                            and post_crash_window_id.isdigit()
                            and post_crash_window_id != active_window_id
                        ):
                            # Dismiss only an isolated crash notification that
                            # stole focus; never send Return to the document.
                            run_checked(
                                [
                                    xdotool,
                                    "key",
                                    "--window",
                                    post_crash_window_id,
                                    "--clearmodifiers",
                                    "Return",
                                ],
                                env=env,
                                timeout=5,
                            )
                            time.sleep(0.2)
                        run_checked(
                            [
                                xdotool,
                                "windowactivate",
                                "--sync",
                                active_window_id,
                            ],
                            env=env,
                            timeout=5,
                        )
                        run_checked(
                            [
                                xdotool,
                                "mousemove",
                                "--window",
                                active_window_id,
                                "600",
                                "300",
                                "click",
                                "1",
                            ],
                            env=env,
                            timeout=5,
                        )
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "ctrl+a"],
                            env=env,
                            timeout=5,
                        )
                        time.sleep(0.1)
                        run_checked(
                            [xdotool, "key", "--clearmodifiers", "ctrl+c"],
                            env=env,
                            timeout=5,
                        )
                        time.sleep(0.2)
                        clipboard_result = run_checked(
                            [xclip, "-selection", "clipboard", "-o"],
                            env=env,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL,
                            check=False,
                            timeout=5,
                        )
                        clipboard_read_ok = clipboard_result.returncode == 0
                        clipboard = (
                            clipboard_result.stdout if clipboard_read_ok else b""
                        )
                        clipboard_digest = hashlib.sha256(clipboard).hexdigest()
                        clipboard_exact = (
                            isinstance(expected_bytes, int)
                            and not isinstance(expected_bytes, bool)
                            and len(clipboard) == expected_bytes
                            and isinstance(expected_digest, str)
                            and clipboard_digest == expected_digest
                        )
                        plaintext_copyable = clipboard_exact or any(
                            token.encode("utf-8") in clipboard for token in tokens
                        )
                        selection_channel = "clipboard"
                        if not plaintext_copyable:
                            # A dead plugin host can also prevent key-command
                            # dispatch. Select the short fixture with the
                            # editor's native mouse path; X11 PRIMARY owns a
                            # selection without invoking a plugin command.
                            run_checked(
                                [
                                    xdotool,
                                    "mousemove",
                                    "--window",
                                    active_window_id,
                                    "1000",
                                    "400",
                                    "mousedown",
                                    "1",
                                    "mousemove",
                                    "--window",
                                    active_window_id,
                                    "5",
                                    "65",
                                    "mouseup",
                                    "1",
                                ],
                                env=env,
                                timeout=5,
                            )
                            time.sleep(0.2)
                            primary_result = run_checked(
                                [xclip, "-selection", "primary", "-o"],
                                env=env,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                check=False,
                                timeout=5,
                            )
                            primary_read_ok = primary_result.returncode == 0
                            primary = (
                                primary_result.stdout if primary_read_ok else b""
                            )
                            primary_digest = hashlib.sha256(primary).hexdigest()
                            primary_exact = (
                                isinstance(expected_bytes, int)
                                and not isinstance(expected_bytes, bool)
                                and len(primary) == expected_bytes
                                and isinstance(expected_digest, str)
                                and primary_digest == expected_digest
                            )
                            primary_copyable = primary_exact or any(
                                token.encode("utf-8") in primary for token in tokens
                            )
                            if primary_read_ok:
                                clipboard = primary
                                clipboard_digest = primary_digest
                                clipboard_read_ok = True
                                selection_channel = "primary"
                            if primary_copyable:
                                plaintext_copyable = True
                                clipboard_exact = primary_exact
                            primary = b""
                        append_report(
                            report,
                            {
                                "event": "plugin_host_dead_clipboard_checked",
                                "byte_count": len(clipboard),
                                "content_sha256": clipboard_digest,
                                "same_length_and_hash": clipboard_exact,
                                "host_dead_plaintext_copyable": plaintext_copyable,
                                "clipboard_read_ok": clipboard_read_ok,
                                "selection_channel": selection_channel,
                            },
                        )
                        clipboard = b""
                        host_dead_plaintext_copyable = plaintext_copyable
                        host_dead_clipboard_read_ok = clipboard_read_ok
                        time.sleep(0.25)
                        if replacement_host_ready():
                            plugin_host_restarted = True
                        else:
                            plugin_host_restart_required = True
                            append_report(
                                report,
                                {
                                    "event": "plugin_host_restart_required",
                                    "documented_platform_boundary": True,
                                },
                            )
                            flow_complete = True
                    else:
                        plugin_host_restarted = True
                if event == "plugin_host_restart_checked":
                    if not plugin_host_restarted:
                        raise QaFailure("plugin-host restart check arrived out of order")
                    plugin_host_checked = True
                    if record.get("plaintext_survived") is True:
                        raise QaFailure(
                            "plugin_host-3.8 crash left the managed plaintext view intact"
                        )
                    if record.get("orphan_scrubbed") is not True:
                        raise QaFailure(
                            "plugin_host-3.8 restart did not scrub the marked orphan view"
                        )
                if event == "complete":
                    if not args.plugin_host_crash and not minimal_complete:
                        raise QaFailure("completion preceded the minimal-flow close")
                    if not args.plugin_host_crash and not all(
                        (
                            crud_folder_created,
                            crud_markdown_created,
                            crud_markdown_renamed,
                            crud_markdown_deleted,
                        )
                    ):
                        raise QaFailure("completion preceded the CRUD assertions")
                    if (
                        args.plugin_host_crash
                        and not plugin_host_checked
                        and not plugin_host_restart_required
                    ):
                        raise QaFailure("completion preceded the plugin-host restart check")
                    flow_complete = True
                    break
            if flow_complete:
                break
            time.sleep(0.1)
        if not flow_complete:
            raise QaFailure("minimal flow did not complete")

        assert_ciphertext(vault, tokens)
        terminate_sublime_tree(sublime_main_pid, sublime_process, root)
        sublime_main_pid = None
        sublime_process = None
        hits = scan_for_tokens((root,), tokens)
        if hits:
            raise QaFailure("plaintext residue found: " + ", ".join(hits[:8]))
        summary = {
            "events": events,
            "plugin_host_crash": args.plugin_host_crash,
            "result": (
                "PASS_WITH_DOCUMENTED_BOUNDARY"
                if plugin_host_restart_required
                else "PASS"
            ),
            "root_scan_hits": 0,
            "vault_envelope": "EDRY",
            "crud_complete": (
                not args.plugin_host_crash
                and crud_folder_created
                and crud_markdown_created
                and crud_markdown_renamed
                and crud_markdown_deleted
            ),
        }
        if args.plugin_host_crash:
            summary.update(
                {
                    "plugin_host_restarted": plugin_host_checked,
                    "sublime_restart_required": plugin_host_restart_required,
                    "host_dead_plaintext_copyable": host_dead_plaintext_copyable,
                    "host_dead_clipboard_read_ok": host_dead_clipboard_read_ok,
                }
            )
        write_json(control / "final-result.json", summary)
        print(json.dumps(summary, sort_keys=True), flush=True)
        final_success = True
        return 0
    finally:
        try:
            terminate_sublime_tree(sublime_main_pid, sublime_process, root)
        except QaFailure:
            for pid in root_bound_pids(root):
                terminate_pid(pid, 0.2)
        if window_manager_process is not None:
            terminate_pid(window_manager_process.pid, 0.2)
        if xvfb_process is not None:
            terminate_pid(xvfb_process.pid, 0.2)
        terminate_pid(dbus_pid, 0.2)
        if args.keep or not final_success:
            print("retained-root=" + str(root), flush=True)
        else:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (QaFailure, subprocess.SubprocessError, OSError) as error:
        print("result=FAIL " + str(error), file=sys.stderr, flush=True)
        raise SystemExit(1)
