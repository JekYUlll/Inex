"""Fail-closed external masked password prompts for Sublime Build 4200."""

from __future__ import annotations

import os
import stat
import subprocess
import threading
from typing import Optional


MAX_PASSWORD_OUTPUT_BYTES = 4096


class PasswordPromptError(Exception):
    pass


WINDOWS_PASSWORD_SCRIPT = r"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
$form = New-Object System.Windows.Forms.Form
$form.Text = 'Unlock Inex vault'
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MinimizeBox = $false
$form.MaximizeBox = $false
$form.ClientSize = New-Object System.Drawing.Size(420,130)
$label = New-Object System.Windows.Forms.Label
$label.Text = 'Vault password:'
$label.Location = New-Object System.Drawing.Point(12,15)
$label.AutoSize = $true
$box = New-Object System.Windows.Forms.TextBox
$box.Location = New-Object System.Drawing.Point(15,40)
$box.Size = New-Object System.Drawing.Size(390,25)
$box.UseSystemPasswordChar = $true
$ok = New-Object System.Windows.Forms.Button
$ok.Text = 'Unlock'
$ok.Location = New-Object System.Drawing.Point(245,82)
$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK
$cancel = New-Object System.Windows.Forms.Button
$cancel.Text = 'Cancel'
$cancel.Location = New-Object System.Drawing.Point(330,82)
$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$form.Controls.AddRange(@($label,$box,$ok,$cancel))
$form.AcceptButton = $ok
$form.CancelButton = $cancel
$form.Add_Shown({$box.Select()})
$result = $form.ShowDialog()
if ($result -ne [System.Windows.Forms.DialogResult]::OK) { exit 2 }
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
[Console]::Out.Write($box.Text)
""".strip()


def _regular_absolute_executable(path: str) -> str:
    if not isinstance(path, str) or not os.path.isabs(path):
        raise PasswordPromptError("Secure password helper path must be absolute")
    path = os.path.normpath(path)
    try:
        metadata = os.lstat(path)
    except OSError:
        raise PasswordPromptError("Secure password helper is unavailable")
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise PasswordPromptError("Secure password helper is not a regular file")
    if os.name != "nt" and metadata.st_mode & 0o111 == 0:
        raise PasswordPromptError("Secure password helper is not executable")
    return path


def resolve_zenity(configured_path: str) -> str:
    if configured_path:
        return _regular_absolute_executable(configured_path)
    for candidate in ("/usr/bin/zenity", "/usr/local/bin/zenity"):
        try:
            return _regular_absolute_executable(candidate)
        except PasswordPromptError:
            pass
    raise PasswordPromptError("A verified absolute zenity executable is required")


def resolve_system_powershell(system_root: Optional[str] = None) -> str:
    root = system_root
    if root is None and os.name == "nt":
        try:
            import ctypes

            buffer = ctypes.create_unicode_buffer(32768)
            length = ctypes.windll.kernel32.GetWindowsDirectoryW(buffer, len(buffer))
            if 0 < length < len(buffer):
                root = buffer.value
        except Exception:
            root = None
    if not root or not os.path.isabs(root):
        raise PasswordPromptError("Windows system PowerShell is unavailable")
    expected = os.path.join(
        os.path.normpath(root),
        "System32",
        "WindowsPowerShell",
        "v1.0",
        "powershell.exe",
    )
    return _regular_absolute_executable(expected)


def _run_password_helper(argv: list, encoding: str = "utf-8") -> Optional[str]:
    """Run a constant helper command; the password is read only from stdout."""

    process = None
    output_box = [b""]
    read_error = [False]
    oversized = [False]
    process_options = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.DEVNULL,
        "shell": False,
        "close_fds": True,
    }
    if os.name == "nt":
        process_options["creationflags"] = subprocess.CREATE_NO_WINDOW
    try:
        process = subprocess.Popen(
            argv,
            **process_options,
        )
        if process.stdout is None:
            raise OSError("password helper stdout unavailable")

        def bounded_reader() -> None:
            try:
                # At most MAX password bytes, one CRLF terminator, plus one
                # sentinel byte used to detect an oversized helper response.
                output_box[0] = process.stdout.read(MAX_PASSWORD_OUTPUT_BYTES + 3)
                if len(output_box[0]) > MAX_PASSWORD_OUTPUT_BYTES + 2:
                    oversized[0] = True
                    process.kill()
            except OSError:
                read_error[0] = True

        reader = threading.Thread(
            target=bounded_reader, name="inex-password-helper", daemon=True
        )
        reader.start()
        process.wait(timeout=300.0)
        reader.join(timeout=1.0)
        if reader.is_alive() or read_error[0]:
            raise OSError("password helper output failed")
        output = output_box[0]
    except (OSError, subprocess.TimeoutExpired):
        try:
            if process is not None:
                process.kill()
                process.wait(timeout=5.0)
        except Exception:
            pass
        raise PasswordPromptError("Secure password prompt failed")
    if process.returncode == 2 or process.returncode == 1:
        return None
    if oversized[0]:
        raise PasswordPromptError("Password exceeds the client limit")
    if process.returncode != 0:
        raise PasswordPromptError("Secure password prompt failed")
    if output.endswith(b"\r\n"):
        output = output[:-2]
    elif output.endswith(b"\n"):
        output = output[:-1]
    if len(output) == 0:
        raise PasswordPromptError("Password must not be empty")
    if len(output) > MAX_PASSWORD_OUTPUT_BYTES:
        raise PasswordPromptError("Password exceeds the client limit")
    try:
        password = output.decode(encoding, "strict")
    except UnicodeError:
        raise PasswordPromptError("Password prompt returned invalid text")
    if "\x00" in password or "\r" in password or "\n" in password:
        raise PasswordPromptError("Password prompt returned invalid text")
    return password


def prompt_password(platform: str, zenity_path: str = "") -> Optional[str]:
    if platform == "linux":
        executable = resolve_zenity(zenity_path)
        return _run_password_helper(
            [executable, "--password", "--title=Unlock Inex vault"]
        )
    if platform == "windows":
        executable = resolve_system_powershell()
        return _run_password_helper(
            [
                executable,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Sta",
                "-Command",
                WINDOWS_PASSWORD_SCRIPT,
            ]
        )
    raise PasswordPromptError("Secure password input is unsupported on this platform")
