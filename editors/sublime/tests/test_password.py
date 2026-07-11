from __future__ import annotations

import os
import io
import tempfile
import unittest
from unittest import mock

import inex_password
from inex_password import PasswordPromptError, WINDOWS_PASSWORD_SCRIPT, prompt_password


class FakeProcess:
    def __init__(self, argv, **kwargs):
        self.argv = argv
        self.kwargs = kwargs
        self.returncode = 0
        self.stdout = io.BytesIO(b"correct horse battery staple\n")

    def wait(self, timeout):
        return self.returncode

    def kill(self):
        self.returncode = -1


class PasswordPromptTests(unittest.TestCase):
    def test_linux_password_never_appears_in_argv_env_or_stderr(self):
        with tempfile.TemporaryDirectory() as root:
            zenity = os.path.join(root, "zenity")
            with open(zenity, "wb") as stream:
                stream.write(b"fake")
            os.chmod(zenity, 0o700)
            created = []

            def factory(argv, **kwargs):
                process = FakeProcess(argv, **kwargs)
                created.append(process)
                return process

            with mock.patch.object(inex_password.subprocess, "Popen", factory):
                password = prompt_password("linux", zenity)
            self.assertEqual(password, "correct horse battery staple")
            flattened = " ".join(created[0].argv)
            self.assertNotIn(password, flattened)
            self.assertNotIn("env", created[0].kwargs)
            self.assertIs(created[0].kwargs["stderr"], inex_password.subprocess.DEVNULL)
            self.assertFalse(created[0].kwargs["shell"])

    def test_linux_helper_must_not_be_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            target = os.path.join(root, "zenity-real")
            with open(target, "wb") as stream:
                stream.write(b"fake")
            os.chmod(target, 0o700)
            link = os.path.join(root, "zenity")
            os.symlink(target, link)
            with self.assertRaises(PasswordPromptError):
                prompt_password("linux", link)

    def test_one_zenity_line_terminator_is_removed_but_internal_newline_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            zenity = os.path.join(root, "zenity")
            with open(zenity, "wb") as stream:
                stream.write(b"fake")
            os.chmod(zenity, 0o700)

            class OutputProcess(FakeProcess):
                def __init__(self, argv, **kwargs):
                    super().__init__(argv, **kwargs)
                    self.stdout = io.BytesIO(b"line-one\nline-two\n")

            with mock.patch.object(inex_password.subprocess, "Popen", OutputProcess):
                with self.assertRaises(PasswordPromptError):
                    prompt_password("linux", zenity)

    def test_windows_script_is_constant_and_masked(self):
        self.assertIn("UseSystemPasswordChar = $true", WINDOWS_PASSWORD_SCRIPT)
        self.assertIn("DialogResult", WINDOWS_PASSWORD_SCRIPT)
        self.assertNotIn("{password}", WINDOWS_PASSWORD_SCRIPT)

    def test_helper_output_is_bounded_before_decode(self):
        with tempfile.TemporaryDirectory() as root:
            zenity = os.path.join(root, "zenity")
            with open(zenity, "wb") as stream:
                stream.write(b"fake")
            os.chmod(zenity, 0o700)

            class OversizedProcess(FakeProcess):
                def __init__(self, argv, **kwargs):
                    super().__init__(argv, **kwargs)
                    self.stdout = io.BytesIO(b"x" * 5000)

            with mock.patch.object(inex_password.subprocess, "Popen", OversizedProcess):
                with self.assertRaisesRegex(PasswordPromptError, "exceeds"):
                    prompt_password("linux", zenity)

    def test_unsupported_platform_fails_closed(self):
        with self.assertRaises(PasswordPromptError):
            prompt_password("osx")


if __name__ == "__main__":
    unittest.main()
