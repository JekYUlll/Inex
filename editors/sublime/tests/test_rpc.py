from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import time
import unittest

from inex_rpc import (
    ERROR_CONTRACT,
    MAX_FRAME_BYTES,
    MAX_PIPE_READ_BYTES,
    FrameDecoder,
    InexRpcClient,
    MAX_PENDING_CALLS,
    RpcLifecycleError,
    RpcProtocolError,
    RpcRemoteError,
    _read_pipe_once,
    decode_base64url,
    encode_request,
    resolve_sidecar,
    response_result,
)


def frame(value):
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


class FrameTests(unittest.TestCase):
    def test_fragmented_and_multiple_frames(self):
        first = {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
        second = {"jsonrpc": "2.0", "id": "two", "result": [1, 2]}
        encoded = frame(first) + frame(second)
        decoder = FrameDecoder()
        values = []
        for byte in encoded:
            values.extend(decoder.feed(bytes((byte,))))
        decoder.finish()
        self.assertEqual([first, second], values)

    def test_unknown_and_duplicate_headers_are_rejected(self):
        for header in (
            b"Content-Type: application/json\r\n\r\n",
            b"Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"Content-Length: +2\r\n\r\n{}",
            b"Content-Length: 02x\r\n\r\n{}",
        ):
            with self.subTest(header=header):
                with self.assertRaises(RpcProtocolError):
                    FrameDecoder().feed(header)

    def test_response_frame_and_header_bounds(self):
        with self.assertRaises(RpcProtocolError):
            FrameDecoder().feed(
                ("Content-Length: %d\r\n\r\n" % (MAX_FRAME_BYTES + 1)).encode("ascii")
            )
        with self.assertRaises(RpcProtocolError):
            FrameDecoder().feed(b"X" * 8193)

    def test_partial_frame_at_eof_is_rejected(self):
        decoder = FrameDecoder()
        decoder.feed(b"Content-Length: 10\r\n\r\n{}")
        with self.assertRaises(RpcProtocolError):
            decoder.finish()

    def test_invalid_utf8_batch_and_extra_envelope_keys_are_rejected(self):
        cases = [
            b"Content-Length: 1\r\n\r\n\xff",
            frame([]),
            frame({"jsonrpc": "2.0", "id": 1, "result": {}, "extra": 1}),
            b'Content-Length: 43\r\n\r\n{"jsonrpc":"2.0","id":1,"id":1,"result":{}}',
        ]
        for encoded in cases:
            with self.subTest(encoded=encoded[:40]):
                with self.assertRaises(RpcProtocolError):
                    FrameDecoder().feed(encoded)

    def test_complexity_bound_is_enforced(self):
        value = None
        for _unused in range(66):
            value = [value]
        encoded = frame({"jsonrpc": "2.0", "id": 1, "result": value})
        with self.assertRaises(RpcProtocolError):
            FrameDecoder().feed(encoded)


class PipeReadTests(unittest.TestCase):
    def test_read1_is_bounded_retries_interrupt_and_reports_eof(self):
        class InterruptedThenData:
            def __init__(self):
                self.calls = 0

            def read1(self, maximum):
                self.calls += 1
                self.maximum = maximum
                if self.calls == 1:
                    raise InterruptedError()
                return b"fragment"

        stream = InterruptedThenData()
        self.assertEqual(_read_pipe_once(stream), b"fragment")
        self.assertEqual(stream.calls, 2)
        self.assertEqual(stream.maximum, MAX_PIPE_READ_BYTES)

        class Eof:
            def read1(self, maximum):
                return b""

        self.assertEqual(_read_pipe_once(Eof()), b"")

        class Oversized:
            def read1(self, maximum):
                return b"x" * (maximum + 1)

        with self.assertRaisesRegex(RpcLifecycleError, "invalid chunk"):
            _read_pipe_once(Oversized())

    def test_os_read_fallback_returns_short_fragment_while_pipe_stays_open(self):
        read_descriptor, write_descriptor = os.pipe()
        stream = os.fdopen(read_descriptor, "rb", buffering=0)
        try:
            os.write(write_descriptor, b"short")
            started = time.monotonic()
            self.assertEqual(_read_pipe_once(stream), b"short")
            self.assertLess(time.monotonic() - started, 0.5)
            os.close(write_descriptor)
            write_descriptor = -1
            self.assertEqual(_read_pipe_once(stream), b"")
        finally:
            if write_descriptor >= 0:
                os.close(write_descriptor)
            stream.close()


class RequestAndResponseTests(unittest.TestCase):
    def test_request_is_compact_bounded_content_length(self):
        encoded = encode_request(7, "system.ping", {})
        header, body = bytes(encoded).split(b"\r\n\r\n", 1)
        self.assertEqual(header, b"Content-Length: %d" % len(body))
        self.assertEqual(
            json.loads(body),
            {"jsonrpc": "2.0", "id": 7, "method": "system.ping", "params": {}},
        )
        with self.assertRaises(RpcProtocolError):
            encode_request(True, "system.ping", {})
        with self.assertRaises(RpcProtocolError):
            encode_request(1, "x", {"x": "a" * MAX_FRAME_BYTES})

    def test_remote_error_requires_frozen_safe_contract(self):
        code = -32006
        name, message = ERROR_CONTRACT[code]
        response = {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": code, "message": message, "data": {"name": name}},
        }
        with self.assertRaises(RpcRemoteError) as caught:
            response_result(response)
        self.assertEqual(caught.exception.stable_name, "ETAG_CONFLICT")
        response["error"]["message"] = "unsafe details"
        with self.assertRaises(RpcProtocolError):
            response_result(response)

    def test_base64url_must_be_unpadded_and_canonical(self):
        self.assertEqual(decode_base64url("AQI", 2), bytearray(b"\x01\x02"))
        for value in ("AQI=", "A", "+w"):
            with self.subTest(value=value):
                with self.assertRaises(RpcProtocolError):
                    decode_base64url(value, 8)

    def test_authenticated_draft_decrypt_result_is_strictly_parsed(self):
        client = InexRpcClient("/unused")
        client._session = "A" * 43
        metadata = {
            "fileId": "00000000-0000-4000-8000-000000000000",
            "logicalPath": "today.md",
            "createdAt": 1,
            "modifiedAt": 2,
            "flags": 2,
        }
        client._call_raw = lambda method, params: {
            "contentBase64": "cmVjb3ZlcmVk",
            "baseEtag": "sha256:" + "1" * 64,
            "metadata": metadata,
        }
        content, base_etag = client.decrypt_draft(
            "today.md", bytearray(b"EDRYciphertext")
        )
        self.assertEqual(content, bytearray(b"recovered"))
        self.assertEqual(base_etag, "sha256:" + "1" * 64)


class SidecarResolutionTests(unittest.TestCase):
    def test_no_path_fallback_and_regular_executable_required(self):
        with tempfile.TemporaryDirectory() as root:
            package = os.path.join(root, "package")
            os.makedirs(os.path.join(package, "bin"))
            executable = os.path.join(package, "bin", "inexd")
            with open(executable, "wb") as stream:
                stream.write(b"fake")
            os.chmod(executable, 0o700)
            self.assertEqual(resolve_sidecar("", package, "linux"), executable)
            with self.assertRaises(RpcLifecycleError):
                resolve_sidecar("inexd", package, "linux")
            link = os.path.join(root, "linked-inexd")
            os.symlink(executable, link)
            with self.assertRaises(RpcLifecycleError):
                resolve_sidecar(link, package, "linux")
            os.chmod(executable, stat.S_IRUSR)
            with self.assertRaises(RpcLifecycleError):
                resolve_sidecar(executable, package, "linux")


class ClientBoundTests(unittest.TestCase):
    class Sink:
        def write(self, value):
            return len(value)

        def flush(self):
            return None

    class SilentProcess:
        def __init__(self):
            self.stdin = ClientBoundTests.Sink()
            self.killed = False

        def poll(self):
            return -1 if self.killed else None

        def kill(self):
            self.killed = True

    def test_timeout_is_terminal_even_without_response(self):
        client = InexRpcClient("/unused", timeout_seconds=0.001)
        process = self.SilentProcess()
        client._process = process
        with self.assertRaisesRegex(RpcLifecycleError, "timed out"):
            client._call_raw("system.ping", {})
        self.assertTrue(process.killed)

    def test_pending_request_count_is_bounded_before_write(self):
        client = InexRpcClient("/unused", timeout_seconds=0.001)
        client._process = self.SilentProcess()
        client._pending = {index: object() for index in range(MAX_PENDING_CALLS)}
        with self.assertRaisesRegex(RpcLifecycleError, "call limit"):
            client._call_raw("system.ping", {})

    def test_terminal_session_loss_callback_is_exactly_once(self):
        callbacks = []
        client = InexRpcClient(
            "/unused", on_session_lost=lambda error: callbacks.append(error)
        )
        client._process = self.SilentProcess()
        client._session = "A" * 43
        first = RpcProtocolError("terminal one")
        client._fail_terminal(first)
        client._fail_terminal(RpcProtocolError("terminal two"))
        self.assertEqual(callbacks, [first])

    def test_session_invalid_then_process_exit_does_not_double_notify(self):
        callbacks = []
        client = InexRpcClient(
            "/unused", on_session_lost=lambda error: callbacks.append(error)
        )
        client._process = self.SilentProcess()
        client._session = "A" * 43
        first = RpcRemoteError(-32001, "SESSION_INVALID", "Session is invalid or expired")
        client._lose_session(first)
        client._fail_terminal(RpcLifecycleError("child exited"))
        self.assertEqual(callbacks, [first])

    def test_successful_protected_rpc_reports_authenticated_activity(self):
        activities = []
        client = InexRpcClient(
            "/unused", on_session_activity=lambda: activities.append("renew")
        )

        class EchoSink:
            def write(self, value):
                return len(value)

            def flush(self):
                client._accept_response(
                    {"jsonrpc": "2.0", "id": 1, "result": {"ok": True}}
                )

        process = self.SilentProcess()
        process.stdin = EchoSink()
        client._process = process
        client._call_raw("system.ping", {})
        self.assertEqual(activities, ["renew"])

    def test_stdout_eof_and_reader_failures_are_terminal(self):
        class Eof:
            def read1(self, maximum):
                return b""

        eof_client = InexRpcClient("/unused")
        eof_process = self.SilentProcess()
        eof_process.stdout = Eof()
        eof_client._process = eof_process
        eof_client._read_stdout()
        self.assertTrue(eof_process.killed)
        self.assertIsInstance(eof_client._terminal_error, RpcLifecycleError)

        class Oversized:
            def read1(self, maximum):
                return b"x" * (maximum + 1)

        stdout_client = InexRpcClient("/unused")
        stdout_process = self.SilentProcess()
        stdout_process.stdout = Oversized()
        stdout_client._process = stdout_process
        stdout_client._read_stdout()
        self.assertTrue(stdout_process.killed)
        self.assertIsInstance(stdout_client._terminal_error, RpcLifecycleError)

        class Broken:
            def read1(self, maximum):
                raise RuntimeError("broken pipe reader")

        stderr_client = InexRpcClient("/unused")
        stderr_process = self.SilentProcess()
        stderr_process.stderr = Broken()
        stderr_client._process = stderr_process
        stderr_client._drain_stderr()
        self.assertTrue(stderr_process.killed)
        self.assertIsInstance(stderr_client._terminal_error, RpcLifecycleError)

    @unittest.skipUnless(os.name == "posix", "requires an executable script")
    def test_real_short_fragmented_frame_decodes_while_child_keeps_pipes_open(self):
        hello = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "server": "inexd",
                "serverVersion": "test",
                "protocolMajor": 1,
                "capabilities": sorted(InexRpcClient.REQUIRED_CAPABILITIES),
            },
        }
        encoded = frame(hello)
        diagnostic = b"short-stderr"
        with tempfile.TemporaryDirectory() as root:
            executable = os.path.join(root, "short-frame-child")
            script = (
                "#!%s\n"
                "import os, time\n"
                "payload = %r\n"
                "os.write(1, payload[:7])\n"
                "time.sleep(0.05)\n"
                "os.write(1, payload[7:])\n"
                "os.write(2, %r)\n"
                "time.sleep(5)\n"
            ) % (sys.executable, encoded, diagnostic)
            with open(executable, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(script)
            os.chmod(executable, 0o700)

            client = InexRpcClient(executable, timeout_seconds=1.5)
            started = time.monotonic()
            try:
                result = client.start("test")
                self.assertEqual(result["server"], "inexd")
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertIsNotNone(client._process)
                self.assertIsNone(client._process.poll())
                deadline = time.monotonic() + 1.0
                while (
                    client._stderr_bytes < len(diagnostic)
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertEqual(client._stderr_bytes, len(diagnostic))
            finally:
                process = client._process
                client.dispose()
                if process is not None:
                    process.wait(timeout=2.0)
                    for pipe in (process.stdin, process.stdout, process.stderr):
                        if pipe is not None:
                            pipe.close()


if __name__ == "__main__":
    unittest.main()
