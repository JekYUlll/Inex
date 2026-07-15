#!/usr/bin/env python3
"""Verify a Sublime RPC process can read VS Code-written Umbra catalog data.

This is an integration helper, not a standalone Sublime UI test. Its Outer and
Umbra passwords are accepted as two stdin lines so the Extension Host runner
never places either in an argument, environment variable, or temporary file.
"""

from __future__ import annotations

from pathlib import Path
import sys
from typing import List


PACKAGE_DIRECTORY = Path(__file__).resolve().parents[1]
if str(PACKAGE_DIRECTORY) not in sys.path:
    sys.path.insert(0, str(PACKAGE_DIRECTORY))

from inex_rpc import InexRpcClient, RpcRemoteError, wipe


EXPECTED_TAG_ID = "cross-editor-catalog"
EXPECTED_TAG_LABEL = "Cross editor catalog"
EXPECTED_DOCUMENT_PATH = "plain.md"


def main(arguments: List[str]) -> int:
    if len(arguments) != 3:
        return 2
    executable, vault_path = arguments[1:]
    outer_password = bytearray(sys.stdin.buffer.readline(4097))
    umbra_password = bytearray(sys.stdin.buffer.readline(4097))
    if not outer_password.endswith(b"\n") or not umbra_password.endswith(b"\n"):
        wipe(outer_password)
        wipe(umbra_password)
        return 2
    outer_password.pop()
    umbra_password.pop()
    if (
        not outer_password
        or not umbra_password
        or b"\x00" in outer_password
        or b"\x00" in umbra_password
    ):
        wipe(outer_password)
        wipe(umbra_password)
        return 2
    client = InexRpcClient(executable, timeout_seconds=15.0)
    try:
        client.start("cross-editor-integration")
        client.unlock(vault_path, outer_password.decode("utf-8"))
        try:
            client.open_document(EXPECTED_DOCUMENT_PATH)
        except RpcRemoteError:
            pass
        else:
            return 1
        client.unlock_umbra(umbra_password.decode("utf-8"))
        config = client.load_umbra_annotation_config()
        tags = config["tags"]
        if not any(
            tag["id"] == EXPECTED_TAG_ID
            and tag["label"] == EXPECTED_TAG_LABEL
            for tag in tags
        ):
            return 1
        content, _etag, render_map = client.open_umbra_document(
            EXPECTED_DOCUMENT_PATH
        )
        try:
            slots = render_map.get("privateSlots")
            # VS Code's preceding lifecycle retains one slot and then adds a
            # second tagged slot for this cross-editor proof.
            if not isinstance(slots, list) or len(slots) != 2:
                return 1
        finally:
            wipe(content)
        print("sublime-cross-editor-catalog-ok")
        return 0
    finally:
        wipe(outer_password)
        wipe(umbra_password)
        try:
            client.lock_umbra()
        except Exception:
            pass
        client.shutdown()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
