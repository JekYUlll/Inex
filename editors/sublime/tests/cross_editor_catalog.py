#!/usr/bin/env python3
"""Verify a Sublime RPC process can read VS Code-written Umbra catalog data.

This is an integration helper, not a standalone Sublime UI test. Its password
is accepted only from stdin so the Extension Host runner never places it in an
argument, environment variable, or temporary file.
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
    password = bytearray(sys.stdin.buffer.readline(4097))
    if not password.endswith(b"\n"):
        wipe(password)
        return 2
    password.pop()
    if not password or b"\x00" in password:
        wipe(password)
        return 2
    client = InexRpcClient(executable, timeout_seconds=15.0)
    try:
        client.start("cross-editor-integration")
        client.unlock(vault_path, password.decode("utf-8"))
        try:
            client.open_document(EXPECTED_DOCUMENT_PATH)
        except RpcRemoteError:
            pass
        else:
            return 1
        client.unlock_umbra(password.decode("utf-8"))
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
            if not isinstance(slots, list) or len(slots) != 1:
                return 1
        finally:
            wipe(content)
        print("sublime-cross-editor-catalog-ok")
        return 0
    finally:
        wipe(password)
        try:
            client.lock_umbra()
        except Exception:
            pass
        client.shutdown()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
