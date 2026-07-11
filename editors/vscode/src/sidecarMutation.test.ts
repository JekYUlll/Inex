import assert from "node:assert/strict";
import test from "node:test";

import { RpcProtocolError } from "./rpc.ts";
import {
  parseDeleteResult,
  parseRenameResult,
  parseStatResult,
  parseWriteResult,
} from "./sidecar.ts";

const ETAG = `sha256:${"a".repeat(64)}`;
const METADATA = {
  fileId: "12345678-1234-4234-9234-123456789abc",
  logicalPath: "notes/new.md",
  createdAt: 1,
  modifiedAt: 2,
  flags: 0,
};

test("CRUD result parsers accept the exact frozen v1 response shapes", () => {
  assert.equal(
    parseStatResult(
      { type: "file", size: 0, etag: ETAG, metadata: METADATA },
      "notes/new.md",
    ).etag,
    ETAG,
  );
  assert.equal(
    parseWriteResult(
      { etag: ETAG, metadata: METADATA, durability: "synced" },
      "notes/new.md",
    ).durability,
    "synced",
  );
  assert.equal(
    parseRenameResult(
      {
        etag: ETAG,
        metadata: METADATA,
        sourceDurability: "synced",
        destinationDurability: "notSynced",
      },
      "notes/new.md",
    ).destinationDurability,
    "notSynced",
  );
  assert.equal(parseDeleteResult({ ok: true, durability: "synced" }).durability, "synced");
});

test("CRUD result parsers reject path substitution, unknown fields, and bad durability", () => {
  assert.throws(
    () =>
      parseWriteResult(
        {
          etag: ETAG,
          metadata: { ...METADATA, logicalPath: "notes/other.md" },
          durability: "synced",
        },
        "notes/new.md",
      ),
    RpcProtocolError,
  );
  assert.throws(
    () =>
      parseStatResult(
        { type: "file", size: 0, etag: ETAG, metadata: METADATA, extra: true },
        "notes/new.md",
      ),
    RpcProtocolError,
  );
  assert.throws(
    () => parseDeleteResult({ ok: true, durability: "maybe" }),
    RpcProtocolError,
  );
});
