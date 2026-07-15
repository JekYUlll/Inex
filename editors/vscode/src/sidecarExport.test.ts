import assert from "node:assert/strict";
import test from "node:test";

import { RpcProtocolError } from "./rpc.ts";
import {
  parsePlaintextExportCommit,
  parsePlaintextExportPrepare,
} from "./sidecar.ts";

const CONFIRMATION = "a".repeat(43);

test("plaintext-export parsers accept the exact prepare and commit contracts", () => {
  const prepared = parsePlaintextExportPrepare({
    confirmation: CONFIRMATION,
    scope: "outer",
    files: 3,
    assets: 2,
    directories: 4,
  }, "outer");
  assert.deepEqual(prepared, {
    confirmation: CONFIRMATION,
    scope: "outer",
    files: 3,
    assets: 2,
    directories: 4,
  });

  assert.deepEqual(parsePlaintextExportCommit({
    ok: true,
    scope: "umbra",
    files: 3,
    assets: 2,
    directories: 4,
    durability: "synced",
  }), {
    scope: "umbra",
    files: 3,
    assets: 2,
    directories: 4,
  });
});

test("plaintext-export parsers reject response substitutions and impossible counts", () => {
  assert.throws(
    () => parsePlaintextExportPrepare({
      confirmation: CONFIRMATION,
      scope: "umbra",
      files: 0,
      assets: 0,
      directories: 0,
    }, "outer"),
    RpcProtocolError,
  );
  assert.throws(
    () => parsePlaintextExportPrepare({
      confirmation: CONFIRMATION,
      scope: "outer",
      files: -1,
      assets: 0,
      directories: 0,
    }, "outer"),
    RpcProtocolError,
  );
  assert.throws(
    () => parsePlaintextExportCommit({
      ok: true,
      scope: "outer",
      files: 0,
      assets: 0,
      directories: 0,
      durability: "synced",
      unexpected: true,
    }),
    RpcProtocolError,
  );
  assert.throws(
    () => parsePlaintextExportCommit({
      ok: false,
      scope: "outer",
      files: 0,
      assets: 0,
      directories: 0,
      durability: "synced",
    }),
    RpcProtocolError,
  );
});
