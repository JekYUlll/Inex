import assert from "node:assert/strict";
import { chmodSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";

import { CliExecutableError, resolveCliExecutable } from "./cliExecutable.ts";

test("CLI resolution is absolute, regular, and never falls back to PATH", () => {
  const root = path.join(os.tmpdir(), `inex-vscode-cli-${process.pid}-${Date.now()}`);
  try {
    const bundled = path.join(root, "bin", "linux-x64", "inex");
    mkdirSync(path.dirname(bundled), { recursive: true });
    writeFileSync(bundled, "fixture");
    chmodSync(bundled, 0o700);
    assert.equal(resolveCliExecutable("", root, "linux", "x64"), bundled);
    assert.throws(() => resolveCliExecutable("inex", root), CliExecutableError);
    const linked = path.join(root, "linked");
    symlinkSync(bundled, linked);
    assert.throws(() => resolveCliExecutable(linked, root), CliExecutableError);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
