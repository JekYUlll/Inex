import assert from "node:assert/strict";
import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";

import { InexSidecar, SidecarLifecycleError, resolveSidecarExecutable } from "./sidecar.ts";

test("sidecar resolution never falls back to PATH", () => {
  const root = path.join(os.tmpdir(), `inex-vscode-sidecar-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(path.join(root, "bin", "linux-x64"), { recursive: true });
    assert.throws(
      () => resolveSidecarExecutable("", root, "linux", "x64"),
      SidecarLifecycleError,
    );
    const executable = path.join(root, "bin", "linux-x64", "inexd");
    writeFileSync(executable, "fixture");
    chmodSync(executable, 0o700);
    assert.equal(resolveSidecarExecutable("", root, "linux", "x64"), executable);
    assert.throws(() => resolveSidecarExecutable("inexd", root, "linux", "x64"));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test("explicit absolute sidecar path is authoritative and must be regular", () => {
  const root = path.join(os.tmpdir(), `inex-vscode-explicit-${process.pid}-${Date.now()}`);
  try {
    mkdirSync(root, { recursive: true });
    const executable = path.join(root, process.platform === "win32" ? "custom.exe" : "custom");
    writeFileSync(executable, "fixture");
    assert.equal(resolveSidecarExecutable(executable, "/unused"), executable);
    assert.throws(() => resolveSidecarExecutable(root, "/unused"));
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});

test(
  "sidecar stream failure is terminal and never becomes an unhandled EPIPE",
  { skip: process.platform === "win32" },
  async () => {
    const root = path.join(os.tmpdir(), `inex-vscode-epipe-${process.pid}-${Date.now()}`);
    const executable = path.join(root, "closed-stdin-sidecar");
    try {
      mkdirSync(root, { recursive: true });
      writeFileSync(executable, "#!/bin/sh\nexec 0<&-\nsleep 0.05\nexit 1\n");
      chmodSync(executable, 0o700);
      const sidecar = new InexSidecar(executable);
      await assert.rejects(sidecar.start("test"), SidecarLifecycleError);
      sidecar.dispose();
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);
