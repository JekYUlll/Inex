import assert from "node:assert/strict";
import { chmodSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";

import { CliExecutableError, resolveCliExecutable } from "./cliExecutable.ts";
import {
  classifyImportTarget,
  rejectOverlappingTarget,
  RepositoryImportError,
  requireRegularDirectory,
  validateTargetFolderName,
} from "./repositoryImportPaths.ts";

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

test("repository initialization path policy accepts safe create and reconcile targets", () => {
  const root = path.join(os.tmpdir(), `inex-vscode-import-paths-${process.pid}-${Date.now()}`);
  try {
    const source = path.join(root, "source");
    const nestedSource = path.join(source, "notes");
    const existing = path.join(root, "existing-target");
    const absent = path.join(root, "absent-target");
    const file = path.join(root, "target-file");
    const linked = path.join(root, "target-link");
    mkdirSync(nestedSource, { recursive: true });
    mkdirSync(existing);
    writeFileSync(file, "not a directory");
    symlinkSync(existing, linked, "dir");

    requireRegularDirectory(source, "Source");
    assert.equal(classifyImportTarget(absent), "absent");
    assert.equal(classifyImportTarget(existing), "existing-directory");
    assert.throws(() => classifyImportTarget(file), RepositoryImportError);
    assert.throws(() => classifyImportTarget(linked), RepositoryImportError);
    assert.doesNotThrow(() => rejectOverlappingTarget(source, existing));
    assert.throws(
      () => rejectOverlappingTarget(source, nestedSource),
      RepositoryImportError,
    );
    assert.throws(
      () => rejectOverlappingTarget(nestedSource, source),
      RepositoryImportError,
    );

    assert.equal(validateTargetFolderName("notes-inex"), undefined);
    assert.match(validateTargetFolderName("../notes") ?? "", /portable/u);
    assert.match(validateTargetFolderName("CON") ?? "", /portable/u);
  } finally {
    rmSync(root, { force: true, recursive: true });
  }
});
