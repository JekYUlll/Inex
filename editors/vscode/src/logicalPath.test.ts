import assert from "node:assert/strict";
import test from "node:test";

import {
  LogicalPathError,
  logicalDirectoryComponents,
  logicalFileComponents,
} from "./logicalPath.ts";

test("logical path validation accepts canonical portable files and directories", () => {
  assert.deepEqual(logicalFileComponents("日记/2026-07-11.md"), ["日记", "2026-07-11.md"]);
  assert.deepEqual(logicalDirectoryComponents("日记/七月"), ["日记", "七月"]);
  assert.deepEqual(logicalDirectoryComponents(""), []);
});

test("logical path validation rejects traversal, aliases, and noncanonical text", () => {
  for (const value of [
    "../escape.md",
    "/absolute.md",
    "dir\\note.md",
    "vault.json/note.md",
    ".GIT/note.md",
    "NUL.md",
    "CON .md",
    "LPT1 .md",
    "draft~1.md",
    "bad?.md",
    "trailing./note.md",
    "Cafe\u0301.md",
    "UPPER.MD",
  ]) {
    assert.throws(() => logicalFileComponents(value), LogicalPathError, value);
  }
});

test("logical file validation reserves physical suffix space", () => {
  assert.doesNotThrow(() => logicalFileComponents(`${"a".repeat(248)}.md`));
  assert.throws(
    () => logicalFileComponents(`${"a".repeat(249)}.md`),
    LogicalPathError,
  );
});
