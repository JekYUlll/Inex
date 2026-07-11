import assert from "node:assert/strict";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import test from "node:test";

import { readBoundedRegularFile } from "./boundedFile.ts";

test("bounded reader returns an exact regular file", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "inex-vscode-bounded-"));
  try {
    const file = path.join(root, "draft.edry");
    await writeFile(file, Buffer.from([1, 2, 3]));
    assert.deepEqual(await readBoundedRegularFile(file, 3), Buffer.from([1, 2, 3]));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("bounded reader rejects oversized and symbolic-link inputs", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "inex-vscode-bounded-"));
  try {
    const file = path.join(root, "draft.edry");
    const link = path.join(root, "link.edry");
    await writeFile(file, Buffer.from([1, 2, 3, 4]));
    await symlink(file, link);
    await assert.rejects(readBoundedRegularFile(file, 3));
    await assert.rejects(readBoundedRegularFile(link, 8));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
