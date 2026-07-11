import assert from "node:assert/strict";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";

import {
  ResidueStreamDetector,
  residueSignatures,
  scanResidueRoots,
} from "./residueScanner.mjs";

const CANARY = `unit-test:${"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_".repeat(2)}`;
const PLAINTEXT = `# Scanner fixture\n\n${CANARY}\n`;

test("detects a signature split across read chunks", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "inex-residue-scanner-"));
  try {
    const file = path.join(root, "split.bin");
    const prefix = Buffer.alloc(1024 * 1024 - 7, 0x2e);
    await fs.writeFile(file, Buffer.concat([prefix, Buffer.from(CANARY, "utf8")]));
    const hits = await scanResidueRoots(
      [root],
      residueSignatures(CANARY, [PLAINTEXT]),
    );
    assert.equal(hits.length, 1);
    assert.equal(hits[0]?.path, file);
    assert.match(hits[0]?.encoding ?? "", /utf8|high-entropy-fragment/u);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("does not follow symbolic links", async (context) => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "inex-residue-scanner-"));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "inex-residue-outside-"));
  try {
    const secret = path.join(outside, "secret.txt");
    await fs.writeFile(secret, PLAINTEXT);
    try {
      await fs.symlink(secret, path.join(root, "link"));
    } catch (error) {
      if (error?.code === "EPERM") {
        context.skip("symlinks are unavailable on this platform");
        return;
      }
      throw error;
    }
    const hits = await scanResidueRoots(
      [root],
      residueSignatures(CANARY, [PLAINTEXT]),
    );
    assert.deepEqual(hits, []);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  }
});

test("detects unpadded base64url in a directory-entry name", async () => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "inex-residue-scanner-"));
  try {
    const encoded = Buffer.from(CANARY, "utf8").toString("base64url");
    const leakedPath = path.join(root, encoded);
    await fs.writeFile(leakedPath, "ciphertext-shaped-placeholder");
    const signatures = residueSignatures(CANARY, [PLAINTEXT]);
    assert.ok(signatures.some(({ encoding }) => encoding === "canary:base64url"));
    const hits = await scanResidueRoots([root], signatures);
    assert.ok(
      hits.some(
        (hit) =>
          hit.path === leakedPath &&
          /^filename:canary:base64(?:url)?$/u.test(hit.encoding),
      ),
    );
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
});

test("stream detector scans all chunks and bridges chunk boundaries", () => {
  const signatures = residueSignatures(CANARY, [PLAINTEXT]);
  const base64url = signatures.find(
    ({ encoding }) => encoding === "plaintext-1:base64url",
  );
  assert.ok(base64url);
  const detector = new ResidueStreamDetector([base64url]);
  const encoded = Buffer.from(PLAINTEXT, "utf8").toString("base64url");
  detector.push(Buffer.from(`discarded-prefix-${encoded.slice(0, 13)}`, "utf8"));
  detector.push(Buffer.from(encoded.slice(13), "utf8"));
  detector.push(Buffer.alloc(1024 * 1024, 0x2e));
  assert.equal(detector.hit, "plaintext-1:base64url");
});
