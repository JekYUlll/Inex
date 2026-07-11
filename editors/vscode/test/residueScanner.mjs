import * as fs from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import * as path from "node:path";

const READ_CHUNK_BYTES = 1024 * 1024;
const HIGH_ENTROPY_FRAGMENT_BYTES = 24;

export function residueSignatures(canary, plaintexts) {
  if (typeof canary !== "string" || canary.length < 64) {
    throw new Error("Residue canary is too short");
  }
  if (!Array.isArray(plaintexts) || plaintexts.length === 0) {
    throw new Error("At least one plaintext form is required");
  }

  const signatures = [];
  addTextForms(signatures, "canary", canary, true);
  plaintexts.forEach((plaintext, index) => {
    if (typeof plaintext !== "string" || !plaintext.includes(canary)) {
      throw new Error("Plaintext form does not contain the residue canary");
    }
    addTextForms(signatures, `plaintext-${index + 1}`, plaintext, true);
  });

  const entropy = canary.slice(canary.indexOf(":") + 1);
  const finalStart = Math.max(0, entropy.length - HIGH_ENTROPY_FRAGMENT_BYTES);
  const starts = new Set([0, 1, 2, finalStart]);
  for (const start of starts) {
    const fragment = entropy.slice(start, start + HIGH_ENTROPY_FRAGMENT_BYTES);
    if (fragment.length === HIGH_ENTROPY_FRAGMENT_BYTES) {
      const bytes = Buffer.from(fragment, "utf8");
      signatures.push({
        encoding: `high-entropy-fragment-${start}:utf8`,
        bytes,
      });
      signatures.push({
        encoding: `high-entropy-fragment-${start}:utf16le`,
        bytes: Buffer.from(fragment, "utf16le"),
      });
      const utf16be = Buffer.from(fragment, "utf16le");
      utf16be.swap16();
      signatures.push({
        encoding: `high-entropy-fragment-${start}:utf16be`,
        bytes: utf16be,
      });
      signatures.push({
        encoding: `high-entropy-fragment-${start}:base64`,
        bytes: Buffer.from(bytes.toString("base64"), "ascii"),
      });
      signatures.push({
        encoding: `high-entropy-fragment-${start}:base64url`,
        bytes: Buffer.from(bytes.toString("base64url"), "ascii"),
      });
      signatures.push({
        encoding: `high-entropy-fragment-${start}:hex`,
        bytes: Buffer.from(bytes.toString("hex"), "ascii"),
      });
    }
  }
  return deduplicateSignatures(signatures);
}

export class ResidueStreamDetector {
  #overlap = Buffer.alloc(0);
  #hit;

  constructor(signatures) {
    if (!Array.isArray(signatures) || signatures.length === 0) {
      throw new Error("Residue stream detector requires signatures");
    }
    this.signatures = signatures;
    this.maximumSignatureBytes = Math.max(...signatures.map(({ bytes }) => bytes.length));
  }

  push(chunk) {
    if (this.#hit !== undefined) {
      return;
    }
    const inspected = Buffer.concat([this.#overlap, Buffer.from(chunk)]);
    this.#hit = firstMatchingSignature(inspected, this.signatures);
    const retained = Math.min(this.maximumSignatureBytes - 1, inspected.length);
    this.#overlap = Buffer.from(inspected.subarray(inspected.length - retained));
  }

  get hit() {
    return this.#hit;
  }
}

export async function scanResidueRoots(roots, signatures) {
  if (!Array.isArray(roots) || !Array.isArray(signatures) || signatures.length === 0) {
    throw new Error("Residue scan roots and signatures are required");
  }
  const hits = [];
  for (const root of roots) {
    try {
      await scanEntry(path.resolve(root), signatures, hits);
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
    }
  }
  return hits;
}

async function scanEntry(entryPath, signatures, hits) {
  const metadata = await fs.lstat(entryPath);
  if (metadata.isSymbolicLink()) {
    return;
  }
  if (metadata.isDirectory()) {
    const directory = await fs.opendir(entryPath);
    for await (const entry of directory) {
      const childPath = path.join(entryPath, entry.name);
      const nameHit = firstMatchingSignature(Buffer.from(entry.name, "utf8"), signatures);
      if (nameHit !== undefined) {
        hits.push({ path: childPath, encoding: `filename:${nameHit}` });
      }
      if (entry.isSymbolicLink()) {
        continue;
      }
      await scanEntry(childPath, signatures, hits);
    }
    return;
  }
  if (!metadata.isFile()) {
    return;
  }
  const hit = await scanRegularFile(entryPath, metadata, signatures);
  if (hit !== undefined) {
    hits.push({ path: entryPath, encoding: hit });
  }
}

async function scanRegularFile(filePath, pathMetadata, signatures) {
  const noFollow = fsConstants.O_NOFOLLOW ?? 0;
  const handle = await fs.open(filePath, fsConstants.O_RDONLY | noFollow);
  try {
    const openedMetadata = await handle.stat();
    if (
      !openedMetadata.isFile() ||
      openedMetadata.dev !== pathMetadata.dev ||
      openedMetadata.ino !== pathMetadata.ino
    ) {
      throw new Error(`Residue scan target changed during inspection: ${filePath}`);
    }
    const maximumSignatureBytes = Math.max(...signatures.map(({ bytes }) => bytes.length));
    let overlap = Buffer.alloc(0);
    const chunk = Buffer.allocUnsafe(READ_CHUNK_BYTES);
    while (true) {
      const { bytesRead } = await handle.read(chunk, 0, chunk.length, null);
      if (bytesRead === 0) {
        return undefined;
      }
      const inspected = Buffer.concat([overlap, chunk.subarray(0, bytesRead)]);
      const hit = firstMatchingSignature(inspected, signatures);
      if (hit !== undefined) {
        return hit;
      }
      const retained = Math.min(maximumSignatureBytes - 1, inspected.length);
      overlap = Buffer.from(inspected.subarray(inspected.length - retained));
    }
  } finally {
    await handle.close();
  }
}

function addTextForms(signatures, label, text, includeEncodings) {
  const utf8 = Buffer.from(text, "utf8");
  signatures.push({ encoding: `${label}:utf8`, bytes: utf8 });
  signatures.push({ encoding: `${label}:utf16le`, bytes: Buffer.from(text, "utf16le") });
  const utf16be = Buffer.from(text, "utf16le");
  utf16be.swap16();
  signatures.push({ encoding: `${label}:utf16be`, bytes: utf16be });
  if (includeEncodings) {
    signatures.push({
      encoding: `${label}:base64`,
      bytes: Buffer.from(utf8.toString("base64"), "ascii"),
    });
    signatures.push({
      encoding: `${label}:base64url`,
      bytes: Buffer.from(utf8.toString("base64url"), "ascii"),
    });
    signatures.push({
      encoding: `${label}:hex`,
      bytes: Buffer.from(utf8.toString("hex"), "ascii"),
    });
  }
}

function firstMatchingSignature(bytes, signatures) {
  for (const signature of signatures) {
    if (bytes.indexOf(signature.bytes) !== -1) {
      return signature.encoding;
    }
  }
  return undefined;
}

function deduplicateSignatures(signatures) {
  const seen = new Set();
  return signatures.filter(({ encoding, bytes }) => {
    if (bytes.length < 16) {
      return false;
    }
    const key = `${encoding}\0${bytes.toString("hex")}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}
