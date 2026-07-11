import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";

export async function readBoundedRegularFile(
  filePath: string,
  maximumBytes: number,
): Promise<Buffer> {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 0) {
    throw new Error("Bounded file limit is invalid");
  }
  const before = await lstat(filePath);
  validateMetadata(before, maximumBytes);

  const noFollow = process.platform === "win32" ? 0 : constants.O_NOFOLLOW;
  const handle = await open(filePath, constants.O_RDONLY | noFollow);
  let allocation = Buffer.alloc(0);
  try {
    const opened = await handle.stat();
    validateMetadata(opened, maximumBytes);
    if (!sameFile(before, opened)) {
      throw new Error("Bounded file changed while it was opened");
    }

    allocation = Buffer.alloc(opened.size + 1);
    let offset = 0;
    while (offset < allocation.byteLength) {
      const { bytesRead } = await handle.read(
        allocation,
        offset,
        allocation.byteLength - offset,
        offset,
      );
      if (bytesRead === 0) {
        break;
      }
      offset += bytesRead;
    }
    if (offset !== opened.size) {
      throw new Error("Bounded file changed while it was read");
    }
    const after = await handle.stat();
    if (!sameFile(opened, after) || after.size !== opened.size) {
      throw new Error("Bounded file changed while it was read");
    }
    const result = Buffer.from(allocation.subarray(0, offset));
    allocation.fill(0);
    return result;
  } finally {
    allocation.fill(0);
    await handle.close();
  }
}

function validateMetadata(metadata: Awaited<ReturnType<typeof lstat>>, maximumBytes: number): void {
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.nlink !== 1 ||
    !Number.isSafeInteger(metadata.size) ||
    metadata.size < 0 ||
    metadata.size > maximumBytes
  ) {
    throw new Error("Bounded file is not a supported regular file");
  }
}

function sameFile(
  left: Awaited<ReturnType<typeof lstat>>,
  right: Awaited<ReturnType<typeof lstat>>,
): boolean {
  return left.dev === right.dev && left.ino !== 0 && left.ino === right.ino;
}
