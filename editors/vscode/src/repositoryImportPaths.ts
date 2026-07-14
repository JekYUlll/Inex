import { lstatSync } from "node:fs";
import * as path from "node:path";

export class RepositoryImportError extends Error {
  public override readonly name = "RepositoryImportError";
}

export type ImportTargetState = "absent" | "existing-directory";

export function requireRegularDirectory(folderPath: string, label: string): void {
  let metadata;
  try {
    metadata = lstatSync(folderPath);
  } catch {
    throw new RepositoryImportError(`${label} is unavailable`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new RepositoryImportError(`${label} must be a real local directory`);
  }
}

export function classifyImportTarget(targetPath: string): ImportTargetState {
  let metadata;
  try {
    metadata = lstatSync(targetPath);
  } catch (error: unknown) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return "absent";
    }
    throw new RepositoryImportError("Could not inspect the encrypted repository target");
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new RepositoryImportError(
      "The encrypted repository target must be absent or an existing real directory",
    );
  }
  return "existing-directory";
}

export function rejectOverlappingTarget(sourcePath: string, targetPath: string): void {
  if (
    isSameOrDescendant(path.relative(sourcePath, targetPath)) ||
    isSameOrDescendant(path.relative(targetPath, sourcePath))
  ) {
    throw new RepositoryImportError(
      "The encrypted repository and Markdown source must not contain one another",
    );
  }
}

export function validateTargetFolderName(value: string): string | undefined {
  if (
    value.length === 0 ||
    value === "." ||
    value === ".." ||
    value.includes("/") ||
    value.includes("\\") ||
    /\p{Cc}/u.test(value) ||
    /[<>:"|?*]/u.test(value) ||
    value.startsWith(" ") ||
    value.endsWith(" ") ||
    value.endsWith(".")
  ) {
    return "Enter one portable folder name without separators";
  }
  if (Buffer.byteLength(value, "utf8") > 255) {
    return "Folder name exceeds the portable byte limit";
  }
  const base = (value.split(".", 1)[0] ?? value).replace(/ +$/u, "").toUpperCase();
  if (
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].includes(base) ||
    /^(?:COM|LPT)(?:[1-9]|[¹²³])$/u.test(base) ||
    /~[0-9]$/u.test(base)
  ) {
    return "Folder name is not portable to Windows and Git";
  }
  return undefined;
}

function isSameOrDescendant(relative: string): boolean {
  return (
    relative.length === 0 ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
  );
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
