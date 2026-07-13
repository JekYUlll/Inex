import { accessSync, constants, lstatSync } from "node:fs";
import * as path from "node:path";

export class CliExecutableError extends Error {
  public override readonly name = "CliExecutableError";
}

export function resolveCliExecutable(
  configuredPath: string,
  extensionPath: string,
  platform: NodeJS.Platform = process.platform,
  architecture: string = process.arch,
): string {
  const candidate = configuredPath.length > 0
    ? configuredPath
    : path.join(
        extensionPath,
        "bin",
        `${platform}-${architecture}`,
        platform === "win32" ? "inex.exe" : "inex",
      );
  if (!path.isAbsolute(candidate)) {
    throw new CliExecutableError("Inex CLI path must be absolute");
  }
  let metadata;
  try {
    metadata = lstatSync(candidate);
  } catch {
    throw new CliExecutableError(
      "Inex CLI was not found; configure inex.cliPath to an absolute audited binary",
    );
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new CliExecutableError("Inex CLI path is not a regular file");
  }
  try {
    accessSync(candidate, constants.X_OK);
  } catch {
    throw new CliExecutableError("Inex CLI path is not executable");
  }
  return candidate;
}
