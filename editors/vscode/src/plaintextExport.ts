/**
 * Validate the one path component collected by the plaintext-export UI.
 * The daemon still independently validates the final native destination; this
 * keeps the editor's chosen parent from being silently bypassed by `.`/`..`.
 */
export function validatePlaintextExportDirectoryName(value: string): string | undefined {
  if (
    value.length === 0
    || value === "."
    || value === ".."
    || /[\\/\0-\x1f\x7f]/u.test(value)
  ) {
    return "Enter one new folder name without separators, control characters, . or ..";
  }
  return undefined;
}
