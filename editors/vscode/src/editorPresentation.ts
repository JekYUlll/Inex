export type EditorLineEnding = "lf" | "crlf";

/**
 * A textarea is specified to expose LF-only values. Keep that browser-facing
 * representation separate from the authenticated ciphertext plaintext so
 * opening/navigating a CRLF document can never be mistaken for an edit.
 */
export function editorLineEnding(text: string): EditorLineEnding {
  return text.includes("\r\n") ? "crlf" : "lf";
}

export function toEditorPresentation(text: string): string {
  return text.replace(/\r\n?/gu, "\n");
}

export function fromEditorPresentation(text: string, lineEnding: EditorLineEnding): string {
  return lineEnding === "crlf" ? text.replace(/\n/gu, "\r\n") : text;
}

export function presentationByteToCanonicalByte(
  presentation: string,
  byteOffset: number,
  lineEnding: EditorLineEnding,
): number {
  const index = utf16IndexAtUtf8Byte(presentation, byteOffset);
  return Buffer.byteLength(fromEditorPresentation(presentation.slice(0, index), lineEnding), "utf8");
}

export function canonicalByteToPresentationByte(
  canonical: string,
  byteOffset: number,
): number {
  const index = utf16IndexAtUtf8Byte(canonical, byteOffset);
  return Buffer.byteLength(toEditorPresentation(canonical.slice(0, index)), "utf8");
}

export function presentationUtf16ToCanonicalUtf16(
  presentation: string,
  utf16Offset: number,
  lineEnding: EditorLineEnding,
): number {
  if (!Number.isSafeInteger(utf16Offset) || utf16Offset < 0 || utf16Offset > presentation.length) {
    throw new Error("Inex editor offset is invalid");
  }
  return fromEditorPresentation(presentation.slice(0, utf16Offset), lineEnding).length;
}

function utf16IndexAtUtf8Byte(text: string, byteOffset: number): number {
  if (!Number.isSafeInteger(byteOffset) || byteOffset < 0) {
    throw new Error("Inex editor byte offset is invalid");
  }
  let bytes = 0;
  let index = 0;
  for (const scalar of text) {
    if (bytes === byteOffset) return index;
    bytes += Buffer.byteLength(scalar, "utf8");
    index += scalar.length;
    if (bytes > byteOffset) {
      throw new Error("Inex editor byte offset splits UTF-8");
    }
  }
  if (bytes === byteOffset) return index;
  throw new Error("Inex editor byte offset is out of bounds");
}
