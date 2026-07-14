import type { OuterMode, PrivateAnnotationKind, PrivateAnnotationSpec } from "./sidecar.ts";
import type { NoSelectionTarget } from "./privateAnnotationPreferences.ts";

export interface PrivateTagChoice {
  readonly id: string;
  readonly label: string;
  readonly defaultSelected: boolean;
}

export interface AnnotationPickerState {
  readonly kind: PrivateAnnotationKind;
  readonly tagIds: readonly string[];
  readonly outerMode: OuterMode;
}

export interface ByteRange {
  readonly startByte: number;
  readonly endByte: number;
}

/** Returns contiguous nonblank UTF-8 lines containing `offset`, excluding line endings. */
export function markdownParagraphRange(content: Buffer, offset: number): ByteRange | undefined {
  if (offset < 0 || offset > content.byteLength) return undefined;
  const currentStart = lineStart(content, offset);
  const currentEnd = lineEnd(content, offset);
  if (lineIsBlank(content, currentStart, currentEnd)) return undefined;

  let start = currentStart;
  while (start > 0) {
    const previousEnd = start - 1;
    const previousStart = lineStart(content, previousEnd);
    if (lineIsBlank(content, previousStart, previousEnd)) break;
    start = previousStart;
  }

  let end = currentEnd;
  while (end < content.byteLength) {
    const nextStart = end + 1;
    const nextEnd = lineEnd(content, nextStart);
    if (lineIsBlank(content, nextStart, nextEnd)) break;
    end = nextEnd;
  }
  return { startByte: start, endByte: end };
}

export function emptySelectionRange(
  content: Buffer,
  offset: number,
  target: NoSelectionTarget,
): ByteRange | undefined {
  if (target === "reject") return undefined;
  if (target === "paragraph") return markdownParagraphRange(content, offset);
  if (offset < 0 || offset > content.byteLength) return undefined;
  const start = lineStart(content, offset);
  const end = lineEnd(content, offset);
  return lineIsBlank(content, start, end) ? undefined : { startByte: start, endByte: end };
}

export function defaultAnnotationPickerState(
  tags: readonly PrivateTagChoice[],
): AnnotationPickerState {
  return {
    kind: "comment",
    tagIds: tags
      .filter((tag) => tag.defaultSelected)
      .map((tag) => tag.id)
      .sort(),
    outerMode: "drop",
  };
}

export function selectAnnotationKind(
  state: AnnotationPickerState,
  kind: PrivateAnnotationKind,
): AnnotationPickerState {
  return { ...state, kind };
}

export function selectOuterMode(
  state: AnnotationPickerState,
  outerMode: OuterMode,
): AnnotationPickerState {
  return { ...state, outerMode };
}

export function toggleAnnotationTag(
  state: AnnotationPickerState,
  tagId: string,
  availableTags: readonly PrivateTagChoice[],
): AnnotationPickerState {
  if (!availableTags.some((tag) => tag.id === tagId)) {
    throw new Error("Private annotation tag is unavailable");
  }
  const tags = new Set(state.tagIds);
  if (tags.has(tagId)) {
    tags.delete(tagId);
  } else {
    tags.add(tagId);
  }
  return { ...state, tagIds: [...tags].sort() };
}

export function annotationSpecFromPicker(
  state: AnnotationPickerState,
  coverText?: string,
): PrivateAnnotationSpec {
  if ((state.outerMode === "cover") !== (coverText !== undefined) || coverText === "") {
    throw new Error("Private annotation cover text is invalid");
  }
  return {
    kind: state.kind,
    tagIds: [...state.tagIds],
    outer: { mode: state.outerMode, ...(coverText === undefined ? {} : { coverText }) },
  };
}

function lineStart(content: Buffer, offset: number): number {
  let start = Math.min(offset, content.byteLength);
  while (start > 0 && content[start - 1] !== 0x0a) start -= 1;
  return start;
}

function lineEnd(content: Buffer, offset: number): number {
  let end = Math.min(offset, content.byteLength);
  while (end < content.byteLength && content[end] !== 0x0a) end += 1;
  return end;
}

function lineIsBlank(content: Buffer, start: number, end: number): boolean {
  for (let index = start; index < end; index += 1) {
    const byte = content[index];
    if (byte !== 0x20 && byte !== 0x09 && byte !== 0x0d) return false;
  }
  return true;
}
