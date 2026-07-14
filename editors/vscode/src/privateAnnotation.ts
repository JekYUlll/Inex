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
  if (target === "headingSection") return markdownHeadingSectionRange(content, offset);
  if (offset < 0 || offset > content.byteLength) return undefined;
  const start = lineStart(content, offset);
  const end = lineEnd(content, offset);
  return lineIsBlank(content, start, end) ? undefined : { startByte: start, endByte: end };
}

/** Returns the current ATX heading section, ending before an equal/higher heading. */
export function markdownHeadingSectionRange(content: Buffer, offset: number): ByteRange | undefined {
  if (offset < 0 || offset > content.byteLength) return undefined;
  const currentLineStart = lineStart(content, offset);
  let headingStart: number | undefined;
  let headingLevel: number | undefined;
  let cursor = 0;
  while (cursor <= currentLineStart && cursor < content.byteLength) {
    const end = lineEnd(content, cursor);
    const level = atxHeadingLevel(content, cursor, end);
    if (level !== undefined) {
      headingStart = cursor;
      headingLevel = level;
    }
    if (end >= content.byteLength) break;
    cursor = end + 1;
  }
  if (headingStart === undefined || headingLevel === undefined) return undefined;
  let end = content.byteLength;
  cursor = lineEnd(content, headingStart);
  cursor = cursor >= content.byteLength ? content.byteLength : cursor + 1;
  while (cursor < content.byteLength) {
    const lineEndOffset = lineEnd(content, cursor);
    const level = atxHeadingLevel(content, cursor, lineEndOffset);
    if (level !== undefined && level <= headingLevel) {
      end = cursor;
      break;
    }
    if (lineEndOffset >= content.byteLength) break;
    cursor = lineEndOffset + 1;
  }
  while (end > headingStart && (content[end - 1] === 0x0a || content[end - 1] === 0x0d)) end -= 1;
  return end > headingStart ? { startByte: headingStart, endByte: end } : undefined;
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

export function annotationPickerStateFromSpec(
  spec: PrivateAnnotationSpec,
  availableTags: readonly PrivateTagChoice[],
): AnnotationPickerState {
  const available = new Set(availableTags.map((tag) => tag.id));
  const tagIds = [...new Set(spec.tagIds)].filter((tagId) => available.has(tagId)).sort();
  return { kind: spec.kind, tagIds, outerMode: spec.outer.mode };
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

/** Parses canonical unlocked private-block headers only for edit-picker preselection. */
export function parseVisiblePrivateAnnotationBlock(content: Buffer): PrivateAnnotationSpec {
  const header = content.toString("utf8");
  const match = /^:::inex-private\nid: p_[a-f0-9]{32}\nkind: (block|comment)\ntags: \[([^\]\n]*)\]\nouter: (drop|cover|placeholder)\n---\n/u.exec(header);
  if (match === null) {
    throw new Error("Current private annotation metadata is invalid");
  }
  const kind = match[1] ?? "";
  const rawTags = match[2] ?? "";
  const tagIds = rawTags === "" ? [] : rawTags.split(", ");
  const outerMode = match[3] ?? "";
  if (
    (kind !== "block" && kind !== "comment") ||
    (outerMode !== "drop" && outerMode !== "cover" && outerMode !== "placeholder") ||
    tagIds.some((tag) => !/^[a-z0-9][a-z0-9._-]{0,63}$/u.test(tag)) ||
    !tagIds.every((tag, index) => index === 0 || tagIds[index - 1]! < tag)
  ) {
    throw new Error("Current private annotation metadata is invalid");
  }
  return { kind, tagIds, outer: { mode: outerMode } };
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

function atxHeadingLevel(content: Buffer, start: number, end: number): number | undefined {
  let cursor = start;
  let level = 0;
  while (cursor < end && content[cursor] === 0x23 && level < 6) {
    cursor += 1;
    level += 1;
  }
  return level > 0 && cursor < end && (content[cursor] === 0x20 || content[cursor] === 0x09)
    ? level
    : undefined;
}
