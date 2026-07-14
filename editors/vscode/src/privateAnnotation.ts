import type { OuterMode, PrivateAnnotationKind, PrivateAnnotationSpec } from "./sidecar.ts";

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
