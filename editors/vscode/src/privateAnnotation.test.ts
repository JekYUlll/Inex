import assert from "node:assert/strict";
import test from "node:test";

import {
  annotationSpecFromPicker,
  defaultAnnotationPickerState,
  selectAnnotationKind,
  selectOuterMode,
  toggleAnnotationTag,
} from "./privateAnnotation.ts";

const tags = [
  { id: "comment-content", label: "Comment", defaultSelected: true },
  { id: "relationship", label: "Relationship", defaultSelected: false },
] as const;

test("annotation picker keeps one kind/outer and canonical tag IDs", () => {
  let state = defaultAnnotationPickerState(tags);
  state = selectAnnotationKind(state, "block");
  state = selectOuterMode(state, "placeholder");
  state = toggleAnnotationTag(state, "relationship", tags);
  assert.deepEqual(annotationSpecFromPicker(state), {
    kind: "block",
    tagIds: ["comment-content", "relationship"],
    outer: { mode: "placeholder" },
  });
});

test("annotation picker requires public cover text only for cover mode", () => {
  const state = selectOuterMode(defaultAnnotationPickerState(tags), "cover");
  assert.throws(() => annotationSpecFromPicker(state));
  assert.deepEqual(annotationSpecFromPicker(state, "private note omitted"), {
    kind: "comment",
    tagIds: ["comment-content"],
    outer: { mode: "cover", coverText: "private note omitted" },
  });
});
