import assert from "node:assert/strict";
import test from "node:test";

import {
  annotationSpecFromPicker,
  defaultAnnotationPickerState,
  markdownParagraphRange,
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

test("empty selection expands to its Markdown paragraph, not merely one line", () => {
  const content = Buffer.from("first line\nsecond line\n\nthird line\n", "utf8");
  assert.deepEqual(markdownParagraphRange(content, 13), { startByte: 0, endByte: 22 });
  assert.deepEqual(markdownParagraphRange(content, 25), { startByte: 24, endByte: 34 });
  assert.equal(markdownParagraphRange(content, 23), undefined);
});
