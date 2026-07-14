import assert from "node:assert/strict";
import test from "node:test";

import {
  annotationSpecFromPicker,
  annotationPickerStateFromSpec,
  defaultAnnotationPickerState,
  emptySelectionRange,
  markdownHeadingSectionRange,
  parseVisiblePrivateAnnotationBlock,
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

test("empty selection supports line and explicit-selection modes", () => {
  const content = Buffer.from("first line\nsecond line\n", "utf8");
  assert.deepEqual(emptySelectionRange(content, 13, "line"), { startByte: 11, endByte: 22 });
  assert.equal(emptySelectionRange(content, 13, "reject"), undefined);
});

test("empty selection can target the current Markdown heading section", () => {
  const content = Buffer.from("# One\nfirst\n## Nested\nsecond\n# Two\nthird\n", "utf8");
  assert.deepEqual(markdownHeadingSectionRange(content, 20), { startByte: 12, endByte: 28 });
  assert.deepEqual(emptySelectionRange(content, 20, "headingSection"), { startByte: 12, endByte: 28 });
  assert.equal(markdownHeadingSectionRange(Buffer.from("plain\ntext\n"), 2), undefined);
});

test("existing annotation metadata preselects only catalog-resolvable tags", () => {
  assert.deepEqual(
    annotationPickerStateFromSpec(
      { kind: "block", tagIds: ["missing", "relationship", "relationship"], outer: { mode: "cover" } },
      tags,
    ),
    { kind: "block", tagIds: ["relationship"], outerMode: "cover" },
  );
});

test("canonical unlocked private-block headers can prefill editing without cover text", () => {
  const block = Buffer.from(
    ":::inex-private\nid: p_0123456789abcdef0123456789abcdef\nkind: block\ntags: [family, relationship]\nouter: cover\n---\nprivate text\n:::\n",
    "utf8",
  );
  assert.deepEqual(parseVisiblePrivateAnnotationBlock(block), {
    kind: "block",
    tagIds: ["family", "relationship"],
    outer: { mode: "cover" },
  });
  assert.throws(() => parseVisiblePrivateAnnotationBlock(Buffer.from("not a private block")));
});
