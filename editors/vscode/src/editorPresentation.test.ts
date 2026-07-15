import assert from "node:assert/strict";
import test from "node:test";

import {
  canonicalByteToPresentationByte,
  editorLineEnding,
  fromEditorPresentation,
  presentationByteToCanonicalByte,
  presentationUtf16ToCanonicalUtf16,
  toEditorPresentation,
} from "./editorPresentation.ts";

test("textarea presentation round-trips CRLF without treating it as a content edit", () => {
  const canonical = "# 标题\r\n正文 😀\r\n";
  const presentation = toEditorPresentation(canonical);
  assert.equal(presentation, "# 标题\n正文 😀\n");
  assert.equal(editorLineEnding(canonical), "crlf");
  assert.equal(fromEditorPresentation(presentation, "crlf"), canonical);
});

test("presentation offsets map across CRLF and UTF-8 boundaries", () => {
  const canonical = "a\r\n标题😀\r\n";
  const presentation = toEditorPresentation(canonical);
  const visibleByte = Buffer.byteLength("a\n标题", "utf8");
  const canonicalByte = Buffer.byteLength("a\r\n标题", "utf8");
  assert.equal(presentationByteToCanonicalByte(presentation, visibleByte, "crlf"), canonicalByte);
  assert.equal(canonicalByteToPresentationByte(canonical, canonicalByte), visibleByte);
  assert.equal(presentationUtf16ToCanonicalUtf16(presentation, "a\n标题".length, "crlf"), "a\r\n标题".length);
  assert.throws(() => presentationByteToCanonicalByte(presentation, visibleByte + 1, "crlf"));
});
