import assert from "node:assert/strict";
import test from "node:test";

import {
  headingForFragment,
  linkAtUtf16,
  parseMarkdownNavigation,
  resolveMarkdownTarget,
} from "./markdown.ts";

test("Markdown navigation parses Unicode headings, duplicates, links, and byte ranges", () => {
  const text = "# 标题\n见 [记录](../2025/entry.md#Details) 与 [[同目录#小节|别名]]。\n## Details\n## Details\n";
  const parsed = parseMarkdownNavigation(text);
  assert.deepEqual(parsed.headings.map((heading) => heading.slug), ["标题", "details", "details-1"]);
  assert.equal(parsed.links.length, 2);
  assert.equal(linkAtUtf16(parsed, text.indexOf("记录"))?.target, "../2025/entry.md#Details");
  assert.equal(headingForFragment(parsed, "details-1")?.line, 3);
  assert.equal(Buffer.from(text).subarray(parsed.links[0]?.startByte, parsed.links[0]?.endByte).toString(), "[记录](../2025/entry.md#Details)");
});

test("Markdown targets resolve inside the vault and reject external or escaping links", () => {
  assert.deepEqual(resolveMarkdownTarget("2026/notes/current.md", "../shared.md#标题", false), {
    logicalPath: "2026/shared.md",
    fragment: "标题",
  });
  assert.deepEqual(resolveMarkdownTarget("2026/current.md", "[[ignored]]".slice(2, -2), true), {
    logicalPath: "2026/ignored.md",
    fragment: undefined,
  });
  assert.throws(() => resolveMarkdownTarget("current.md", "../escape.md", false));
  assert.throws(() => resolveMarkdownTarget("current.md", "https://example.com", false));
  assert.throws(() => resolveMarkdownTarget("current.md", "bad%2Fpath.md", false));
});

test("Markdown navigation ignores fenced code blocks", () => {
  const parsed = parseMarkdownNavigation(
    "```markdown\n# not a heading\n[not a link](secret.md)\n```\n# real\n[[real]]\n",
  );
  assert.deepEqual(parsed.headings.map((heading) => heading.text), ["real"]);
  assert.deepEqual(parsed.links.map((link) => link.target), ["real"]);
});
