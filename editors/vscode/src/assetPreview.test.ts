import assert from "node:assert/strict";
import test from "node:test";

import {
  parseMarkdownImageTargets,
  resolveAssetImageTarget,
} from "./assetPreview.ts";

test("relative Markdown image targets resolve canonically inside the vault", () => {
  assert.equal(
    resolveAssetImageTarget("notes/day.md", "../images/station%20one.png"),
    "images/station one.png",
  );
  assert.equal(
    resolveAssetImageTarget("notes/day.md", "./chart.webp#ignored"),
    "notes/chart.webp",
  );
});

test("external, absolute, encoded-separator, escaping, and Markdown targets stay inert", () => {
  for (const target of [
    "https://example.test/a.png",
    "//example.test/a.png",
    "data:image/png;base64,AAAA",
    "/images/a.png",
    "../../escape.png",
    "images%2Fa.png",
    "note.md",
    "image.png?download=1",
  ]) {
    assert.throws(() => resolveAssetImageTarget("notes/day.md", target));
  }
});

test("image extraction ignores code and malformed or unsafe destinations", () => {
  const markdown = [
    "![one](../images/one.png)",
    "`![inline](../images/no.png)`",
    "```md",
    "![fenced](../images/no2.png)",
    "``` trailing text is not a closing fence",
    "![still-fenced](../images/no6.png)",
    "```",
    "<script type=\"text/plain\">",
    "![raw-script](../images/no7.png)",
    "</script>",
    "<PRE>",
    "![raw-pre](../images/no8.png)",
    "</PrE>",
    "![external](https://example.test/no.png)",
    "\\![escaped](../images/no3.png)",
    "    ![indented](../images/no4.png)",
    "<!-- ![commented](../images/no5.png)",
    "still commented -->",
    "![duplicate](../images/one.png)",
    "![angle](<../images/two.webp> \"title\")",
  ].join("\n");
  assert.deepEqual(parseMarkdownImageTargets("notes/day.md", markdown), [
    "images/one.png",
    "images/two.webp",
  ]);
});
