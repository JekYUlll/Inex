import assert from "node:assert/strict";
import test from "node:test";

import { revisionCompareHtml } from "./revisionCompare.ts";

test("revision comparison highlights only changed line ranges and aligns unchanged suffixes", () => {
  const html = revisionCompareHtml(
    Buffer.from("title\nnew line\nend\n", "utf8"),
    Buffer.from("title\nold line\nend\n", "utf8"),
  );
  assert.match(html, /class="row head-change"/u);
  assert.match(html, /class="row parent-change"/u);
  assert.match(html, /<span class="number">3<\/span><pre class="line">end<\/pre>/u);
  assert.doesNotMatch(html, /<script/iu);
  assert.match(html, /default-src 'none'/u);
});

test("revision comparison escapes plaintext and represents a one-sided line addition", () => {
  const html = revisionCompareHtml(
    Buffer.from("safe\n<script>alert(1)</script>\n", "utf8"),
    Buffer.from("safe\n", "utf8"),
  );
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/u);
  assert.doesNotMatch(html, /<script>alert/iu);
  assert.match(html, /class="row empty"/u);
});
