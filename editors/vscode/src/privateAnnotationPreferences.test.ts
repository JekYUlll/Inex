import assert from "node:assert/strict";
import test from "node:test";

import { parsePrivateAnnotationPreferences } from "./privateAnnotationPreferences.ts";

test("private annotation preferences accept only editor-local supported values", () => {
  assert.deepEqual(parsePrivateAnnotationPreferences({}), {
    noSelectionTarget: "paragraph",
    confirmBeforeUnwrap: true,
  });
  assert.deepEqual(
    parsePrivateAnnotationPreferences({ noSelectionTarget: "line", confirmBeforeUnwrap: false }),
    { noSelectionTarget: "line", confirmBeforeUnwrap: false },
  );
  assert.deepEqual(
    parsePrivateAnnotationPreferences({ noSelectionTarget: "headingSection", confirmBeforeUnwrap: "no" }),
    { noSelectionTarget: "paragraph", confirmBeforeUnwrap: true },
  );
});
