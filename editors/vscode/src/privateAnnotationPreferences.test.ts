import assert from "node:assert/strict";
import test from "node:test";

import {
  parsePrivateAnnotationPreferences,
  resolveToggleAnnotationAction,
} from "./privateAnnotationPreferences.ts";

test("private annotation preferences accept only editor-local supported values", () => {
  assert.deepEqual(parsePrivateAnnotationPreferences({}), {
    noSelectionTarget: "paragraph",
    confirmBeforeUnwrap: true,
    toggleBehavior: "alwaysAsk",
    rememberLastSelection: true,
  });
  assert.deepEqual(
    parsePrivateAnnotationPreferences({
      noSelectionTarget: "line",
      confirmBeforeUnwrap: false,
      toggleBehavior: "useDefaultProfile",
      rememberLastSelection: false,
    }),
    {
      noSelectionTarget: "line",
      confirmBeforeUnwrap: false,
      toggleBehavior: "useDefaultProfile",
      rememberLastSelection: false,
    },
  );
  assert.deepEqual(
    parsePrivateAnnotationPreferences({
      noSelectionTarget: "headingSection",
      confirmBeforeUnwrap: "no",
      toggleBehavior: "unsafe",
      rememberLastSelection: "yes",
    }),
    {
      noSelectionTarget: "paragraph",
      confirmBeforeUnwrap: true,
      toggleBehavior: "alwaysAsk",
      rememberLastSelection: true,
    },
  );
});

test("toggle behavior uses only unlocked session state or encrypted defaults", () => {
  const base = parsePrivateAnnotationPreferences({});
  assert.equal(resolveToggleAnnotationAction(base, true, true), "ask");
  assert.equal(
    resolveToggleAnnotationAction({ ...base, toggleBehavior: "useLast" }, true, true),
    "last",
  );
  assert.equal(
    resolveToggleAnnotationAction({ ...base, toggleBehavior: "askOnFirstUse" }, false, true),
    "ask",
  );
  assert.equal(
    resolveToggleAnnotationAction({ ...base, toggleBehavior: "askOnFirstUse" }, true, true),
    "last",
  );
  assert.equal(
    resolveToggleAnnotationAction({ ...base, toggleBehavior: "useDefaultProfile" }, false, true),
    "defaultProfile",
  );
  assert.equal(
    resolveToggleAnnotationAction({ ...base, toggleBehavior: "useDefaultProfile" }, false, false),
    "ask",
  );
  assert.equal(
    resolveToggleAnnotationAction({ ...base, toggleBehavior: "useLast", rememberLastSelection: false }, true, true),
    "ask",
  );
});
