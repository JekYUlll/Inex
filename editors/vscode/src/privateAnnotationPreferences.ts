export type NoSelectionTarget = "line" | "paragraph" | "headingSection" | "reject";
export type ToggleBehavior = "alwaysAsk" | "useLast" | "useDefaultProfile" | "askOnFirstUse";

export interface PrivateAnnotationPreferences {
  readonly noSelectionTarget: NoSelectionTarget;
  readonly confirmBeforeUnwrap: boolean;
  readonly toggleBehavior: ToggleBehavior;
  readonly rememberLastSelection: boolean;
  /** Merge directly adjacent editor ranges before the authenticated mutation. */
  readonly mergeAdjacentSelections: boolean;
}

export type ToggleAnnotationAction = "ask" | "last" | "defaultProfile";

const DEFAULT_PREFERENCES: PrivateAnnotationPreferences = Object.freeze({
  noSelectionTarget: "paragraph",
  confirmBeforeUnwrap: true,
  toggleBehavior: "alwaysAsk",
  rememberLastSelection: true,
  mergeAdjacentSelections: false,
});

/** Parses only editor-local interaction flags; private labels and tags never belong here. */
export function parsePrivateAnnotationPreferences(
  values: Readonly<Record<string, unknown>>,
): PrivateAnnotationPreferences {
  const target = values.noSelectionTarget;
  const behavior = values.toggleBehavior;
  return {
    noSelectionTarget:
      target === "line" || target === "paragraph" || target === "headingSection" || target === "reject"
        ? target
        : DEFAULT_PREFERENCES.noSelectionTarget,
    confirmBeforeUnwrap:
      typeof values.confirmBeforeUnwrap === "boolean"
        ? values.confirmBeforeUnwrap
        : DEFAULT_PREFERENCES.confirmBeforeUnwrap,
    toggleBehavior:
      behavior === "alwaysAsk" || behavior === "useLast" || behavior === "useDefaultProfile" || behavior === "askOnFirstUse"
        ? behavior
        : DEFAULT_PREFERENCES.toggleBehavior,
    rememberLastSelection:
      typeof values.rememberLastSelection === "boolean"
        ? values.rememberLastSelection
        : DEFAULT_PREFERENCES.rememberLastSelection,
    mergeAdjacentSelections:
      typeof values.mergeAdjacentSelections === "boolean"
        ? values.mergeAdjacentSelections
        : DEFAULT_PREFERENCES.mergeAdjacentSelections,
  };
}

/** Resolves shortcut behavior without retaining any private catalog values. */
export function resolveToggleAnnotationAction(
  preferences: PrivateAnnotationPreferences,
  hasSessionLastSelection: boolean,
  hasDefaultProfile: boolean,
): ToggleAnnotationAction {
  if (
    (preferences.toggleBehavior === "useLast" || preferences.toggleBehavior === "askOnFirstUse") &&
    preferences.rememberLastSelection &&
    hasSessionLastSelection
  ) {
    return "last";
  }
  if (preferences.toggleBehavior === "useDefaultProfile" && hasDefaultProfile) {
    return "defaultProfile";
  }
  return "ask";
}
