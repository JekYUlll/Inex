export type NoSelectionTarget = "line" | "paragraph" | "reject";

export interface PrivateAnnotationPreferences {
  readonly noSelectionTarget: NoSelectionTarget;
  readonly confirmBeforeUnwrap: boolean;
}

const DEFAULT_PREFERENCES: PrivateAnnotationPreferences = Object.freeze({
  noSelectionTarget: "paragraph",
  confirmBeforeUnwrap: true,
});

/** Parses only editor-local interaction flags; private labels and tags never belong here. */
export function parsePrivateAnnotationPreferences(
  values: Readonly<Record<string, unknown>>,
): PrivateAnnotationPreferences {
  const target = values.noSelectionTarget;
  return {
    noSelectionTarget:
      target === "line" || target === "paragraph" || target === "reject"
        ? target
        : DEFAULT_PREFERENCES.noSelectionTarget,
    confirmBeforeUnwrap:
      typeof values.confirmBeforeUnwrap === "boolean"
        ? values.confirmBeforeUnwrap
        : DEFAULT_PREFERENCES.confirmBeforeUnwrap,
  };
}
