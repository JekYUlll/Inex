import * as vscode from "vscode";

import {
  annotationSpecFromPicker,
  annotationPickerStateFromSpec,
  defaultAnnotationPickerState,
  selectAnnotationKind,
  selectOuterMode,
  toggleAnnotationTag,
  type AnnotationPickerState,
  type PrivateTagChoice,
} from "./privateAnnotation.ts";
import type { PrivateAnnotationSpec, UmbraAnnotationConfig } from "./sidecar.ts";
import { showSensitiveInputBox } from "./sensitiveUi.ts";

type ChoiceGroup = "kind" | "tag" | "outer";

interface AnnotationQuickPickItem extends vscode.QuickPickItem {
  readonly group: ChoiceGroup;
  readonly value: string;
}

/** Configure one annotation without retaining private labels after lock. */
export async function choosePrivateAnnotation(
  config: UmbraAnnotationConfig,
  onDidInvalidate: vscode.Event<void>,
  initialSpec?: PrivateAnnotationSpec,
): Promise<PrivateAnnotationSpec | undefined> {
  const tags: PrivateTagChoice[] = config.tags
    .filter((tag) => !tag.archived || initialSpec?.tagIds.includes(tag.id) === true)
    .map((tag) => ({ id: tag.id, label: tag.label, defaultSelected: tag.defaultSelected }));
  let state = initialSpec === undefined
    ? defaultAnnotationPickerState(tags)
    : annotationPickerStateFromSpec(initialSpec, tags);
  const accepted = await chooseState(state, tags, onDidInvalidate);
  if (accepted === undefined) {
    return undefined;
  }
  state = accepted;
  let coverText: string | undefined;
  if (state.outerMode === "cover") {
    coverText = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        prompt: "Public cover text (visible in Outer Mode)",
        title: "Inex Outer Cover",
        validateInput: (value) =>
          Buffer.byteLength(value, "utf8") > 0 && Buffer.byteLength(value, "utf8") <= 4096
            ? undefined
            : "Cover text must be 1–4096 UTF-8 bytes",
      },
      onDidInvalidate,
    );
    if (coverText === undefined) {
      return undefined;
    }
  }
  return annotationSpecFromPicker(state, coverText);
}

function chooseState(
  initial: AnnotationPickerState,
  tags: readonly PrivateTagChoice[],
  onDidInvalidate: vscode.Event<void>,
): Promise<AnnotationPickerState | undefined> {
  const picker = vscode.window.createQuickPick<AnnotationQuickPickItem>();
  picker.canSelectMany = true;
  picker.matchOnDescription = false;
  picker.matchOnDetail = false;
  picker.title = "Configure Private Annotation";
  picker.placeholder = "Choose one kind, any private tags, and one Outer strategy";
  let state = initial;
  let applying = false;
  const items: AnnotationQuickPickItem[] = [
    { label: "$(comment) Kind: Private comment", group: "kind", value: "comment" },
    { label: "$(symbol-namespace) Kind: Private block", group: "kind", value: "block" },
    ...tags.map((tag) => ({
      label: `$(tag) Tag: ${tag.label}`,
      description: tag.id,
      group: "tag" as const,
      value: tag.id,
    })),
    { label: "$(eye-closed) Outer: Drop", group: "outer", value: "drop" },
    { label: "$(note) Outer: Public cover", group: "outer", value: "cover" },
    { label: "$(circle-slash) Outer: Placeholder", group: "outer", value: "placeholder" },
  ];
  picker.items = items;
  let previousSelected = new Set<string>();

  const sync = (): void => {
    applying = true;
    picker.selectedItems = items.filter((item) =>
      (item.group === "kind" && item.value === state.kind) ||
      (item.group === "outer" && item.value === state.outerMode) ||
      (item.group === "tag" && state.tagIds.includes(item.value)),
    );
    previousSelected = new Set(picker.selectedItems.map((item) => `${item.group}:${item.value}`));
    applying = false;
  };
  sync();
  return new Promise<AnnotationPickerState | undefined>((resolve) => {
    let settled = false;
    const subscriptions: vscode.Disposable[] = [];
    const finish = (value: AnnotationPickerState | undefined): void => {
      if (settled) return;
      settled = true;
      subscriptions.forEach((subscription) => subscription.dispose());
      picker.items = [];
      picker.hide();
      picker.dispose();
      resolve(value);
    };
    subscriptions.push(
      picker.onDidChangeSelection((selected) => {
        if (applying) return;
        const current = new Set(selected.map((item) => `${item.group}:${item.value}`));
        const changedKey = [...current].find((key) => !previousSelected.has(key))
          ?? [...previousSelected].find((key) => !current.has(key));
        previousSelected = current;
        const chosen = changedKey === undefined
          ? undefined
          : items.find((item) => `${item.group}:${item.value}` === changedKey);
        if (chosen === undefined) return;
        if (chosen.group === "kind") {
          state = selectAnnotationKind(state, chosen.value as "block" | "comment");
        } else if (chosen.group === "outer") {
          state = selectOuterMode(state, chosen.value as "drop" | "cover" | "placeholder");
        } else if (current.has(changedKey!)) {
          state = toggleAnnotationTag(state, chosen.value, tags);
        }
        sync();
      }),
      picker.onDidAccept(() => finish(state)),
      picker.onDidHide(() => finish(undefined)),
      onDidInvalidate(() => finish(undefined)),
    );
    picker.show();
  });
}
