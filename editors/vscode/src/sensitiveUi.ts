import * as vscode from "vscode";

export interface SensitiveInputBoxOptions {
  readonly ignoreFocusOut?: boolean;
  readonly password?: boolean;
  readonly prompt?: string;
  readonly title?: string;
  readonly validateInput?: (value: string) => string | undefined;
}

export interface SensitiveQuickPickOptions {
  readonly matchOnDescription?: boolean;
  readonly matchOnDetail?: boolean;
  readonly placeHolder?: string;
  readonly title?: string;
}

/** Show a secret input only while the authenticated session remains valid. */
export function showSensitiveInputBox(
  options: SensitiveInputBoxOptions,
  onDidInvalidate: vscode.Event<void>,
): Promise<string | undefined> {
  const input = vscode.window.createInputBox();
  input.ignoreFocusOut = options.ignoreFocusOut ?? false;
  input.password = options.password ?? false;
  input.prompt = options.prompt;
  input.title = options.title;

  return new Promise<string | undefined>((resolve) => {
    let settled = false;
    const subscriptions: vscode.Disposable[] = [];
    const finish = (value: string | undefined): void => {
      if (settled) {
        return;
      }
      settled = true;
      for (const subscription of subscriptions) {
        subscription.dispose();
      }
      input.value = "";
      input.hide();
      input.dispose();
      resolve(value);
    };
    const validate = (): string | undefined => options.validateInput?.(input.value);

    subscriptions.push(
      input.onDidChangeValue(() => {
        input.validationMessage = validate();
      }),
      input.onDidAccept(() => {
        const validation = validate();
        input.validationMessage = validation;
        if (validation === undefined) {
          finish(input.value);
        }
      }),
      input.onDidHide(() => {
        finish(undefined);
      }),
      onDidInvalidate(() => {
        finish(undefined);
      }),
    );
    input.show();
  });
}

/**
 * Show plaintext-bearing choices only while the authenticated session remains
 * valid. The built-in showQuickPick helper does not expose a handle that can be
 * closed when the vault locks.
 */
export function showSensitiveQuickPick<T extends vscode.QuickPickItem>(
  items: readonly T[],
  options: SensitiveQuickPickOptions,
  onDidInvalidate: vscode.Event<void>,
): Promise<T | undefined> {
  const picker = vscode.window.createQuickPick<T>();
  picker.items = items;
  picker.matchOnDescription = options.matchOnDescription ?? false;
  picker.matchOnDetail = options.matchOnDetail ?? false;
  picker.placeholder = options.placeHolder;
  picker.title = options.title;

  return new Promise<T | undefined>((resolve) => {
    let settled = false;
    const subscriptions: vscode.Disposable[] = [];
    const finish = (value: T | undefined): void => {
      if (settled) {
        return;
      }
      settled = true;
      for (const subscription of subscriptions) {
        subscription.dispose();
      }
      picker.hide();
      picker.dispose();
      resolve(value);
    };

    subscriptions.push(
      picker.onDidAccept(() => {
        finish(picker.selectedItems[0]);
      }),
      picker.onDidHide(() => {
        finish(undefined);
      }),
      onDidInvalidate(() => {
        finish(undefined);
      }),
    );
    picker.show();
  });
}
