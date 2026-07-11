import * as vscode from "vscode";

const VIEW_TYPE = "inex.markdownEditor";

class PlaceholderDocument implements vscode.CustomDocument {
  public constructor(public readonly uri: vscode.Uri) {}

  public dispose(): void {
    // Phase 4 replaces this placeholder with document.close and buffer wipe.
  }
}

class PlaceholderProvider implements vscode.CustomReadonlyEditorProvider<PlaceholderDocument> {
  public async openCustomDocument(
    uri: vscode.Uri,
    _openContext: vscode.CustomDocumentOpenContext,
    _token: vscode.CancellationToken,
  ): Promise<PlaceholderDocument> {
    return new PlaceholderDocument(uri);
  }

  public async resolveCustomEditor(
    _document: PlaceholderDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken,
  ): Promise<void> {
    webviewPanel.webview.options = {
      enableScripts: false,
      localResourceRoots: [],
    };
    webviewPanel.webview.html = [
      "<!doctype html>",
      '<html lang="en"><head><meta charset="utf-8">',
      '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'">',
      "<title>Inex pre-alpha</title></head>",
      "<body><h1>Inex pre-alpha</h1>",
      "<p>The encrypted custom editor is not implemented yet. No ciphertext was decrypted.</p>",
      "</body></html>",
    ].join("");
  }
}

export function activate(context: vscode.ExtensionContext): void {
  const showNotImplemented = async (): Promise<void> => {
    await vscode.window.showInformationMessage(
      "Inex is pre-alpha: this command is not implemented and no content was decrypted.",
    );
  };

  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(VIEW_TYPE, new PlaceholderProvider(), {
      supportsMultipleEditorsPerDocument: false,
      webviewOptions: { retainContextWhenHidden: false },
    }),
    vscode.commands.registerCommand("inex.showSecurityStatus", async () => {
      await vscode.window.showInformationMessage(
        "Inex is pre-alpha: the custom editor is registered read-only and never decrypts content.",
      );
    }),
    vscode.commands.registerCommand("inex.unlockVault", showNotImplemented),
    vscode.commands.registerCommand("inex.lockVault", showNotImplemented),
    vscode.commands.registerCommand("inex.search", showNotImplemented),
  );
}
