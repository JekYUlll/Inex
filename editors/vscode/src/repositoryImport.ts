import * as path from "node:path";

import * as vscode from "vscode";

import { resolveCliExecutable } from "./cliExecutable.ts";
import { runProcessTask } from "./processTask.ts";
import {
  classifyImportTarget,
  rejectOverlappingTarget,
  RepositoryImportError,
  requireRegularDirectory,
  validateTargetFolderName,
} from "./repositoryImportPaths.ts";

export { RepositoryImportError } from "./repositoryImportPaths.ts";

const RECONCILE_EXISTING_ACTION = "Audit and Reconcile Existing Target";

export async function importMarkdownRepository(
  context: vscode.ExtensionContext,
  preferredSource?: vscode.Uri,
): Promise<vscode.Uri | undefined> {
  const defaultUri = defaultSourceFolder();
  const source =
    preferredSource === undefined
      ? await pickOneLocalFolder({
          ...(defaultUri === undefined ? {} : { defaultUri }),
          openLabel: "Select Markdown/Git Folder",
          title: "Select the existing Markdown Git repository to initialize from",
        })
      : requireLocalFolderUri(preferredSource);
  if (source === undefined) {
    return undefined;
  }
  requireRegularDirectory(source.fsPath, "Selected Markdown repository");

  const targetParent = await pickOneLocalFolder({
    defaultUri: vscode.Uri.file(path.dirname(source.fsPath)),
    openLabel: "Select Target Parent",
    title: "Select the parent for the new encrypted Inex repository",
  });
  if (targetParent === undefined) {
    return undefined;
  }
  requireRegularDirectory(targetParent.fsPath, "Selected target parent");

  const suggested = `${path.basename(source.fsPath)}-inex`;
  const folderName = await vscode.window.showInputBox({
    ignoreFocusOut: true,
    prompt: "Name a new encrypted repository, or an interrupted Inex target to reconcile",
    title: "Initialize Inex from Existing Markdown",
    value: suggested,
    valueSelection: [0, suggested.length],
    validateInput: validateTargetFolderName,
  });
  if (folderName === undefined) {
    return undefined;
  }
  const target = vscode.Uri.file(path.join(targetParent.fsPath, folderName));
  rejectOverlappingTarget(source.fsPath, target.fsPath);
  const targetState = classifyImportTarget(target.fsPath);
  if (targetState === "existing-directory") {
    const choice = await vscode.window.showWarningMessage(
      "The target currently exists. Inex will only audit and reconcile an exact interrupted v2 publication; every other existing directory fails without modification. Exact reconciliation never requests a password—cancel the task if a password prompt appears because the target changed before dispatch.",
      { modal: true },
      RECONCILE_EXISTING_ACTION,
    );
    if (choice !== RECONCILE_EXISTING_ACTION) {
      return undefined;
    }
  } else {
    const choice = await vscode.window.showWarningMessage(
      "Inex will import only the clean tracked HEAD snapshot, including tracked images and attachments, into one new encrypted root commit. The source and its plaintext Git history remain unchanged and are not copied.",
      { modal: true },
      "Initialize Encrypted Snapshot",
    );
    if (choice !== "Initialize Encrypted Snapshot") {
      return undefined;
    }
  }
  if (process.env.INEX_PASSWORD_STDIN !== undefined) {
    throw new RepositoryImportError(
      "Repository import requires hidden terminal password input; remove INEX_PASSWORD_STDIN from the VS Code environment and reload the window",
    );
  }

  const configured = vscode.workspace
    .getConfiguration("inex")
    .get<string>("cliPath", "");
  const executable = resolveCliExecutable(configured, context.extensionPath);
  const execution = new vscode.ProcessExecution(
    executable,
    ["import-repository", source.fsPath, target.fsPath],
    { cwd: targetParent.fsPath },
  );
  const task = new vscode.Task(
    { type: "inex", operation: "importRepository" },
    vscode.TaskScope.Global,
    "Initialize Inex from Existing Markdown",
    "Inex",
    execution,
    [],
  );
  task.presentationOptions = {
    clear: true,
    echo: true,
    focus: true,
    panel: vscode.TaskPanelKind.Dedicated,
    reveal: vscode.TaskRevealKind.Always,
    showReuseMessage: false,
  };
  const exitCode = await runProcessTask({
    start: () => vscode.tasks.executeTask(task),
    onProcessStart: (listener) =>
      vscode.tasks.onDidStartTaskProcess((event) => listener(event.execution)),
    onProcessEnd: (listener) =>
      vscode.tasks.onDidEndTaskProcess((event) =>
        listener(event.execution, event.exitCode),
      ),
    onTaskEnd: (listener) =>
      vscode.tasks.onDidEndTask((event) => listener(event.execution)),
  });
  if (exitCode !== 0) {
    if (exitCode === undefined) {
      throw new RepositoryImportError("Inex repository import ended without an exit status");
    }
    throw new RepositoryImportError(
      `Inex repository import failed with exit code ${exitCode}; review the dedicated task terminal`,
    );
  }
  return target;
}

function defaultSourceFolder(): vscode.Uri | undefined {
  const folders = vscode.workspace.workspaceFolders?.filter(
    (folder) =>
      folder.uri.scheme === "file" && !folder.uri.query && !folder.uri.fragment,
  );
  return folders?.length === 1 ? folders[0]?.uri : undefined;
}

async function pickOneLocalFolder(
  options: vscode.OpenDialogOptions,
): Promise<vscode.Uri | undefined> {
  const selected = await vscode.window.showOpenDialog({
    ...options,
    canSelectFiles: false,
    canSelectFolders: true,
    canSelectMany: false,
  });
  const folder = selected?.[0];
  if (folder !== undefined && (folder.scheme !== "file" || folder.query || folder.fragment)) {
    throw new RepositoryImportError("Inex repository import supports local folders only");
  }
  return folder;
}

function requireLocalFolderUri(folder: vscode.Uri): vscode.Uri {
  if (folder.scheme !== "file" || folder.query || folder.fragment) {
    throw new RepositoryImportError("Inex repository import supports local folders only");
  }
  return folder;
}
