import { lstatSync } from "node:fs";
import * as path from "node:path";

import * as vscode from "vscode";

import { resolveCliExecutable } from "./cliExecutable.ts";

export class RepositoryImportError extends Error {
  public override readonly name = "RepositoryImportError";
}

export async function importMarkdownRepository(
  context: vscode.ExtensionContext,
): Promise<vscode.Uri | undefined> {
  const source = await pickOneLocalFolder({
    openLabel: "Select Markdown Repository",
    title: "Select the existing Markdown Git repository to copy",
  });
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
    prompt: "Name of the new, currently absent encrypted repository",
    title: "Import Existing Markdown Repository",
    value: suggested,
    valueSelection: [0, suggested.length],
    validateInput: validateTargetFolderName,
  });
  if (folderName === undefined) {
    return undefined;
  }
  const target = vscode.Uri.file(path.join(targetParent.fsPath, folderName));
  requireAbsent(target.fsPath);
  rejectNestedTarget(source.fsPath, target.fsPath);
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
    "Import Existing Markdown Repository",
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
  const running = await vscode.tasks.executeTask(task);
  const exitCode = await waitForProcessTask(running);
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

function requireRegularDirectory(folderPath: string, label: string): void {
  let metadata;
  try {
    metadata = lstatSync(folderPath);
  } catch {
    throw new RepositoryImportError(`${label} is unavailable`);
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new RepositoryImportError(`${label} must be a real local directory`);
  }
}

function requireAbsent(targetPath: string): void {
  try {
    lstatSync(targetPath);
  } catch (error: unknown) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return;
    }
    throw new RepositoryImportError("Could not verify that the target is absent");
  }
  throw new RepositoryImportError("The encrypted repository target already exists");
}

function rejectNestedTarget(sourcePath: string, targetPath: string): void {
  const relative = path.relative(sourcePath, targetPath);
  if (
    relative.length === 0 ||
    (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative))
  ) {
    throw new RepositoryImportError(
      "The new encrypted repository must not be created inside the source repository",
    );
  }
}

function validateTargetFolderName(value: string): string | undefined {
  if (
    value.length === 0 ||
    value === "." ||
    value === ".." ||
    value.includes("/") ||
    value.includes("\\") ||
    /\p{Cc}/u.test(value) ||
    /[<>:"|?*]/u.test(value) ||
    value.startsWith(" ") ||
    value.endsWith(" ") ||
    value.endsWith(".")
  ) {
    return "Enter one portable new folder name without separators";
  }
  if (Buffer.byteLength(value, "utf8") > 255) {
    return "Folder name exceeds the portable byte limit";
  }
  const base = (value.split(".", 1)[0] ?? value).replace(/ +$/u, "").toUpperCase();
  if (
    ["CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"].includes(base) ||
    /^(?:COM|LPT)(?:[1-9]|[¹²³])$/u.test(base) ||
    /~[0-9]$/u.test(base)
  ) {
    return "Folder name is not portable to Windows and Git";
  }
  return undefined;
}

function waitForProcessTask(execution: vscode.TaskExecution): Promise<number | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (exitCode: number | undefined) => {
      if (settled) {
        return;
      }
      settled = true;
      processSubscription.dispose();
      taskSubscription.dispose();
      resolve(exitCode);
    };
    const processSubscription = vscode.tasks.onDidEndTaskProcess((event) => {
      if (event.execution === execution) {
        finish(event.exitCode);
      }
    });
    const taskSubscription = vscode.tasks.onDidEndTask((event) => {
      if (event.execution === execution) {
        setTimeout(() => finish(undefined), 0);
      }
    });
  });
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}
