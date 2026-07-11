import * as path from "node:path";

import * as vscode from "vscode";

import type { VaultController, VaultSession } from "./controller.ts";
import type { InexCustomEditorProvider } from "./customEditor.ts";
import {
  LogicalPathError,
  logicalDirectoryChild,
  logicalDirectoryComponents,
  logicalFileChild,
  logicalFileComponents,
} from "./logicalPath.ts";
import { showSensitiveInputBox, showSensitiveQuickPick } from "./sensitiveUi.ts";
import type { TreeEntry } from "./sidecar.ts";
import type { InexTreeNode, InexTreeProvider } from "./tree.ts";

const VIEW_TYPE = "inex.markdownEditor";

interface DirectoryPick extends vscode.QuickPickItem {
  readonly logicalPath: string;
}

interface FilePick extends vscode.QuickPickItem {
  readonly logicalPath: string;
}

export class InexCrudActions {
  public constructor(
    private readonly controller: VaultController,
    private readonly tree: InexTreeProvider,
    private readonly editor: InexCustomEditorProvider,
  ) {}

  public async newEncryptedMarkdown(node?: unknown): Promise<void> {
    const target = await this.selectDirectory(node, "New Encrypted Markdown");
    if (target === undefined) {
      return;
    }
    const name = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        password: true,
        prompt: `One Markdown filename inside ${displayDirectory(target.logicalPath)}`,
        title: "New Encrypted Markdown",
        value: "untitled.md",
        valueSelection: [0, "untitled".length],
        validateInput: (value) => validateFileChild(target.logicalPath, value),
      },
      this.controller.onDidLock,
    );
    if (name === undefined) {
      return;
    }
    this.requireSession(target.session, "before creating the encrypted document");
    await this.createEmptyMarkdownBound(
      target.session,
      logicalFileChild(target.logicalPath, name),
    );
  }

  public async newFolder(node?: unknown): Promise<void> {
    const target = await this.selectDirectory(node, "New Encrypted Folder");
    if (target === undefined) {
      return;
    }
    const name = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        password: true,
        prompt: `One folder name inside ${displayDirectory(target.logicalPath)}`,
        title: "New Encrypted Folder",
        value: "new-folder",
        valueSelection: [0, "new-folder".length],
        validateInput: (value) => validateDirectoryChild(target.logicalPath, value),
      },
      this.controller.onDidLock,
    );
    if (name === undefined) {
      return;
    }
    this.requireSession(target.session, "before creating the encrypted folder");
    await this.createDirectoryBound(
      target.session,
      logicalDirectoryChild(target.logicalPath, name),
    );
  }

  public async rename(node?: unknown): Promise<void> {
    const target = await this.selectFile(node, "Rename Encrypted Markdown");
    if (target === undefined) {
      return;
    }
    const currentName = path.posix.basename(target.logicalPath);
    const parent = path.posix.dirname(target.logicalPath);
    const logicalParent = parent === "." ? "" : parent;
    const suffixStart = currentName.endsWith(".md")
      ? currentName.length - ".md".length
      : currentName.length;
    const name = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        password: true,
        prompt: `New Markdown filename inside ${displayDirectory(logicalParent)}`,
        title: `Rename ${target.logicalPath}`,
        value: currentName,
        valueSelection: [0, suffixStart],
        validateInput: (value) => {
          const validation = validateFileChild(logicalParent, value);
          if (validation !== undefined) {
            return validation;
          }
          return value === currentName ? "Choose a different filename" : undefined;
        },
      },
      this.controller.onDidLock,
    );
    if (name === undefined) {
      return;
    }
    this.requireSession(target.session, "before preparing the encrypted rename");
    await this.renameFileBound(
      target.session,
      target.logicalPath,
      logicalFileChild(logicalParent, name),
    );
  }

  public async delete(node?: unknown): Promise<void> {
    const target = await this.selectFile(node, "Delete Encrypted Markdown");
    if (target === undefined) {
      return;
    }
    const confirmation = await showSensitiveQuickPick(
      [
        {
          label: "Delete Encrypted Document",
          detail: target.logicalPath,
          action: "delete" as const,
        },
        {
          label: "Cancel",
          detail: "Keep the encrypted document.",
          action: "cancel" as const,
        },
      ],
      { title: "Confirm etag-conditional delete" },
      this.controller.onDidLock,
    );
    if (confirmation?.action !== "delete") {
      return;
    }
    this.requireSession(target.session, "before preparing the encrypted delete");
    await this.deleteFileBound(target.session, target.logicalPath);
  }

  public async createEmptyMarkdown(logicalPath: string): Promise<void> {
    await this.createEmptyMarkdownBound(this.controller.acquireSession(), logicalPath);
  }

  public async createDirectory(logicalPath: string): Promise<void> {
    await this.createDirectoryBound(this.controller.acquireSession(), logicalPath);
  }

  public async renameFile(source: string, destination: string): Promise<void> {
    await this.renameFileBound(this.controller.acquireSession(), source, destination);
  }

  public async deleteFile(logicalPath: string): Promise<void> {
    await this.deleteFileBound(this.controller.acquireSession(), logicalPath);
  }

  public async listTree(): Promise<readonly TreeEntry[]> {
    const session = this.controller.acquireSession();
    return this.controller.listTreeForSession(session);
  }

  private async createEmptyMarkdownBound(
    session: VaultSession,
    logicalPath: string,
  ): Promise<void> {
    logicalFileComponents(logicalPath);
    const created = await this.controller.createEmptyMarkdownForSession(
      session,
      logicalPath,
    );
    this.tree.refresh();
    if (created.durability === "notSynced") {
      void vscode.window.showWarningMessage(
        "Inex created ciphertext, but the filesystem did not confirm parent-directory crash durability.",
      );
    }
    await this.openEncryptedDocument(session, logicalPath);
  }

  private async createDirectoryBound(
    session: VaultSession,
    logicalPath: string,
  ): Promise<void> {
    if (logicalDirectoryComponents(logicalPath).length === 0) {
      throw new LogicalPathError("The vault root already exists");
    }
    await this.controller.createDirectoryForSession(session, logicalPath);
    this.tree.refresh();
  }

  private async renameFileBound(
    session: VaultSession,
    source: string,
    destination: string,
  ): Promise<void> {
    logicalFileComponents(source);
    logicalFileComponents(destination);
    if (source === destination) {
      throw new LogicalPathError("Rename destination must differ from the source");
    }
    const prepared = await this.editor.prepareFileMutation(session, source, "rename");
    if (prepared === undefined) {
      return;
    }
    try {
      const renamed = await this.controller.renameFileForSession(
        session,
        source,
        destination,
        prepared.etag,
      );
      if (
        renamed.sourceDurability === "notSynced" ||
        renamed.destinationDurability === "notSynced"
      ) {
        void vscode.window.showWarningMessage(
          "Inex renamed ciphertext, but the filesystem did not confirm crash durability for every parent directory.",
        );
      }
    } catch (error: unknown) {
      if (prepared.wasOpen) {
        await this.recoverOpenFile(session, [source, destination]);
      }
      throw error;
    } finally {
      this.tree.refresh();
    }
    if (prepared.wasOpen) {
      await this.openEncryptedDocument(session, destination);
    }
  }

  private async deleteFileBound(
    session: VaultSession,
    logicalPath: string,
  ): Promise<void> {
    logicalFileComponents(logicalPath);
    const prepared = await this.editor.prepareFileMutation(session, logicalPath, "delete");
    if (prepared === undefined) {
      return;
    }
    let deleted: Awaited<ReturnType<VaultController["deleteFileForSession"]>>;
    try {
      deleted = await this.controller.deleteFileForSession(
        session,
        logicalPath,
        prepared.etag,
      );
    } catch (error: unknown) {
      if (prepared.wasOpen) {
        await this.recoverOpenFile(session, [logicalPath]);
      }
      throw error;
    } finally {
      this.tree.refresh();
    }
    if (deleted.durability === "notSynced") {
      void vscode.window.showWarningMessage(
        "Inex deleted ciphertext, but the filesystem did not confirm parent-directory crash durability.",
      );
    }
  }

  private async openEncryptedDocument(
    session: VaultSession,
    logicalPath: string,
  ): Promise<void> {
    this.requireSession(session, "before opening the encrypted document");
    await vscode.commands.executeCommand(
      "vscode.openWith",
      this.controller.ciphertextUriForSession(logicalPath, session),
      VIEW_TYPE,
      { preview: false },
    );
    this.requireSession(session, "while opening the encrypted document");
    await this.editor.waitForOpenedDocument(logicalPath, session);
  }

  private async recoverOpenFile(
    session: VaultSession,
    candidates: readonly string[],
  ): Promise<void> {
    if (!this.controller.isSessionCurrent(session)) {
      return;
    }
    let entries: readonly TreeEntry[];
    try {
      entries = await this.controller.listTreeForSession(session);
    } catch {
      return;
    }
    const existing = new Set(
      entries
        .filter((entry) => entry.kind === "file")
        .map((entry) => entry.logicalPath),
    );
    const logicalPath = candidates.find((candidate) => existing.has(candidate));
    if (logicalPath === undefined) {
      return;
    }
    try {
      await this.openEncryptedDocument(session, logicalPath);
    } catch {
      // Preserve the original mutation failure. The refreshed ciphertext tree
      // remains the manual recovery surface if VS Code refuses to reopen.
    }
  }

  private async selectDirectory(
    value: unknown,
    title: string,
  ): Promise<{ readonly session: VaultSession; readonly logicalPath: string } | undefined> {
    if (value !== undefined) {
      const node = requireTreeNode(value);
      if (node.entry.kind !== "directory") {
        throw new Error("Choose an encrypted vault directory");
      }
      this.requireSession(node.session, "before using the selected directory");
      return { session: node.session, logicalPath: node.entry.logicalPath };
    }

    const session = this.controller.acquireSession();
    const entries = await this.controller.listTreeForSession(session);
    const selected = await showSensitiveQuickPick<DirectoryPick>(
      [
        { label: "$(root-folder) Vault root", logicalPath: "" },
        ...entries
          .filter((entry) => entry.kind === "directory")
          .map((entry) => ({ label: entry.logicalPath, logicalPath: entry.logicalPath })),
      ],
      { title, placeHolder: "Choose the encrypted parent directory" },
      this.controller.onDidLock,
    );
    if (selected === undefined) {
      return undefined;
    }
    this.requireSession(session, "before using the selected directory");
    return { session, logicalPath: selected.logicalPath };
  }

  private async selectFile(
    value: unknown,
    title: string,
  ): Promise<{ readonly session: VaultSession; readonly logicalPath: string } | undefined> {
    if (value !== undefined) {
      const node = requireTreeNode(value);
      if (node.entry.kind !== "file") {
        throw new Error("This operation supports encrypted Markdown files only");
      }
      this.requireSession(node.session, "before using the selected encrypted document");
      return { session: node.session, logicalPath: node.entry.logicalPath };
    }

    const session = this.controller.acquireSession();
    const entries = await this.controller.listTreeForSession(session);
    const selected = await showSensitiveQuickPick<FilePick>(
      entries
        .filter((entry) => entry.kind === "file")
        .map((entry) => ({ label: entry.logicalPath, logicalPath: entry.logicalPath })),
      { title, placeHolder: "Choose an encrypted Markdown document" },
      this.controller.onDidLock,
    );
    if (selected === undefined) {
      return undefined;
    }
    this.requireSession(session, "before using the selected encrypted document");
    return { session, logicalPath: selected.logicalPath };
  }

  private requireSession(session: VaultSession, phase: string): void {
    if (!this.controller.isSessionCurrent(session)) {
      throw new Error(`Inex vault session changed ${phase}`);
    }
  }
}

function requireTreeNode(value: unknown): InexTreeNode {
  if (value === null || typeof value !== "object") {
    throw new Error("Inex tree entry is invalid");
  }
  const candidate = value as Partial<InexTreeNode>;
  if (
    candidate.session === undefined ||
    candidate.entry === undefined ||
    (candidate.entry.kind !== "file" && candidate.entry.kind !== "directory") ||
    typeof candidate.entry.logicalPath !== "string"
  ) {
    throw new Error("Inex tree entry is invalid");
  }
  return candidate as InexTreeNode;
}

function validateFileChild(parent: string, name: string): string | undefined {
  try {
    logicalFileChild(parent, name);
    return undefined;
  } catch (error: unknown) {
    return pathValidationMessage(error);
  }
}

function validateDirectoryChild(parent: string, name: string): string | undefined {
  try {
    logicalDirectoryChild(parent, name);
    return undefined;
  } catch (error: unknown) {
    return pathValidationMessage(error);
  }
}

function pathValidationMessage(error: unknown): string {
  return error instanceof LogicalPathError ? error.message : "Logical path is invalid";
}

function displayDirectory(logicalPath: string): string {
  return logicalPath.length === 0 ? "the vault root" : logicalPath;
}
