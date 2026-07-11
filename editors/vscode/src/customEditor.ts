import { createHash, randomBytes } from "node:crypto";
import * as path from "node:path";

import * as vscode from "vscode";

import { readBoundedRegularFile } from "./boundedFile.ts";
import type { VaultController, VaultSession } from "./controller.ts";
import {
  headingForFragment,
  linkAtUtf16,
  logicalStem,
  parseMarkdownNavigation,
  resolveMarkdownTarget,
} from "./markdown.ts";
import type { DocumentMetadata } from "./sidecar.ts";
import { showSensitiveQuickPick } from "./sensitiveUi.ts";

const MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;
const MAX_DRAFT_ENVELOPE_BYTES = MAX_DOCUMENT_BYTES + 12 + 4096 + 16;
const MAX_BACKLINK_CANDIDATES = 256;
const MAX_BACKLINK_PLAINTEXT_BYTES = 64 * 1024 * 1024;
const WEBVIEW_SNAPSHOT_TIMEOUT_MS = 5_000;
const VIEW_TYPE = "inex.markdownEditor";

interface SnapshotRequest {
  readonly resolve: () => void;
  readonly reject: (error: Error) => void;
  readonly timer: NodeJS.Timeout;
  readonly cancellation: vscode.Disposable;
}

export interface FileMutationPreparation {
  readonly etag: string;
  readonly wasOpen: boolean;
}

export type FileMutationKind = "rename" | "delete";

class InexDocument implements vscode.CustomDocument {
  private readonly panels = new Set<vscode.WebviewPanel>();
  private readonly readyPanels = new Set<vscode.WebviewPanel>();
  private disposed = false;
  private locked = false;
  private mutating = false;
  private closeHandlePromise: Promise<void> | undefined;
  private revision = 0;
  private savedRevision: number;
  private pendingReveal: { readonly startByte: number; readonly endByte: number } | undefined;
  private readonly snapshotRequests = new Map<number, SnapshotRequest>();
  private nextSnapshotRequest = 1;

  public constructor(
    public readonly uri: vscode.Uri,
    public readonly logicalPath: string,
    public readonly handle: string,
    private content: Buffer,
    public etag: string,
    public metadata: DocumentMetadata,
    public readonly session: VaultSession,
    private readonly onDispose: (document: InexDocument) => void,
    restoredBackup: boolean,
    private staleBackup: boolean,
  ) {
    this.savedRevision = restoredBackup ? -1 : 0;
  }

  public snapshot(): { readonly content: Buffer; readonly revision: number } {
    this.requireUsable();
    return { content: Buffer.from(this.content), revision: this.revision };
  }

  public get isDirty(): boolean {
    return this.revision !== this.savedRevision;
  }

  public get requiresStaleBackupConfirmation(): boolean {
    return this.staleBackup;
  }

  public applyEdit(text: string): boolean {
    this.requireUsable();
    const bytes = Buffer.byteLength(text, "utf8");
    if (bytes > MAX_DOCUMENT_BYTES) {
      throw new Error("Document exceeds the Inex v1 plaintext limit");
    }
    const replacement = Buffer.from(text, "utf8");
    if (replacement.equals(this.content)) {
      replacement.fill(0);
      return false;
    }
    this.content.fill(0);
    this.content = replacement;
    this.revision += 1;
    return true;
  }

  public replaceFromCiphertext(
    content: Buffer,
    etag: string,
    metadata: DocumentMetadata,
  ): void {
    this.requireUsable();
    this.content.fill(0);
    this.content = content;
    this.etag = etag;
    this.metadata = metadata;
    this.revision += 1;
    this.savedRevision = this.revision;
    this.staleBackup = false;
    this.broadcast();
  }

  public acceptSave(
    revision: number,
    etag: string,
    metadata: DocumentMetadata,
  ): boolean {
    this.requireUsable();
    this.etag = etag;
    this.metadata = metadata;
    this.savedRevision = revision;
    this.staleBackup = false;
    return this.isDirty;
  }

  public attach(panel: vscode.WebviewPanel): void {
    this.panels.add(panel);
    panel.onDidDispose(() => {
      this.panels.delete(panel);
      this.readyPanels.delete(panel);
      this.rejectSnapshotRequests(new Error("Inex editor webview closed during synchronization"));
    });
  }

  public markReady(panel: vscode.WebviewPanel): void {
    if (this.panels.has(panel)) {
      this.readyPanels.add(panel);
    }
  }

  public get hasReadyPanel(): boolean {
    return this.readyPanels.size > 0;
  }

  public refreshPanels(): void {
    this.broadcast();
  }

  public async flushWebview(token: vscode.CancellationToken): Promise<void> {
    this.requireUsable();
    const panel = this.panels.values().next().value as vscode.WebviewPanel | undefined;
    if (panel === undefined) {
      return;
    }
    if (token.isCancellationRequested) {
      throw new vscode.CancellationError();
    }
    const requestId = this.nextSnapshotRequest;
    this.nextSnapshotRequest =
      this.nextSnapshotRequest >= Number.MAX_SAFE_INTEGER ? 1 : this.nextSnapshotRequest + 1;
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.rejectSnapshotRequest(
          requestId,
          new Error("Inex editor webview did not synchronize before the deadline"),
        );
      }, WEBVIEW_SNAPSHOT_TIMEOUT_MS);
      const cancellation = token.onCancellationRequested(() => {
        this.rejectSnapshotRequest(requestId, new vscode.CancellationError());
      });
      this.snapshotRequests.set(requestId, { resolve, reject, timer, cancellation });
      void panel.webview.postMessage({ type: "snapshotRequest", requestId }).then(
        (delivered) => {
          if (!delivered) {
            this.rejectSnapshotRequest(
              requestId,
              new Error("Inex editor webview is unavailable for synchronization"),
            );
          }
        },
        () => {
          this.rejectSnapshotRequest(
            requestId,
            new Error("Inex editor webview synchronization failed"),
          );
        },
      );
    });
  }

  public acceptSnapshot(requestId: number, text: string): boolean {
    const request = this.snapshotRequests.get(requestId);
    if (request === undefined) {
      return false;
    }
    this.snapshotRequests.delete(requestId);
    clearTimeout(request.timer);
    request.cancellation.dispose();
    try {
      const changed = this.applyEdit(text);
      request.resolve();
      return changed;
    } catch (error: unknown) {
      request.reject(error instanceof Error ? error : new Error("Inex snapshot was invalid"));
      throw error;
    }
  }

  public send(panel: vscode.WebviewPanel): void {
    this.requireUsable();
    void panel.webview.postMessage({
      type: "content",
      content: this.content.toString("utf8"),
      revision: this.revision,
    });
    if (this.pendingReveal !== undefined) {
      void panel.webview.postMessage({ type: "reveal", ...this.pendingReveal });
    }
  }

  public reveal(startByte: number, endByte: number): void {
    this.pendingReveal = { startByte, endByte };
    for (const panel of this.panels) {
      void panel.webview.postMessage({ type: "reveal", startByte, endByte });
    }
  }

  public dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.content.fill(0);
    this.content = Buffer.alloc(0);
    this.rejectSnapshotRequests(new Error("Inex document was disposed"));
    this.panels.clear();
    this.readyPanels.clear();
    this.onDispose(this);
    void this.beginCloseHandle().catch(() => undefined);
  }

  public wipeForLock(): void {
    if (this.locked || this.disposed) {
      return;
    }
    this.locked = true;
    this.content.fill(0);
    this.content = Buffer.alloc(0);
    this.rejectSnapshotRequests(new Error("Inex document was locked"));
    for (const panel of this.panels) {
      panel.webview.html = lockedHtml();
    }
    void this.beginCloseHandle().catch(() => undefined);
  }

  public freezeForMutation(): void {
    this.requireUsable();
    this.mutating = true;
    this.readyPanels.clear();
    this.rejectSnapshotRequests(new Error("Inex document is closing for a file mutation"));
    for (const panel of this.panels) {
      panel.webview.html = mutationHtml();
    }
  }

  public async waitForHandleClose(): Promise<void> {
    await this.beginCloseHandle();
  }

  public thawAfterFailedMutation(): boolean {
    if (!this.mutating || this.disposed || this.locked || this.panels.size === 0) {
      return false;
    }
    this.mutating = false;
    this.readyPanels.clear();
    for (const panel of this.panels) {
      panel.webview.options = { enableScripts: true, localResourceRoots: [] };
      panel.webview.html = editorHtml();
    }
    return true;
  }

  private broadcast(): void {
    for (const panel of this.panels) {
      this.send(panel);
    }
  }

  private requireUsable(): void {
    if (this.locked || this.disposed || this.mutating) {
      throw new Error("Inex document is locked; close and reopen it after unlocking the vault");
    }
  }

  private beginCloseHandle(): Promise<void> {
    this.closeHandlePromise ??= this.session.sidecar.closeDocument(this.handle);
    return this.closeHandlePromise;
  }

  private rejectSnapshotRequest(requestId: number, error: Error): void {
    const request = this.snapshotRequests.get(requestId);
    if (request === undefined) {
      return;
    }
    this.snapshotRequests.delete(requestId);
    clearTimeout(request.timer);
    request.cancellation.dispose();
    request.reject(error);
  }

  private rejectSnapshotRequests(error: Error): void {
    for (const requestId of [...this.snapshotRequests.keys()]) {
      this.rejectSnapshotRequest(requestId, error);
    }
  }
}

export class InexCustomEditorProvider
  implements vscode.CustomEditorProvider<InexDocument>, vscode.Disposable
{
  private readonly changeEmitter =
    new vscode.EventEmitter<vscode.CustomDocumentContentChangeEvent<InexDocument>>();
  private readonly documents = new Set<InexDocument>();
  private readonly lockSubscription: vscode.Disposable;
  private lastBackupUri: vscode.Uri | undefined;
  private failNextMutationCloseForTest = false;

  public readonly onDidChangeCustomDocument = this.changeEmitter.event;

  public constructor(
    private readonly controller: VaultController,
    private readonly integrationTestMode = false,
  ) {
    this.lockSubscription = controller.onDidLock(() => {
      this.wipeAllForLock();
    });
  }

  public async openCustomDocument(
    uri: vscode.Uri,
    openContext: vscode.CustomDocumentOpenContext,
    token: vscode.CancellationToken,
  ): Promise<InexDocument> {
    if (token.isCancellationRequested) {
      throw new vscode.CancellationError();
    }
    if (openContext.untitledDocumentData !== undefined) {
      throw new Error("Untitled plaintext documents are not supported by Inex");
    }
    if (!this.controller.isUnlocked) {
      const unlocked = this.integrationTestMode
        ? await this.unlockIntegrationFixture()
        : await this.controller.unlockInteractive(uri);
      if (unlocked === undefined) {
        throw new vscode.CancellationError();
      }
      if (unlocked.warnings.length > 0) {
        void vscode.window.showWarningMessage(
          `Inex restored an editor with ${unlocked.warnings.length} KDF policy warning(s). Replace weak password slots from the CLI.`,
        );
      }
    }
    const session = this.controller.acquireSession();
    const sidecar = session.sidecar;
    const logicalPath = this.controller.logicalPathForSession(uri, session);
    const opened = await sidecar.openDocument(logicalPath);
    let content = opened.content;
    let restoredBackup = false;
    let staleBackup = false;
    try {
      ensureOpenAllowed(this.controller, session, token);
      if (openContext.backupId !== undefined) {
        const backupUri = vscode.Uri.parse(openContext.backupId, true);
        if (backupUri.scheme !== "file") {
          throw new Error("Encrypted backup must be a local regular file");
        }
        const encrypted = await readBoundedRegularFile(
          backupUri.fsPath,
          MAX_DRAFT_ENVELOPE_BYTES,
        );
        try {
          ensureOpenAllowed(this.controller, session, token);
          const restored = await sidecar.decryptDraft(logicalPath, encrypted);
          let adopted = false;
          try {
            ensureOpenAllowed(this.controller, session, token);
            if (restored.baseEtag !== opened.etag) {
              const choice = await vscode.window.showWarningMessage(
                "The authenticated encrypted backup is based on an older ciphertext version. Open it as a recovery draft? Saving it will require an explicit overwrite confirmation and etag check.",
                { modal: true },
                "Open Recovery Draft",
              );
              if (choice !== "Open Recovery Draft") {
                throw new vscode.CancellationError();
              }
              ensureOpenAllowed(this.controller, session, token);
              staleBackup = true;
            }
            content.fill(0);
            content = restored.content;
            restoredBackup = true;
            adopted = true;
          } finally {
            if (!adopted) {
              restored.content.fill(0);
            }
          }
        } finally {
          encrypted.fill(0);
        }
      }
      ensureOpenAllowed(this.controller, session, token);
      const document = new InexDocument(
        uri,
        logicalPath,
        opened.handle,
        content,
        opened.etag,
        opened.metadata,
        session,
        (disposed) => this.documents.delete(disposed),
        restoredBackup,
        staleBackup,
      );
      this.documents.add(document);
      return document;
    } catch (error: unknown) {
      content.fill(0);
      await sidecar.closeDocument(opened.handle).catch(() => undefined);
      throw error;
    }
  }

  public resolveCustomEditor(
    document: InexDocument,
    webviewPanel: vscode.WebviewPanel,
    _token: vscode.CancellationToken,
  ): void {
    if (!this.controller.isSessionCurrent(document.session)) {
      webviewPanel.webview.options = { enableScripts: false, localResourceRoots: [] };
      webviewPanel.webview.html = lockedHtml();
      return;
    }
    webviewPanel.webview.options = { enableScripts: true, localResourceRoots: [] };
    webviewPanel.webview.html = editorHtml();
    document.attach(webviewPanel);
    webviewPanel.webview.onDidReceiveMessage((message: unknown) => {
      if (!isRecord(message)) {
        return;
      }
      if (message.type === "edit" && typeof message.content === "string") {
        try {
          if (document.applyEdit(message.content)) {
            this.controller.noteUserActivity(document.session);
            this.changeEmitter.fire({ document });
          }
        } catch (error: unknown) {
          void vscode.window.showErrorMessage(safeError(error));
          document.send(webviewPanel);
        }
        return;
      }
      if (message.type === "ready") {
        if (!this.controller.isSessionCurrent(document.session)) {
          webviewPanel.webview.html = lockedHtml();
          return;
        }
        document.markReady(webviewPanel);
        document.send(webviewPanel);
        return;
      }
      if (message.type === "activity") {
        this.controller.noteUserActivity(document.session);
        return;
      }
      if (
        message.type === "snapshot" &&
        Number.isSafeInteger(message.requestId) &&
        typeof message.requestId === "number" &&
        typeof message.content === "string"
      ) {
        try {
          if (document.acceptSnapshot(message.requestId, message.content)) {
            this.controller.noteUserActivity(document.session);
            this.changeEmitter.fire({ document });
          }
        } catch (error: unknown) {
          void vscode.window.showErrorMessage(safeError(error));
        }
        return;
      }
      if (
        (message.type === "followLink" ||
          message.type === "showHeadings" ||
          message.type === "showBacklinks") &&
        typeof message.content === "string"
      ) {
        try {
          if (document.applyEdit(message.content)) {
            this.controller.noteUserActivity(document.session);
            this.changeEmitter.fire({ document });
          }
          if (
            message.type === "followLink" &&
            Number.isSafeInteger(message.offset) &&
            typeof message.offset === "number"
          ) {
            void this.followLink(document, message.offset).catch((error: unknown) => {
              void vscode.window.showErrorMessage(safeError(error));
            });
          } else if (message.type === "showHeadings") {
            void this.showHeadings(document).catch((error: unknown) => {
              void vscode.window.showErrorMessage(safeError(error));
            });
          } else if (message.type === "showBacklinks") {
            void this.showBacklinks(document).catch((error: unknown) => {
              void vscode.window.showErrorMessage(safeError(error));
            });
          }
        } catch (error: unknown) {
          void vscode.window.showErrorMessage(safeError(error));
        }
      }
    });
  }

  public async saveCustomDocument(
    document: InexDocument,
    token: vscode.CancellationToken,
  ): Promise<void> {
    if (token.isCancellationRequested) {
      throw new vscode.CancellationError();
    }
    if (document.requiresStaleBackupConfirmation) {
      const choice = await vscode.window.showWarningMessage(
        "This recovery draft is older than the current authenticated ciphertext. Overwrite the current version with this draft? A concurrent etag change will still abort the write.",
        { modal: true },
        "Overwrite with Recovery Draft",
      );
      if (choice !== "Overwrite with Recovery Draft") {
        throw new vscode.CancellationError();
      }
    }
    await document.flushWebview(token);
    const snapshot = document.snapshot();
    try {
      const sidecar = this.requireCurrentDocumentSession(document);
      const saved = await sidecar.write(document.logicalPath, snapshot.content, {
        ifMatch: document.etag,
      });
      this.requireCurrentDocumentSession(document);
      const editedDuringSave = document.acceptSave(
        snapshot.revision,
        saved.etag,
        saved.metadata,
      );
      if (editedDuringSave) {
        this.changeEmitter.fire({ document });
      }
      if (saved.durability === "notSynced") {
        void vscode.window.showWarningMessage(
          "Inex saved ciphertext, but the filesystem did not confirm parent-directory crash durability.",
        );
      }
    } finally {
      snapshot.content.fill(0);
    }
  }

  public async saveCustomDocumentAs(
    _document: InexDocument,
    _destination: vscode.Uri,
    _token: vscode.CancellationToken,
  ): Promise<void> {
    throw new Error("Inex Save As is disabled; use authenticated rename from the vault tree");
  }

  public async revertCustomDocument(
    document: InexDocument,
    token: vscode.CancellationToken,
  ): Promise<void> {
    if (token.isCancellationRequested) {
      throw new vscode.CancellationError();
    }
    const sidecar = this.requireCurrentDocumentSession(document);
    const reloaded = await sidecar.read(document.logicalPath);
    let adopted = false;
    try {
      if (token.isCancellationRequested) {
        throw new vscode.CancellationError();
      }
      this.requireCurrentDocumentSession(document);
      document.replaceFromCiphertext(reloaded.content, reloaded.etag, reloaded.metadata);
      adopted = true;
    } finally {
      if (!adopted) {
        reloaded.content.fill(0);
      }
    }
  }

  public async backupCustomDocument(
    document: InexDocument,
    context: vscode.CustomDocumentBackupContext,
    token: vscode.CancellationToken,
  ): Promise<vscode.CustomDocumentBackup> {
    if (token.isCancellationRequested) {
      throw new vscode.CancellationError();
    }
    await document.flushWebview(token);
    const snapshot = document.snapshot();
    let envelope: Buffer | undefined;
    try {
      const sidecar = this.requireCurrentDocumentSession(document);
      const encrypted = await sidecar.encryptDraft(
        document.logicalPath,
        document.etag,
        snapshot.content,
      );
      envelope = encrypted.envelope;
      this.requireCurrentDocumentSession(document);
      if (token.isCancellationRequested) {
        throw new vscode.CancellationError();
      }
      const parent = context.destination.with({
        path: path.posix.dirname(context.destination.path),
      });
      await vscode.workspace.fs.createDirectory(parent);
      this.requireCurrentDocumentSession(document);
      if (token.isCancellationRequested) {
        throw new vscode.CancellationError();
      }
      await vscode.workspace.fs.writeFile(context.destination, envelope);
      if (this.integrationTestMode) {
        this.lastBackupUri = context.destination;
      }
    } finally {
      snapshot.content.fill(0);
      envelope?.fill(0);
    }
    return {
      id: context.destination.toString(),
      delete: () => {
        void vscode.workspace.fs.delete(context.destination).then(undefined, () => undefined);
      },
    };
  }

  public dispose(): void {
    this.wipeAllForLock();
    this.lockSubscription.dispose();
    this.changeEmitter.dispose();
  }

  public wipeAllForLock(): void {
    for (const document of this.documents) {
      document.wipeForLock();
    }
  }

  public async confirmLock(): Promise<boolean> {
    const currentDocuments = [...this.documents].filter((document) =>
      this.controller.isSessionCurrent(document.session),
    );
    const synchronization = new vscode.CancellationTokenSource();
    try {
      await Promise.all(
        currentDocuments.map((document) =>
          document.flushWebview(synchronization.token),
        ),
      );
    } catch (error: unknown) {
      await vscode.window.showErrorMessage(
        `Inex did not lock because an editor could not synchronize: ${safeError(error)}`,
      );
      return false;
    } finally {
      synchronization.dispose();
    }
    const dirty = currentDocuments.filter((document) => document.isDirty);
    if (dirty.length === 0) {
      return true;
    }
    const choice = await vscode.window.showWarningMessage(
      `${dirty.length} Inex document(s) have unsaved plaintext edits. Locking must save encrypted ciphertext or explicitly discard them.`,
      { modal: true },
      "Save All Files and Lock",
      "Discard Inex Edits and Lock",
    );
    if (choice === "Discard Inex Edits and Lock") {
      return this.closeDirtyEditorsForDiscard(dirty);
    }
    if (choice !== "Save All Files and Lock") {
      return false;
    }
    const saved = await vscode.workspace.saveAll(false);
    if (!saved || currentDocuments.some((document) => document.isDirty)) {
      await vscode.window.showErrorMessage(
        "Inex did not lock because at least one encrypted document could not be saved.",
      );
      return false;
    }
    return true;
  }

  public reveal(logicalPath: string, startByte: number, endByte: number): void {
    for (const document of this.documents) {
      if (
        document.logicalPath === logicalPath &&
        this.controller.isSessionCurrent(document.session)
      ) {
        document.reveal(startByte, endByte);
      }
    }
  }

  public async prepareFileMutation(
    session: VaultSession,
    logicalPath: string,
    kind: FileMutationKind,
  ): Promise<FileMutationPreparation | undefined> {
    if (!this.controller.isSessionCurrent(session)) {
      throw new Error("Inex vault session changed before the file operation");
    }
    const open = [...this.documents].filter(
      (document) =>
        document.logicalPath === logicalPath &&
        document.session.root === session.root &&
        document.session.sidecar === session.sidecar &&
        document.session.generation === session.generation,
    );
    if (open.length > 1) {
      throw new Error("Inex found multiple models for one encrypted document");
    }
    const document = open[0];
    if (document === undefined) {
      const stat = await this.controller.statFileForSession(session, logicalPath);
      return { etag: stat.etag, wasOpen: false };
    }

    const synchronization = new vscode.CancellationTokenSource();
    try {
      await document.flushWebview(synchronization.token);
      if (document.isDirty) {
        if (kind === "delete") {
          throw new Error(
            "Delete was refused because this encrypted document has unsaved edits. Save or close/discard it explicitly, then retry.",
          );
        }
        const selected = await showSensitiveQuickPick(
          [
            {
              label: "Save and Rename",
              detail: "Encrypt the current edits with an etag check, then rename the ciphertext.",
              action: "save" as const,
            },
            {
              label: "Cancel",
              detail: "Keep the encrypted document open and unchanged.",
              action: "cancel" as const,
            },
          ],
          { title: `Unsaved edits — ${logicalPath}` },
          this.controller.onDidLock,
        );
        if (selected?.action !== "save") {
          return undefined;
        }
        if (!this.controller.isSessionCurrent(session)) {
          throw new Error("Inex vault session changed before saving for rename");
        }
        await this.saveCustomDocument(document, synchronization.token);
        await document.flushWebview(synchronization.token);
        if (document.isDirty) {
          throw new Error(
            "Rename was refused because the document changed again while it was being saved.",
          );
        }
      }
      if (!this.controller.isSessionCurrent(session)) {
        throw new Error("Inex vault session changed before closing the source document");
      }
      const etag = document.etag;
      document.freezeForMutation();
      try {
        await this.closeDocumentForMutation(document);
      } catch (error: unknown) {
        await this.restoreAfterPreparationFailure(document, session, logicalPath);
        throw error;
      }
      if (!this.controller.isSessionCurrent(session)) {
        throw new Error("Inex vault session changed while closing the source document");
      }
      return { etag, wasOpen: true };
    } finally {
      synchronization.dispose();
    }
  }

  public async waitForOpenedDocument(
    logicalPath: string,
    session: VaultSession,
  ): Promise<void> {
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      if (!this.controller.isSessionCurrent(session)) {
        throw new Error("Inex vault session changed while opening the encrypted document");
      }
      const document = [...this.documents].find(
        (candidate) =>
          candidate.logicalPath === logicalPath &&
          candidate.session.root === session.root &&
          candidate.session.sidecar === session.sidecar &&
          candidate.session.generation === session.generation,
      );
      if (document?.hasReadyPanel === true) {
        return;
      }
      await delay(25);
    }
    throw new Error("Inex encrypted editor did not become ready");
  }

  public async waitForIntegrationDocument(logicalPath: string): Promise<void> {
    this.requireIntegrationTestMode();
    await this.waitForOpenedDocument(logicalPath, this.controller.acquireSession());
  }

  public markIntegrationDocumentDirty(logicalPath: string): void {
    this.requireIntegrationTestMode();
    const document = [...this.documents].find(
      (candidate) => candidate.logicalPath === logicalPath,
    );
    if (document === undefined) {
      throw new Error("Inex integration document is not open");
    }
    const snapshot = document.snapshot();
    try {
      const content = `${snapshot.content.toString("utf8")}\n<!-- inex integration dirty -->\n`;
      if (document.applyEdit(content)) {
        this.controller.noteUserActivity(document.session);
        this.changeEmitter.fire({ document });
        document.refreshPanels();
      }
    } finally {
      snapshot.content.fill(0);
    }
  }

  public async waitForIntegrationBackup(): Promise<string> {
    this.requireIntegrationTestMode();
    const deadline = Date.now() + 10_000;
    while (Date.now() < deadline) {
      const uri = this.lastBackupUri;
      if (uri !== undefined) {
        return uri.fsPath;
      }
      await delay(25);
    }
    throw new Error("VS Code did not request an encrypted custom-editor backup");
  }

  public integrationContentSha256(logicalPath: string): string {
    this.requireIntegrationTestMode();
    const document = [...this.documents].find(
      (candidate) => candidate.logicalPath === logicalPath,
    );
    if (document === undefined) {
      throw new Error("Inex integration document is not open");
    }
    const snapshot = document.snapshot();
    try {
      return createHash("sha256").update(snapshot.content).digest("hex");
    } finally {
      snapshot.content.fill(0);
    }
  }

  public failNextMutationCloseForIntegrationTest(): void {
    this.requireIntegrationTestMode();
    this.failNextMutationCloseForTest = true;
  }

  public async recoverIntegrationBackupAndSave(
    logicalPath: string,
    backupPath: string,
  ): Promise<string> {
    this.requireIntegrationTestMode();
    const cancellation = new vscode.CancellationTokenSource();
    let document: InexDocument | undefined;
    try {
      document = await this.openCustomDocument(
        this.controller.ciphertextUri(logicalPath),
        {
          backupId: vscode.Uri.file(backupPath).toString(),
          untitledDocumentData: undefined,
        },
        cancellation.token,
      );
      if (!document.isDirty) {
        throw new Error("Inex integration backup did not restore as a dirty document");
      }
      const snapshot = document.snapshot();
      let digest: string;
      try {
        digest = createHash("sha256").update(snapshot.content).digest("hex");
      } finally {
        snapshot.content.fill(0);
      }
      await this.saveCustomDocument(document, cancellation.token);
      if (document.isDirty) {
        throw new Error("Inex integration recovery remained dirty after encrypted save");
      }
      return digest;
    } finally {
      document?.dispose();
      cancellation.dispose();
    }
  }

  private requireIntegrationTestMode(): void {
    if (!this.integrationTestMode) {
      throw new Error("Inex integration-test editor API is unavailable");
    }
  }

  private requireCurrentDocumentSession(document: InexDocument) {
    if (!this.controller.isSessionCurrent(document.session)) {
      throw new Error("Inex document belongs to a locked or replaced vault session");
    }
    return document.session.sidecar;
  }

  private async closeDocumentForMutation(document: InexDocument): Promise<void> {
    if (this.failNextMutationCloseForTest) {
      this.failNextMutationCloseForTest = false;
      throw new Error("Simulated VS Code tab-close refusal for integration testing");
    }
    const uri = document.uri.toString();
    const tabs = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .filter(
        (tab) =>
          tab.input instanceof vscode.TabInputCustom &&
          tab.input.viewType === VIEW_TYPE &&
          tab.input.uri.toString() === uri,
      );
    if (tabs.length === 0) {
      document.dispose();
    } else if (!(await vscode.window.tabGroups.close(tabs, true))) {
      throw new Error("VS Code did not close the encrypted editor for the file operation");
    }
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline && this.documents.has(document)) {
      await delay(25);
    }
    if (this.documents.has(document)) {
      document.dispose();
    }
    await document.waitForHandleClose();
  }

  private async restoreAfterPreparationFailure(
    document: InexDocument,
    session: VaultSession,
    logicalPath: string,
  ): Promise<void> {
    if (!this.controller.isSessionCurrent(session)) {
      return;
    }
    if (this.documents.has(document) && document.thawAfterFailedMutation()) {
      return;
    }
    try {
      await this.controller.evictFileHandlesForSession(session, logicalPath);
      await vscode.commands.executeCommand(
        "vscode.openWith",
        this.controller.ciphertextUriForSession(logicalPath, session),
        VIEW_TYPE,
        { preview: false },
      );
      await this.waitForOpenedDocument(logicalPath, session);
    } catch {
      if (this.controller.isSessionCurrent(session)) {
        await this.controller.lock().catch(() => undefined);
      }
    }
  }

  private async closeDirtyEditorsForDiscard(
    dirty: readonly InexDocument[],
  ): Promise<boolean> {
    const dirtyUris = new Set(dirty.map((document) => document.uri.toString()));
    const tabs = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .filter(
        (tab) =>
          tab.input instanceof vscode.TabInputCustom &&
          tab.input.viewType === VIEW_TYPE &&
          dirtyUris.has(tab.input.uri.toString()),
      );
    if (tabs.length !== dirty.length || !(await vscode.window.tabGroups.close(tabs, true))) {
      await vscode.window.showErrorMessage(
        "Inex did not lock because VS Code did not close every dirty encrypted editor.",
      );
      return false;
    }
    const deadline = Date.now() + 5_000;
    while (Date.now() < deadline) {
      if (dirty.every((document) => !this.documents.has(document))) {
        return true;
      }
      await delay(25);
    }
    await vscode.window.showErrorMessage(
      "Inex did not lock because a discarded encrypted editor remained open.",
    );
    return false;
  }

  private async unlockIntegrationFixture(): Promise<Awaited<ReturnType<VaultController["unlockForIntegrationTest"]>>> {
    this.requireIntegrationTestMode();
    const vaultPath = process.env.INEX_TEST_VAULT_PATH;
    const password = process.env.INEX_TEST_PASSWORD;
    const sidecarPath = process.env.INEX_TEST_INEXD_PATH;
    if (vaultPath === undefined || password === undefined || sidecarPath === undefined) {
      throw new Error("Inex integration fixture environment is incomplete");
    }
    return this.controller.unlockForIntegrationTest(vaultPath, password, sidecarPath);
  }

  private async followLink(document: InexDocument, offset: number): Promise<void> {
    const snapshot = document.snapshot();
    try {
      const text = snapshot.content.toString("utf8");
      const link = linkAtUtf16(parseMarkdownNavigation(text), offset);
      if (link === undefined) {
        throw new Error("Place the cursor inside an Inex Markdown link");
      }
      const target = resolveMarkdownTarget(document.logicalPath, link.target, link.wiki);
      await this.openTarget(target.logicalPath, target.fragment, document.session);
    } finally {
      snapshot.content.fill(0);
    }
  }

  private async showHeadings(document: InexDocument): Promise<void> {
    const snapshot = document.snapshot();
    try {
      const navigation = parseMarkdownNavigation(snapshot.content.toString("utf8"));
      const selected = await showSensitiveQuickPick(
        navigation.headings.map((heading) => ({
          label: `${"#".repeat(heading.level)} ${heading.text}`,
          description: `line ${heading.line + 1}`,
          heading,
        })),
        { title: `Headings — ${document.logicalPath}` },
        this.controller.onDidLock,
      );
      if (selected !== undefined) {
        document.reveal(selected.heading.startByte, selected.heading.endByte);
      }
    } finally {
      snapshot.content.fill(0);
    }
  }

  private async showBacklinks(document: InexDocument): Promise<void> {
    const selected = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Finding encrypted backlinks to ${document.logicalPath}`,
        cancellable: true,
      },
      async (_progress, token) => {
        const sidecar = this.requireCurrentDocumentSession(document);
        const queries = new Set([logicalStem(document.logicalPath)]);
        queries.add(encodeURIComponent(logicalStem(document.logicalPath)));
        const candidates = new Set<string>();
        let truncated = false;
        for (const query of queries) {
          const hits = await sidecar.search(query, 1_000);
          this.requireCurrentDocumentSession(document);
          truncated ||= hits.length === 1_000;
          for (const hit of hits) {
            if (candidates.has(hit.logicalPath)) {
              continue;
            }
            if (candidates.size >= MAX_BACKLINK_CANDIDATES) {
              truncated = true;
              continue;
            }
            candidates.add(hit.logicalPath);
          }
        }

        const items: Array<{
          readonly label: string;
          readonly description: string;
          readonly detail: string;
          readonly logicalPath: string;
          readonly startByte: number;
          readonly endByte: number;
        }> = [];
        const seen = new Set<string>();
        let inspectedPlaintextBytes = 0;
        for (const logicalPath of [...candidates].sort()) {
          if (token.isCancellationRequested) {
            throw new vscode.CancellationError();
          }
          const read = await sidecar.read(logicalPath);
          let overBudget = false;
          try {
            this.requireCurrentDocumentSession(document);
            if (
              read.content.byteLength >
              MAX_BACKLINK_PLAINTEXT_BYTES - inspectedPlaintextBytes
            ) {
              truncated = true;
              overBudget = true;
            } else {
              inspectedPlaintextBytes += read.content.byteLength;
              const navigation = parseMarkdownNavigation(read.content.toString("utf8"));
              for (const link of navigation.links) {
                let target;
                try {
                  target = resolveMarkdownTarget(logicalPath, link.target, link.wiki);
                } catch {
                  continue;
                }
                if (target.logicalPath !== document.logicalPath) {
                  continue;
                }
                const key = `${logicalPath}:${link.startByte}:${link.endByte}`;
                if (seen.has(key)) {
                  continue;
                }
                seen.add(key);
                items.push({
                  label: logicalPath,
                  description: `line ${link.line + 1}`,
                  detail: link.label,
                  logicalPath,
                  startByte: link.startByte,
                  endByte: link.endByte,
                });
              }
            }
          } finally {
            read.content.fill(0);
          }
          if (overBudget) {
            break;
          }
        }
        if (truncated) {
          void vscode.window.showWarningMessage(
            "Inex backlink discovery reached its bounded candidate or plaintext budget; this result may be incomplete.",
          );
        }
        return showSensitiveQuickPick(
          items,
          {
            matchOnDescription: false,
            matchOnDetail: false,
            title: `Backlinks — ${document.logicalPath}`,
          },
          this.controller.onDidLock,
        );
      },
    );
    if (selected !== undefined) {
      this.requireCurrentDocumentSession(document);
      await vscode.commands.executeCommand(
        "vscode.openWith",
        this.controller.ciphertextUri(selected.logicalPath),
        VIEW_TYPE,
      );
      this.requireCurrentDocumentSession(document);
      this.reveal(selected.logicalPath, selected.startByte, selected.endByte);
    }
  }

  private async openTarget(
    logicalPath: string,
    fragment: string | undefined,
    session: VaultSession,
  ): Promise<void> {
    if (!this.controller.isSessionCurrent(session)) {
      throw new Error("Inex vault session changed before opening the Markdown target");
    }
    await vscode.commands.executeCommand(
      "vscode.openWith",
      this.controller.ciphertextUri(logicalPath),
      VIEW_TYPE,
    );
    if (!this.controller.isSessionCurrent(session)) {
      throw new Error("Inex vault session changed while opening the Markdown target");
    }
    if (fragment === undefined) {
      return;
    }
    const target = [...this.documents].find(
      (document) =>
        document.logicalPath === logicalPath &&
        document.session.root === session.root &&
        document.session.sidecar === session.sidecar &&
        document.session.generation === session.generation,
    );
    if (target === undefined) {
      throw new Error("Inex could not resolve the opened Markdown target");
    }
    const snapshot = target.snapshot();
    try {
      const heading = headingForFragment(
        parseMarkdownNavigation(snapshot.content.toString("utf8")),
        fragment,
      );
      if (heading === undefined) {
        throw new Error("Markdown heading target was not found");
      }
      target.reveal(heading.startByte, heading.endByte);
    } finally {
      snapshot.content.fill(0);
    }
  }
}

function editorHtml(): string {
  const nonce = randomBytes(18).toString("base64");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style nonce="${nonce}">html,body{box-sizing:border-box;width:100%;height:100%;margin:0}body{display:grid;grid-template-rows:auto 1fr;background:var(--vscode-editor-background)}nav{display:flex;gap:.4rem;padding:.35rem .6rem;border-bottom:1px solid var(--vscode-panel-border)}button{color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;padding:.25rem .6rem}textarea{box-sizing:border-box;width:100%;height:100%;resize:none;border:0;padding:1rem;color:var(--vscode-editor-foreground);background:var(--vscode-editor-background);font:var(--vscode-editor-font-size) var(--vscode-editor-font-family);outline:none}</style>
</head><body><nav><button id="headings" type="button">Headings</button><button id="backlinks" type="button">Backlinks</button></nav><textarea id="editor" aria-label="Encrypted Markdown editor" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"></textarea>
<script nonce="${nonce}">
const vscode=acquireVsCodeApi();
const editor=document.getElementById('editor');
const encoder=new TextEncoder();
let applying=false;
let editTimer;
let lastActivity=0;
function byteIndex(text,target){let bytes=0,index=0;for(const scalar of text){if(bytes>=target)break;bytes+=encoder.encode(scalar).length;index+=scalar.length;}return index;}
function cancelEditTimer(){if(editTimer!==undefined){clearTimeout(editTimer);editTimer=undefined;}}
function sendEdit(){cancelEditTimer();if(!applying)vscode.postMessage({type:'edit',content:editor.value});}
function sendNavigation(type,offset){cancelEditTimer();vscode.postMessage({type,offset,content:editor.value});}
editor.addEventListener('input',()=>{if(!applying){const now=Date.now();if(now-lastActivity>=1000){lastActivity=now;vscode.postMessage({type:'activity'});}cancelEditTimer();editTimer=setTimeout(sendEdit,150);}});
editor.addEventListener('click',(event)=>{if(event.ctrlKey||event.metaKey)sendNavigation('followLink',editor.selectionStart);});
editor.addEventListener('keydown',(event)=>{if((event.ctrlKey||event.metaKey)&&event.key==='Enter'){event.preventDefault();sendNavigation('followLink',editor.selectionStart);}});
document.getElementById('headings').addEventListener('click',()=>sendNavigation('showHeadings',editor.selectionStart));
document.getElementById('backlinks').addEventListener('click',()=>sendNavigation('showBacklinks',editor.selectionStart));
window.addEventListener('message',(event)=>{const message=event.data;if(message&&message.type==='content'&&typeof message.content==='string'){cancelEditTimer();applying=true;editor.value=message.content;applying=false;}else if(message&&message.type==='reveal'&&Number.isSafeInteger(message.startByte)&&Number.isSafeInteger(message.endByte)){const start=byteIndex(editor.value,message.startByte);const end=byteIndex(editor.value,message.endByte);editor.focus();editor.setSelectionRange(start,end);}else if(message&&message.type==='snapshotRequest'&&Number.isSafeInteger(message.requestId)){cancelEditTimer();vscode.postMessage({type:'snapshot',requestId:message.requestId,content:editor.value});}});
vscode.postMessage({type:'ready'});
</script>
</body></html>`;
}

function lockedHtml(): string {
  return "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\"></head><body><p>Inex vault is locked. Close this editor and reopen it after unlocking.</p></body></html>";
}

function mutationHtml(): string {
  return "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'\"></head><body><p>Inex is closing this encrypted document for an authenticated file operation.</p></body></html>";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function safeError(error: unknown): string {
  return error instanceof Error ? error.message : "Inex editor operation failed";
}

function ensureOpenAllowed(
  controller: VaultController,
  session: VaultSession,
  token: vscode.CancellationToken,
): void {
  if (token.isCancellationRequested) {
    throw new vscode.CancellationError();
  }
  if (!controller.isSessionCurrent(session)) {
    throw new Error("Inex vault was locked while the encrypted document was opening");
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
