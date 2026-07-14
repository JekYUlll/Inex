import { createHash, randomBytes } from "node:crypto";
import * as path from "node:path";

import * as vscode from "vscode";

import { AssetPreviewCoordinator } from "./assetPreviewCoordinator.ts";
import { readBoundedRegularFile } from "./boundedFile.ts";
import type { VaultController, VaultSession } from "./controller.ts";
import {
  headingForFragment,
  linkAtUtf16,
  logicalStem,
  parseMarkdownNavigation,
  resolveMarkdownTarget,
} from "./markdown.ts";
import type {
  DocumentMetadata,
  PrivateAnnotationSpec,
  RenderMap,
  UmbraProjection,
} from "./sidecar.ts";
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

interface EditorSelection {
  readonly startByte: number;
  readonly endByte: number;
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
  private selection: EditorSelection | undefined;
  private umbraRenderMap: RenderMap | undefined;

  public constructor(
    public readonly uri: vscode.Uri,
    public readonly logicalPath: string,
    private handle: string | undefined,
    private content: Buffer,
    public etag: string,
    public metadata: DocumentMetadata,
    public readonly session: VaultSession,
    private readonly onDispose: (document: InexDocument) => void,
    restoredBackup: boolean,
    private staleBackup: boolean,
    umbraRenderMap?: RenderMap,
  ) {
    this.savedRevision = restoredBackup ? -1 : 0;
    this.umbraRenderMap = umbraRenderMap;
  }

  public get isUmbraProjection(): boolean {
    return this.umbraRenderMap !== undefined;
  }

  public renderMap(): RenderMap | undefined {
    return this.umbraRenderMap;
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

  public currentSelection(): EditorSelection | undefined {
    return this.selection;
  }

  public restoreSelection(selection: EditorSelection | undefined): void {
    if (
      selection !== undefined &&
      selection.endByte <= this.content.byteLength &&
      selection.startByte <= selection.endByte
    ) {
      this.selection = selection;
    }
  }

  public updateSelection(text: string, startByte: number, endByte: number): boolean {
    this.requireUsable();
    if (
      !Number.isSafeInteger(startByte) ||
      !Number.isSafeInteger(endByte) ||
      startByte < 0 ||
      endByte < startByte ||
      endByte > Buffer.byteLength(text, "utf8")
    ) {
      throw new Error("Inex editor selection is invalid");
    }
    const changed = this.applyEdit(text);
    this.selection = { startByte, endByte };
    return changed;
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
    this.umbraRenderMap?.generation.fill(0);
    this.umbraRenderMap = undefined;
    this.content = content;
    this.etag = etag;
    this.metadata = metadata;
    this.revision += 1;
    this.savedRevision = this.revision;
    this.staleBackup = false;
    this.broadcast();
  }

  public replaceFromUmbraProjection(
    projection: UmbraProjection,
    metadata: DocumentMetadata,
  ): void {
    this.requireUsable();
    this.content.fill(0);
    this.umbraRenderMap?.generation.fill(0);
    this.content = projection.content;
    this.etag = projection.etag;
    this.metadata = metadata;
    this.umbraRenderMap = projection.renderMap;
    this.revision += 1;
    this.savedRevision = this.revision;
    this.staleBackup = false;
    this.selection = undefined;
    this.broadcast();
  }

  public async releaseOrdinaryHandle(): Promise<void> {
    const handle = this.handle;
    if (handle === undefined) {
      return;
    }
    await this.session.sidecar.closeDocument(handle);
    this.handle = undefined;
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
      readOnly: this.isUmbraProjection,
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
    this.umbraRenderMap?.generation.fill(0);
    this.umbraRenderMap = undefined;
    this.selection = undefined;
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
    this.umbraRenderMap?.generation.fill(0);
    this.umbraRenderMap = undefined;
    this.selection = undefined;
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
    const handle = this.handle;
    this.closeHandlePromise ??= handle === undefined
      ? Promise.resolve()
      : this.session.sidecar.closeDocument(handle);
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
  private readonly previews: AssetPreviewCoordinator;
  private activeDocument: InexDocument | undefined;
  private lastBackupUri: vscode.Uri | undefined;
  private failNextMutationCloseForTest = false;

  public readonly onDidChangeCustomDocument = this.changeEmitter.event;

  public constructor(
    private readonly controller: VaultController,
    private readonly integrationTestMode = false,
  ) {
    this.previews = new AssetPreviewCoordinator(controller);
    this.lockSubscription = controller.onDidLock(() => {
      this.previews.cancelAll();
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
    let opened: Awaited<ReturnType<typeof sidecar.openDocument>> | undefined;
    let umbraProjection: UmbraProjection | undefined;
    try {
      opened = await sidecar.openDocument(logicalPath);
    } catch (normalOpenError: unknown) {
      const status = await sidecar.umbraStatus().catch(() => undefined);
      if (status?.unlocked !== true) {
        throw normalOpenError;
      }
      umbraProjection = await sidecar.openUmbraDocument(logicalPath);
    }
    let content = opened?.content ?? umbraProjection!.content;
    let restoredBackup = false;
    let staleBackup = false;
    try {
      ensureOpenAllowed(this.controller, session, token);
      if (openContext.backupId !== undefined) {
        if (umbraProjection !== undefined) {
          throw new Error("Umbra projection draft recovery is not supported; reopen the committed document");
        }
        if (opened === undefined) {
          throw new Error("Inex ordinary document handle is unavailable for draft recovery");
        }
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
        opened?.handle,
        content,
        opened?.etag ?? umbraProjection!.etag,
        opened?.metadata ?? umbraProjection!.metadata,
        session,
        (disposed) => {
          this.documents.delete(disposed);
          if (this.activeDocument === disposed) {
            this.activeDocument = undefined;
          }
        },
        restoredBackup,
        staleBackup,
        umbraProjection?.renderMap,
      );
      this.documents.add(document);
      return document;
    } catch (error: unknown) {
      content.fill(0);
      if (opened !== undefined) {
        await sidecar.closeDocument(opened.handle).catch(() => undefined);
      }
      if (umbraProjection !== undefined) {
        umbraProjection.renderMap.generation.fill(0);
      }
      throw error;
    }
  }

  public currentVerifiedSelection():
    | { readonly logicalPath: string; readonly session: VaultSession; readonly range: EditorSelection }
    | undefined {
    const document = this.activeDocument;
    if (
      document === undefined ||
      !this.documents.has(document) ||
      !this.controller.isSessionCurrent(document.session)
    ) {
      return undefined;
    }
    const range = document.currentSelection();
    return range === undefined
      ? undefined
      : { logicalPath: document.logicalPath, session: document.session, range };
  }

  public activeSelectionIsCompletePrivateBlock(): boolean {
    const document = this.activeDocument;
    const selection = document?.currentSelection();
    const renderMap = document?.renderMap();
    return document?.isUmbraProjection === true && selection !== undefined && renderMap !== undefined &&
      renderMap.privateSlots.some(
        (slot) => slot.range.startByte === selection.startByte && slot.range.endByte === selection.endByte,
      );
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
    webviewPanel.onDidChangeViewState((event) => {
      if (event.webviewPanel.active && this.documents.has(document)) {
        this.activeDocument = document;
      }
    });
    this.previews.attach(document, webviewPanel);
    webviewPanel.webview.onDidReceiveMessage((message: unknown) => {
      if (!isRecord(message)) {
        return;
      }
      if (
        message.type === "edit" &&
        typeof message.content === "string" &&
        isEditEpoch(message.editEpoch) &&
        this.previews.acceptEditEpoch(document, webviewPanel, message.editEpoch)
      ) {
        try {
          if (document.applyEdit(message.content)) {
            this.controller.noteUserActivity(document.session);
            this.changeEmitter.fire({ document });
          }
          // The webview suspends previews on every local input, including an
          // edit/undo sequence whose final bytes equal the host snapshot.
          // Always issue a new host-owned generation after synchronization.
          this.previews.refreshDocument(document);
        } catch (error: unknown) {
          void vscode.window.showErrorMessage(safeError(error));
          document.send(webviewPanel);
          this.previews.refresh(document, webviewPanel, 0);
        }
        return;
      }
      if (
        message.type === "ready" &&
        isEditEpoch(message.editEpoch) &&
        this.previews.acceptEditEpoch(document, webviewPanel, message.editEpoch)
      ) {
        if (!this.controller.isSessionCurrent(document.session)) {
          webviewPanel.webview.html = lockedHtml();
          return;
        }
        document.markReady(webviewPanel);
        document.send(webviewPanel);
        this.previews.refresh(document, webviewPanel, 0);
        return;
      }
      if (message.type === "activity") {
        this.controller.noteUserActivity(document.session);
        return;
      }
      if (
        message.type === "selection" &&
        typeof message.content === "string" &&
        Number.isSafeInteger(message.startByte) &&
        Number.isSafeInteger(message.endByte) &&
        typeof message.startByte === "number" &&
        typeof message.endByte === "number" &&
        isEditEpoch(message.editEpoch) &&
        this.previews.acceptEditEpoch(document, webviewPanel, message.editEpoch)
      ) {
        try {
          if (document.updateSelection(message.content, message.startByte, message.endByte)) {
            this.changeEmitter.fire({ document });
          }
          this.controller.noteUserActivity(document.session);
          this.previews.refreshDocument(document);
        } catch (error: unknown) {
          void vscode.window.showErrorMessage(safeError(error));
          document.send(webviewPanel);
        }
        return;
      }
      if (
        message.type === "snapshot" &&
        Number.isSafeInteger(message.requestId) &&
        typeof message.requestId === "number" &&
        typeof message.content === "string" &&
        isEditEpoch(message.editEpoch) &&
        this.previews.acceptEditEpoch(document, webviewPanel, message.editEpoch)
      ) {
        try {
          if (document.acceptSnapshot(message.requestId, message.content)) {
            this.controller.noteUserActivity(document.session);
            this.changeEmitter.fire({ document });
          }
          this.previews.refreshDocument(document);
        } catch (error: unknown) {
          void vscode.window.showErrorMessage(safeError(error));
        }
        return;
      }
      if (
        (message.type === "followLink" ||
          message.type === "showHeadings" ||
          message.type === "showBacklinks") &&
        typeof message.content === "string" &&
        isEditEpoch(message.editEpoch) &&
        this.previews.acceptEditEpoch(document, webviewPanel, message.editEpoch)
      ) {
        try {
          if (document.applyEdit(message.content)) {
            this.controller.noteUserActivity(document.session);
            this.changeEmitter.fire({ document });
          }
          this.previews.refreshDocument(document);
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
    if (document.isUmbraProjection) {
      if (document.isDirty) {
        throw new Error("Umbra projection edits are disabled until authenticated Outer editing is available");
      }
      return;
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
    if (document.isUmbraProjection) {
      const projection = await sidecar.openUmbraDocument(document.logicalPath);
      let adopted = false;
      try {
        this.requireCurrentDocumentSession(document);
        document.replaceFromUmbraProjection(projection, projection.metadata);
        this.previews.refreshDocument(document, 0);
        adopted = true;
      } finally {
        if (!adopted) {
          projection.content.fill(0);
          projection.renderMap.generation.fill(0);
        }
      }
      return;
    }
    const reloaded = await sidecar.read(document.logicalPath);
    let adopted = false;
    try {
      if (token.isCancellationRequested) {
        throw new vscode.CancellationError();
      }
      this.requireCurrentDocumentSession(document);
      document.replaceFromCiphertext(reloaded.content, reloaded.etag, reloaded.metadata);
      this.previews.refreshDocument(document, 0);
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
    this.previews.dispose();
    this.lockSubscription.dispose();
    this.changeEmitter.dispose();
  }

  public wipeAllForLock(): void {
    this.previews.cancelAll();
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

  public async convertActiveDocumentToUmbra(): Promise<InexDocument> {
    const document = this.activeDocument;
    if (
      document === undefined ||
      !this.documents.has(document) ||
      !this.controller.isSessionCurrent(document.session)
    ) {
      throw new Error("Focus an active Inex Markdown editor before enabling Umbra");
    }
    if (document.isUmbraProjection) {
      return document;
    }
    const synchronization = new vscode.CancellationTokenSource();
    try {
      await document.flushWebview(synchronization.token);
      const selection = document.currentSelection();
      if (document.isDirty) {
        await this.saveCustomDocument(document, synchronization.token);
      }
      if (document.isDirty) {
        throw new Error("Inex document changed while preparing Umbra conversion");
      }
      const sidecar = this.requireCurrentDocumentSession(document);
      await document.releaseOrdinaryHandle();
      const converted = await sidecar.convertDocumentToUmbra(document.logicalPath, document.etag);
      this.requireCurrentDocumentSession(document);
      const projection = await sidecar.openUmbraDocument(document.logicalPath);
      let adopted = false;
      try {
        this.requireCurrentDocumentSession(document);
        document.replaceFromUmbraProjection(projection, converted.metadata);
        document.restoreSelection(selection);
        this.previews.refreshDocument(document, 0);
        adopted = true;
      } finally {
        if (!adopted) {
          projection.content.fill(0);
          projection.renderMap.generation.fill(0);
        }
      }
      return document;
    } finally {
      synchronization.dispose();
    }
  }

  public async applyPrivateAnnotationToActive(
    spec: PrivateAnnotationSpec,
  ): Promise<void> {
    const document = this.activeDocument;
    if (
      document === undefined ||
      !document.isUmbraProjection ||
      !this.documents.has(document) ||
      !this.controller.isSessionCurrent(document.session)
    ) {
      throw new Error("Open an unlocked Umbra projection before adding a private annotation");
    }
    const selection = document.currentSelection();
    const renderMap = document.renderMap();
    if (selection === undefined || renderMap === undefined) {
      throw new Error("Place the cursor in Markdown content before adding a private annotation");
    }
    let resolvedSelection: EditorSelection | undefined = selection;
    if (selection.startByte === selection.endByte) {
      const selectionSnapshot = document.snapshot();
      try {
        resolvedSelection = paragraphRange(selectionSnapshot.content, selection.startByte);
      } finally {
        selectionSnapshot.content.fill(0);
      }
    }
    if (resolvedSelection === undefined) {
      throw new Error("Current Markdown paragraph is empty or unavailable for private annotation");
    }
    const snapshot = document.snapshot();
    try {
      const sidecar = this.requireCurrentDocumentSession(document);
      const applied = await sidecar.applyUmbraAnnotation(
        document.logicalPath,
        { content: snapshot.content, etag: document.etag, metadata: document.metadata, renderMap },
        [resolvedSelection],
        spec,
      );
      this.requireCurrentDocumentSession(document);
      document.replaceFromUmbraProjection(applied, applied.metadata);
      this.previews.refreshDocument(document, 0);
    } finally {
      snapshot.content.fill(0);
    }
  }

  public async removePrivateAnnotationFromActive(): Promise<void> {
    const document = this.activeDocument;
    if (
      document === undefined ||
      !document.isUmbraProjection ||
      !this.documents.has(document) ||
      !this.controller.isSessionCurrent(document.session)
    ) {
      throw new Error("Open an unlocked Umbra projection before removing a private annotation");
    }
    const selection = document.currentSelection();
    const renderMap = document.renderMap();
    if (selection === undefined || selection.startByte === selection.endByte || renderMap === undefined) {
      throw new Error("Select one complete private annotation block before removing it");
    }
    const snapshot = document.snapshot();
    try {
      const sidecar = this.requireCurrentDocumentSession(document);
      const applied = await sidecar.removeUmbraAnnotation(
        document.logicalPath,
        { content: snapshot.content, etag: document.etag, metadata: document.metadata, renderMap },
        [selection],
      );
      this.requireCurrentDocumentSession(document);
      document.replaceFromUmbraProjection(applied, applied.metadata);
      this.previews.refreshDocument(document, 0);
    } finally {
      snapshot.content.fill(0);
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
        this.previews.refreshDocument(document);
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

function paragraphRange(content: Buffer, offset: number): EditorSelection | undefined {
  if (offset < 0 || offset > content.byteLength) return undefined;
  let start = offset;
  while (start > 0 && content[start - 1] !== 0x0a) start -= 1;
  let end = offset;
  while (end < content.byteLength && content[end] !== 0x0a) end += 1;
  if (start === end) return undefined;
  return { startByte: start, endByte: end };
}

function editorHtml(): string {
  const nonce = randomBytes(18).toString("base64");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; img-src blob:">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style nonce="${nonce}">html,body{box-sizing:border-box;width:100%;height:100%;margin:0}body{display:grid;grid-template-rows:auto minmax(10rem,1fr) auto;background:var(--vscode-editor-background)}nav{display:flex;gap:.4rem;padding:.35rem .6rem;border-bottom:1px solid var(--vscode-panel-border)}button{color:var(--vscode-button-foreground);background:var(--vscode-button-background);border:0;padding:.25rem .6rem}textarea{box-sizing:border-box;width:100%;height:100%;resize:none;border:0;padding:1rem;color:var(--vscode-editor-foreground);background:var(--vscode-editor-background);font:var(--vscode-editor-font-size) var(--vscode-editor-font-family);outline:none}#previews{display:flex;gap:.75rem;overflow:auto;max-height:40vh;padding:.6rem;border-top:1px solid var(--vscode-panel-border)}#previews[hidden]{display:none}figure{flex:0 0 auto;max-width:min(32rem,80vw);margin:0}figure img{display:block;max-width:100%;max-height:32vh}figcaption{overflow:hidden;margin-top:.25rem;color:var(--vscode-descriptionForeground);text-overflow:ellipsis;white-space:nowrap}.blocked{color:var(--vscode-descriptionForeground)}</style>
</head><body><nav><button id="headings" type="button">Headings</button><button id="backlinks" type="button">Backlinks</button></nav><textarea id="editor" aria-label="Encrypted Markdown editor" spellcheck="false" autocomplete="off" autocorrect="off" autocapitalize="off"></textarea><section id="previews" aria-label="Validated encrypted image previews" hidden></section>
<script nonce="${nonce}">
const vscode=acquireVsCodeApi();
const editor=document.getElementById('editor');
const previews=document.getElementById('previews');
const encoder=new TextEncoder();
let applying=false;
let editTimer;
let lastActivity=0;
let previewGeneration=0;
let previewSuspended=true;
let editEpoch=0;
const transfers=new Map();
const objectUrls=new Set();
function byteIndex(text,target){let bytes=0,index=0;for(const scalar of text){if(bytes>=target)break;bytes+=encoder.encode(scalar).length;index+=scalar.length;}return index;}
function byteOffset(text,target){return encoder.encode(text.slice(0,target)).length;}
function cancelEditTimer(){if(editTimer!==undefined){clearTimeout(editTimer);editTimer=undefined;}}
function sendEdit(){cancelEditTimer();if(!applying)vscode.postMessage({type:'edit',content:editor.value,editEpoch});}
function sendNavigation(type,offset){cancelEditTimer();vscode.postMessage({type,offset,content:editor.value,editEpoch});}
function wipe(bytes){if(bytes&&typeof bytes.fill==='function')bytes.fill(0);}
function wipeTransfer(transfer){for(const chunk of transfer.chunks)wipe(chunk);transfer.chunks.length=0;transfer.total=0;}
function clearPreviewStorage(){for(const transfer of transfers.values())wipeTransfer(transfer);transfers.clear();for(const url of objectUrls)URL.revokeObjectURL(url);objectUrls.clear();previews.replaceChildren();previews.hidden=true;}
function suspendPreviews(){clearPreviewStorage();previewSuspended=true;}
function acceptPreviewReset(message){if(!Number.isSafeInteger(message.generation)||message.generation<=previewGeneration||message.editEpoch!==editEpoch)return;clearPreviewStorage();previewGeneration=message.generation;previewSuspended=false;}
function blocked(logicalPath){const item=document.createElement('span');item.className='blocked';item.textContent='Preview blocked: '+logicalPath;previews.append(item);previews.hidden=false;}
function rejectTransfer(id,show){const transfer=transfers.get(id);if(transfer!==undefined){wipeTransfer(transfer);transfers.delete(id);if(show)blocked(transfer.logicalPath);}}
function acceptAssetStart(message){if(previewSuspended||message.editEpoch!==editEpoch||message.generation!==previewGeneration||typeof message.transferId!=='string'||typeof message.logicalPath!=='string'||!Number.isSafeInteger(message.size)||message.size<0||message.size>33554432)return;rejectTransfer(message.transferId,false);transfers.set(message.transferId,{logicalPath:message.logicalPath,size:message.size,total:0,chunks:[]});}
function acceptAssetChunk(message){const transfer=transfers.get(message.transferId);let bytes=message.bytes instanceof Uint8Array?message.bytes:message.bytes instanceof ArrayBuffer?new Uint8Array(message.bytes):undefined;if(previewSuspended||message.editEpoch!==editEpoch||message.generation!==previewGeneration||transfer===undefined||bytes===undefined||!Number.isSafeInteger(message.offset)||message.offset!==transfer.total||bytes.byteLength>1048576||transfer.total+bytes.byteLength>transfer.size){wipe(bytes);if(transfer!==undefined)rejectTransfer(message.transferId,true);return;}transfer.chunks.push(bytes);transfer.total+=bytes.byteLength;}
function acceptAssetEnd(message){const transfer=transfers.get(message.transferId);if(previewSuspended||message.editEpoch!==editEpoch||message.generation!==previewGeneration||transfer===undefined||transfer.total!==transfer.size){if(transfer!==undefined)rejectTransfer(message.transferId,true);return;}transfers.delete(message.transferId);const bytes=new Uint8Array(transfer.size);let offset=0;for(const chunk of transfer.chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;wipe(chunk);}transfer.chunks.length=0;const type=validatedRasterType(bytes);if(type===undefined){wipe(bytes);blocked(transfer.logicalPath);return;}const blob=new Blob([bytes],{type});wipe(bytes);const url=URL.createObjectURL(blob);objectUrls.add(url);const figure=document.createElement('figure');const image=document.createElement('img');image.alt='';image.src=url;image.addEventListener('error',()=>{URL.revokeObjectURL(url);objectUrls.delete(url);figure.remove();if(previews.childElementCount===0)previews.hidden=true;},{once:true});const caption=document.createElement('figcaption');caption.textContent=transfer.logicalPath;figure.append(image,caption);previews.append(figure);previews.hidden=false;}
function validRasterDimensions(dimensions){return dimensions!==undefined&&dimensions[0]>=1&&dimensions[1]>=1&&dimensions[0]<=16384&&dimensions[1]<=16384&&dimensions[0]*dimensions[1]<=40000000;}
function validatedRasterType(bytes){let dimensions;if(isPng(bytes))dimensions=pngDimensions(bytes);else if(isJpeg(bytes))dimensions=jpegDimensions(bytes);else if(isWebP(bytes))dimensions=webpDimensions(bytes);else return undefined;if(!validRasterDimensions(dimensions))return undefined;return isPng(bytes)?'image/png':isJpeg(bytes)?'image/jpeg':'image/webp';}
function isPng(b){return b.length>=8&&b[0]===137&&b[1]===80&&b[2]===78&&b[3]===71&&b[4]===13&&b[5]===10&&b[6]===26&&b[7]===10;}
function u16be(b,o){return b[o]*256+b[o+1];}
function u24le(b,o){return b[o]+b[o+1]*256+b[o+2]*65536;}
function u32be(b,o){return b[o]*16777216+b[o+1]*65536+b[o+2]*256+b[o+3];}
function u32le(b,o){return (b[o]+b[o+1]*256+b[o+2]*65536+b[o+3]*16777216)>>>0;}
function ascii(b,o,n){let value='';for(let i=0;i<n;i+=1)value+=String.fromCharCode(b[o+i]);return value;}
function pngDimensions(b){let o=8,width=0,height=0,sawHeader=false,sawEnd=false;while(o+12<=b.length){const length=u32be(b,o);if(length>b.length-o-12)return undefined;const type=ascii(b,o+4,4);const data=o+8;if(!sawHeader){if(type!=='IHDR'||length!==13)return undefined;width=u32be(b,data);height=u32be(b,data+4);sawHeader=true;}if(type==='acTL'||type==='fcTL'||type==='fdAT')return undefined;if(type==='IEND'){if(length!==0||o+12!==b.length)return undefined;sawEnd=true;}o+=12+length;if(sawEnd)break;}return sawHeader&&sawEnd?[width,height]:undefined;}
function isJpeg(b){return b.length>=4&&b[0]===255&&b[1]===216;}
function isSof(marker){return [192,193,194,195,197,198,199,201,202,203,205,206,207].includes(marker);}
function jpegDimensions(b){let i=2,width=0,height=0,inScan=false;while(i<b.length){let marker;if(inScan){let found=false;while(i<b.length){if(b[i++]!==255)continue;while(i<b.length&&b[i]===255)i+=1;if(i>=b.length)return undefined;marker=b[i++];if(marker===0||marker>=208&&marker<=215)continue;found=true;break;}if(!found)return undefined;}else{if(b[i++]!==255)return undefined;while(i<b.length&&b[i]===255)i+=1;if(i>=b.length)return undefined;marker=b[i++];}if(marker===217)return i===b.length&&width>0&&height>0?[width,height]:undefined;if(marker===216||marker===1||marker>=208&&marker<=215)return undefined;if(i+2>b.length)return undefined;const length=u16be(b,i);if(length<2||i+length>b.length)return undefined;if(isSof(marker)){if(length<7)return undefined;const nextHeight=u16be(b,i+3),nextWidth=u16be(b,i+5);if(width!==0&&(width!==nextWidth||height!==nextHeight))return undefined;width=nextWidth;height=nextHeight;}i+=length;if(marker===218)inScan=true;}return undefined;}
function isWebP(b){return b.length>=12&&ascii(b,0,4)==='RIFF'&&ascii(b,8,4)==='WEBP'&&u32le(b,4)+8===b.length;}
function webpDimensions(b){let i=12,index=0,flags=0,canvasWidth=0,canvasHeight=0,frameWidth=0,frameHeight=0,primaryType='',previous='',extended=false,iccp=false,alpha=false,exif=false,xmp=false;while(i+8<=b.length){const type=ascii(b,i,4),length=u32le(b,i+4),data=i+8,end=data+length,padded=end+(length&1);if(end>b.length||padded>b.length||(length&1)!==0&&b[end]!==0)return undefined;if(type==='ANIM'||type==='ANMF')return undefined;if(type==='VP8X'){if(index!==0||extended||length!==10||(b[data]&193)!==0||(b[data]&2)!==0||b[data+1]!==0||b[data+2]!==0||b[data+3]!==0)return undefined;extended=true;flags=b[data];canvasWidth=u24le(b,data+4)+1;canvasHeight=u24le(b,data+7)+1;if(!validRasterDimensions([canvasWidth,canvasHeight]))return undefined;}else if(type==='ICCP'){if(!extended||index!==1||iccp||primaryType!==''||(flags&32)===0)return undefined;iccp=true;}else if(type==='ALPH'){if(!extended||alpha||primaryType!==''||(flags&16)===0)return undefined;alpha=true;}else if(type==='VP8 '){if(primaryType!==''||!extended&&index!==0||alpha&&previous!=='ALPH'||extended&&(flags&16)!==0&&!alpha||length<10||b[data+3]!==157||b[data+4]!==1||b[data+5]!==42)return undefined;frameWidth=(b[data+6]+b[data+7]*256)&16383;frameHeight=(b[data+8]+b[data+9]*256)&16383;if(!validRasterDimensions([frameWidth,frameHeight]))return undefined;primaryType=type;}else if(type==='VP8L'){if(primaryType!==''||alpha||!extended&&index!==0||length<5||b[data]!==47)return undefined;frameWidth=1+b[data+1]+((b[data+2]&63)<<8);frameHeight=1+(b[data+2]>>6)+(b[data+3]<<2)+((b[data+4]&15)<<10);if(!validRasterDimensions([frameWidth,frameHeight]))return undefined;primaryType=type;}else if(type==='EXIF'){if(!extended||primaryType===''||exif||xmp||(flags&8)===0)return undefined;exif=true;}else if(type==='XMP '){if(!extended||primaryType===''||xmp||(flags&4)===0)return undefined;xmp=true;}else{return undefined;}previous=type;i=padded;index+=1;}if(i!==b.length||primaryType===''||extended&&(canvasWidth!==frameWidth||canvasHeight!==frameHeight||iccp!==((flags&32)!==0)||exif!==((flags&8)!==0)||xmp!==((flags&4)!==0)))return undefined;return [frameWidth,frameHeight];}
editor.addEventListener('input',()=>{if(!applying){if(editEpoch>=Number.MAX_SAFE_INTEGER){suspendPreviews();return;}editEpoch+=1;suspendPreviews();const now=Date.now();if(now-lastActivity>=1000){lastActivity=now;vscode.postMessage({type:'activity'});}cancelEditTimer();editTimer=setTimeout(sendEdit,150);}});
editor.addEventListener('select',()=>{if(!applying)vscode.postMessage({type:'selection',content:editor.value,startByte:byteOffset(editor.value,editor.selectionStart),endByte:byteOffset(editor.value,editor.selectionEnd),editEpoch});});
editor.addEventListener('click',(event)=>{if(event.ctrlKey||event.metaKey)sendNavigation('followLink',editor.selectionStart);});
editor.addEventListener('keydown',(event)=>{if((event.ctrlKey||event.metaKey)&&event.key==='Enter'){event.preventDefault();sendNavigation('followLink',editor.selectionStart);}});
document.getElementById('headings').addEventListener('click',()=>sendNavigation('showHeadings',editor.selectionStart));
document.getElementById('backlinks').addEventListener('click',()=>sendNavigation('showBacklinks',editor.selectionStart));
window.addEventListener('message',(event)=>{const message=event.data;if(!message||typeof message!=='object')return;if(message.type==='content'&&typeof message.content==='string'&&typeof message.readOnly==='boolean'){cancelEditTimer();applying=true;editor.value=message.content;editor.readOnly=message.readOnly;applying=false;}else if(message.type==='reveal'&&Number.isSafeInteger(message.startByte)&&Number.isSafeInteger(message.endByte)){const start=byteIndex(editor.value,message.startByte);const end=byteIndex(editor.value,message.endByte);editor.focus();editor.setSelectionRange(start,end);}else if(message.type==='snapshotRequest'&&Number.isSafeInteger(message.requestId)){cancelEditTimer();vscode.postMessage({type:'snapshot',requestId:message.requestId,content:editor.value,editEpoch});}else if(message.type==='previewReset'){acceptPreviewReset(message);}else if(message.type==='assetStart'){acceptAssetStart(message);}else if(message.type==='assetChunk'){acceptAssetChunk(message);}else if(message.type==='assetEnd'){acceptAssetEnd(message);}else if(message.type==='assetRejected'&&!previewSuspended&&message.editEpoch===editEpoch&&message.generation===previewGeneration&&typeof message.logicalPath==='string'){if(typeof message.transferId==='string')rejectTransfer(message.transferId,false);blocked(message.logicalPath);}});
window.addEventListener('beforeunload',suspendPreviews);
vscode.postMessage({type:'ready',editEpoch});
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

function isEditEpoch(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
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
