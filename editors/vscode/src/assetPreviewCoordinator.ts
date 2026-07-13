import * as vscode from "vscode";

import { parseMarkdownImageTargets } from "./assetPreview.ts";
import type { VaultController, VaultSession } from "./controller.ts";
import { MAX_ASSET_CHUNK_BYTES } from "./sidecar.ts";

const MAX_INLINE_IMAGE_BYTES = 32 * 1024 * 1024;
const MAX_PANEL_IMAGE_BYTES = 64 * 1024 * 1024;
const REFRESH_DELAY_MS = 250;

export interface PreviewDocument {
  readonly logicalPath: string;
  readonly session: VaultSession;
  snapshot(): { readonly content: Buffer; readonly revision: number };
}

interface PanelPreviewState {
  readonly document: PreviewDocument;
  readonly panel: vscode.WebviewPanel;
  generation: number;
  editEpoch: number;
  cancellation: vscode.CancellationTokenSource | undefined;
  timer: NodeJS.Timeout | undefined;
  disposed: boolean;
}

export class AssetPreviewCoordinator implements vscode.Disposable {
  private readonly states = new Map<vscode.WebviewPanel, PanelPreviewState>();
  private queue: Promise<void> = Promise.resolve();
  private disposed = false;

  public constructor(private readonly controller: VaultController) {}

  public attach(document: PreviewDocument, panel: vscode.WebviewPanel): void {
    const state: PanelPreviewState = {
      document,
      panel,
      generation: 0,
      editEpoch: 0,
      cancellation: undefined,
      timer: undefined,
      disposed: false,
    };
    this.states.set(panel, state);
    panel.onDidDispose(() => {
      this.cancelState(state, false);
      state.disposed = true;
      this.states.delete(panel);
    });
    panel.onDidChangeViewState(() => {
      if (panel.visible) {
        this.refresh(document, panel, 0);
      } else {
        this.cancelState(state, true);
      }
    });
  }

  public refresh(
    document: PreviewDocument,
    panel: vscode.WebviewPanel,
    delayMs = REFRESH_DELAY_MS,
  ): void {
    const state = this.states.get(panel);
    if (
      state === undefined ||
      state.document !== document ||
      state.disposed ||
      this.disposed
    ) {
      return;
    }
    this.cancelState(state, false);
    state.generation = nextGeneration(state.generation);
    const generation = state.generation;
    const editEpoch = state.editEpoch;
    void panel.webview.postMessage({ type: "previewReset", generation, editEpoch });
    if (!panel.visible) {
      return;
    }
    state.timer = setTimeout(() => {
      state.timer = undefined;
      const cancellation = new vscode.CancellationTokenSource();
      state.cancellation = cancellation;
      const run = () => this.run(state, generation, editEpoch, cancellation);
      this.queue = this.queue.then(run, run).catch(() => undefined);
    }, Math.max(0, delayMs));
  }

  /** Accept one webview-owned edit epoch before adopting its content. */
  public acceptEditEpoch(
    document: PreviewDocument,
    panel: vscode.WebviewPanel,
    editEpoch: number,
  ): boolean {
    const state = this.states.get(panel);
    if (
      state === undefined ||
      state.document !== document ||
      !Number.isSafeInteger(editEpoch) ||
      editEpoch < state.editEpoch ||
      editEpoch < 0
    ) {
      return false;
    }
    state.editEpoch = editEpoch;
    return true;
  }

  public refreshDocument(document: PreviewDocument, delayMs = REFRESH_DELAY_MS): void {
    for (const state of this.states.values()) {
      if (state.document === document) {
        this.refresh(document, state.panel, delayMs);
      }
    }
  }

  public cancelAll(): void {
    for (const state of this.states.values()) {
      this.cancelState(state, true);
    }
  }

  public dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    for (const state of this.states.values()) {
      this.cancelState(state, true);
      state.disposed = true;
    }
    this.states.clear();
  }

  private async run(
    state: PanelPreviewState,
    generation: number,
    editEpoch: number,
    cancellation: vscode.CancellationTokenSource,
  ): Promise<void> {
    const token = cancellation.token;
    try {
      if (!this.isCurrent(state, generation, editEpoch, token)) {
        return;
      }
      const session = state.document.session;
      if (
        !this.controller.isSessionCurrent(session) ||
        !session.sidecar.canReadOpaqueAssetsV1
      ) {
        return;
      }
      const snapshot = state.document.snapshot();
      let targets: readonly string[];
      try {
        targets = parseMarkdownImageTargets(
          state.document.logicalPath,
          snapshot.content.toString("utf8"),
        );
      } finally {
        snapshot.content.fill(0);
      }
      if (
        targets.length === 0 ||
        !this.isCurrent(state, generation, editEpoch, token)
      ) {
        return;
      }
      const entries = await this.controller.listTreeForSession(session);
      if (!this.isCurrent(state, generation, editEpoch, token)) {
        return;
      }
      const assets = new Set(
        entries
          .filter((entry) => entry.kind === "asset")
          .map((entry) => entry.logicalPath),
      );
      let aggregateBytes = 0;
      let transferIndex = 0;
      for (const logicalPath of targets) {
        if (
          !assets.has(logicalPath) ||
          !this.isCurrent(state, generation, editEpoch, token)
        ) {
          continue;
        }
        const transferId = `${generation}:${transferIndex}`;
        transferIndex += 1;
        let handle: string | undefined;
        try {
          const opened = await session.sidecar.openAsset(logicalPath);
          handle = opened.handle;
          if (!this.isCurrent(state, generation, editEpoch, token)) {
            continue;
          }
          if (
            opened.size > MAX_INLINE_IMAGE_BYTES ||
            opened.size > MAX_PANEL_IMAGE_BYTES - aggregateBytes
          ) {
            await this.post(state, generation, editEpoch, token, {
              type: "assetRejected",
              generation,
              editEpoch,
              logicalPath,
              reason: "previewLimit",
            });
            continue;
          }
          aggregateBytes += opened.size;
          await this.post(state, generation, editEpoch, token, {
            type: "assetStart",
            generation,
            editEpoch,
            transferId,
            logicalPath,
            size: opened.size,
          });
          let offset = 0;
          while (this.isCurrent(state, generation, editEpoch, token)) {
            const chunk = await session.sidecar.readAssetChunk(
              opened.handle,
              offset,
              MAX_ASSET_CHUNK_BYTES,
            );
            const end = offset + chunk.content.byteLength;
            if (
              chunk.offset !== offset ||
              end > opened.size ||
              chunk.eof !== (end === opened.size)
            ) {
              chunk.content.fill(0);
              throw new Error("Inex asset stream did not match its authenticated size");
            }
            const bytes = Uint8Array.from(chunk.content);
            chunk.content.fill(0);
            try {
              await this.post(state, generation, editEpoch, token, {
                type: "assetChunk",
                generation,
                editEpoch,
                transferId,
                offset,
                bytes,
                eof: chunk.eof,
              });
            } finally {
              bytes.fill(0);
            }
            offset = end;
            if (chunk.eof) {
              await this.post(state, generation, editEpoch, token, {
                type: "assetEnd",
                generation,
                editEpoch,
                transferId,
              });
              break;
            }
          }
        } catch {
          if (this.isCurrent(state, generation, editEpoch, token)) {
            await state.panel.webview.postMessage({
              type: "assetRejected",
              generation,
              editEpoch,
              transferId,
              logicalPath,
              reason: "unavailable",
            });
          }
        } finally {
          if (handle !== undefined && this.controller.isSessionCurrent(session)) {
            await session.sidecar.closeAsset(handle);
          }
        }
      }
    } finally {
      if (state.cancellation === cancellation) {
        cancellation.dispose();
        state.cancellation = undefined;
      }
    }
  }

  private async post(
    state: PanelPreviewState,
    generation: number,
    editEpoch: number,
    token: vscode.CancellationToken,
    message: Record<string, unknown>,
  ): Promise<void> {
    if (!this.isCurrent(state, generation, editEpoch, token)) {
      throw new vscode.CancellationError();
    }
    if (!(await state.panel.webview.postMessage(message))) {
      throw new vscode.CancellationError();
    }
    if (!this.isCurrent(state, generation, editEpoch, token)) {
      throw new vscode.CancellationError();
    }
  }

  private isCurrent(
    state: PanelPreviewState,
    generation: number,
    editEpoch: number,
    token: vscode.CancellationToken,
  ): boolean {
    return (
      !this.disposed &&
      !state.disposed &&
      state.panel.visible &&
      state.generation === generation &&
      state.editEpoch === editEpoch &&
      !token.isCancellationRequested &&
      this.controller.isSessionCurrent(state.document.session)
    );
  }

  private cancelState(state: PanelPreviewState, postReset: boolean): void {
    if (state.timer !== undefined) {
      clearTimeout(state.timer);
      state.timer = undefined;
    }
    state.cancellation?.cancel();
    state.cancellation?.dispose();
    state.cancellation = undefined;
    state.generation = nextGeneration(state.generation);
    if (postReset && !state.disposed) {
      void state.panel.webview.postMessage({
        type: "previewReset",
        generation: state.generation,
        editEpoch: state.editEpoch,
      });
    }
  }
}

function nextGeneration(value: number): number {
  return value >= Number.MAX_SAFE_INTEGER ? 1 : value + 1;
}
