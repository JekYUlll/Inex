import * as path from "node:path";

import * as vscode from "vscode";

import {
  InexSidecar,
  SidecarLifecycleError,
  type UnlockResult,
  resolveSidecarExecutable,
} from "./sidecar.ts";
import { logicalFileComponents } from "./logicalPath.ts";
import { showSensitiveInputBox } from "./sensitiveUi.ts";

export class VaultController implements vscode.Disposable {
  private readonly stateEmitter = new vscode.EventEmitter<void>();
  private readonly lockEmitter = new vscode.EventEmitter<void>();
  private sidecar: InexSidecar | undefined;
  private root: vscode.Uri | undefined;
  private generation = 0;
  private pendingUnlock: Promise<UnlockResult | undefined> | undefined;
  private idleTimeoutMs: number | undefined;
  private idleTimer: NodeJS.Timeout | undefined;
  private idleWarningTimer: NodeJS.Timeout | undefined;
  private nextKeepaliveAt = 0;

  public readonly onDidChangeState = this.stateEmitter.event;
  public readonly onDidLock = this.lockEmitter.event;

  public constructor(private readonly context: vscode.ExtensionContext) {}

  public get isUnlocked(): boolean {
    return this.sidecar?.hasSession === true && this.root !== undefined;
  }

  public get vaultRoot(): vscode.Uri | undefined {
    return this.root;
  }

  public requireSidecar(): InexSidecar {
    if (!this.isUnlocked || this.sidecar === undefined) {
      throw new SidecarLifecycleError("Inex vault is locked");
    }
    return this.sidecar;
  }

  public unlockInteractive(expectedCiphertext?: vscode.Uri): Promise<UnlockResult | undefined> {
    if (this.pendingUnlock !== undefined) {
      return this.pendingUnlock;
    }
    if (this.sidecar !== undefined || this.root !== undefined) {
      throw new SidecarLifecycleError("Lock the current Inex vault before unlocking another one");
    }
    const operationGeneration = this.generation;
    let tracked: Promise<UnlockResult | undefined>;
    tracked = this.unlockInteractiveOnce(operationGeneration, expectedCiphertext).finally(() => {
      if (this.pendingUnlock === tracked) {
        this.pendingUnlock = undefined;
      }
    });
    this.pendingUnlock = tracked;
    return tracked;
  }

  private async unlockInteractiveOnce(
    operationGeneration: number,
    expectedCiphertext?: vscode.Uri,
  ): Promise<UnlockResult | undefined> {
    const dialogOptions: vscode.OpenDialogOptions = {
      canSelectFiles: false,
      canSelectFolders: true,
      canSelectMany: false,
      openLabel: "Open Inex Vault",
      title: "Select the ciphertext vault containing vault.json",
    };
    const defaultUri = vscode.workspace.workspaceFolders?.[0]?.uri;
    if (defaultUri !== undefined) {
      dialogOptions.defaultUri = defaultUri;
    }
    const selected = await vscode.window.showOpenDialog(dialogOptions);
    if (this.generation !== operationGeneration) {
      throw new SidecarLifecycleError("Inex unlock was cancelled by a vault state change");
    }
    const root = selected?.[0];
    if (root === undefined) {
      return undefined;
    }
    if (root.scheme !== "file") {
      throw new SidecarLifecycleError("Inex v1 supports local file vaults only");
    }
    if (expectedCiphertext !== undefined) {
      logicalPathRelativeToRoot(expectedCiphertext, root);
    }
    await validateVaultRoot(root);
    if (this.generation !== operationGeneration) {
      throw new SidecarLifecycleError("Inex unlock was cancelled by a vault state change");
    }
    const configured = vscode.workspace
      .getConfiguration("inex")
      .get<string>("sidecarPath", "");
    const executable = resolveSidecarExecutable(configured, this.context.extensionPath);
    let password: string | undefined = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        password: true,
        prompt: "Vault password (kept only in process memory)",
        title: "Unlock Inex Vault",
        validateInput: (value) => {
          const bytes = Buffer.byteLength(value, "utf8");
          return bytes >= 1 && bytes <= 1024
            ? undefined
            : "Password must be 1–1024 UTF-8 bytes";
        },
      },
      this.onDidLock,
    );
    if (password === undefined) {
      return undefined;
    }

    try {
      if (this.generation !== operationGeneration) {
        throw new SidecarLifecycleError("Inex unlock was cancelled by a vault state change");
      }
      return await this.startUnlockedSidecar(root, password, executable, operationGeneration);
    } finally {
      password = undefined;
    }
  }

  public async unlockForIntegrationTest(
    vaultPath: string,
    password: string,
    executablePath: string,
  ): Promise<UnlockResult> {
    if (
      this.context.extensionMode !== vscode.ExtensionMode.Test ||
      process.env.INEX_VSCODE_INTEGRATION_TEST !== "1"
    ) {
      throw new SidecarLifecycleError("Inex integration-test unlock is unavailable");
    }
    if (this.pendingUnlock !== undefined || this.sidecar !== undefined || this.root !== undefined) {
      throw new SidecarLifecycleError("Inex vault transition is already active");
    }
    const root = vscode.Uri.file(vaultPath);
    await validateVaultRoot(root);
    const executable = resolveSidecarExecutable(executablePath, this.context.extensionPath);
    return this.startUnlockedSidecar(root, password, executable, this.generation);
  }

  private async startUnlockedSidecar(
    root: vscode.Uri,
    password: string,
    executable: string,
    operationGeneration: number,
  ): Promise<UnlockResult> {
    let sidecar: InexSidecar;
    sidecar = new InexSidecar(
      executable,
      () => {
        this.invalidateSession(sidecar);
      },
      () => {
        if (this.sidecar === sidecar) {
          this.resetIdleDeadline();
        }
      },
    );
    try {
      const version = this.context.extension.packageJSON.version;
      if (typeof version !== "string" || version.length === 0) {
        throw new SidecarLifecycleError("Inex extension version metadata is invalid");
      }
      await sidecar.start(version);
      const result = await sidecar.unlock(root.fsPath, password);
      if (this.generation !== operationGeneration) {
        throw new SidecarLifecycleError("Inex unlock was cancelled by a vault state change");
      }
      this.sidecar = sidecar;
      this.root = root;
      this.advanceGeneration();
      this.idleTimeoutMs = result.idleTimeoutMs;
      this.resetIdleDeadline();
      this.stateEmitter.fire();
      return result;
    } catch (error: unknown) {
      sidecar.dispose();
      throw error;
    }
  }

  public async lock(): Promise<void> {
    const sidecar = this.sidecar;
    this.sidecar = undefined;
    this.root = undefined;
    this.advanceGeneration();
    this.idleTimeoutMs = undefined;
    this.clearIdleDeadline();
    this.lockEmitter.fire();
    this.stateEmitter.fire();
    if (sidecar !== undefined) {
      try {
        if (sidecar.hasSession) {
          await sidecar.lock();
        }
        await sidecar.shutdown();
      } finally {
        sidecar.dispose();
      }
    }
  }

  public acquireSession(): VaultSession {
    const root = this.root;
    const sidecar = this.sidecar;
    if (root === undefined || sidecar === undefined || !sidecar.hasSession) {
      throw new SidecarLifecycleError("Inex vault is locked");
    }
    return { root, sidecar, generation: this.generation };
  }

  public isSessionCurrent(session: VaultSession): boolean {
    return (
      this.root === session.root &&
      this.sidecar === session.sidecar &&
      this.generation === session.generation &&
      session.sidecar.hasSession
    );
  }

  public noteUserActivity(expectedSession?: VaultSession): void {
    if (
      expectedSession !== undefined &&
      !this.isSessionCurrent(expectedSession)
    ) {
      return;
    }
    const sidecar = this.sidecar;
    const idleTimeoutMs = this.idleTimeoutMs;
    if (sidecar === undefined || idleTimeoutMs === undefined || !sidecar.hasSession) {
      return;
    }
    const now = Date.now();
    if (now < this.nextKeepaliveAt) {
      return;
    }
    const interval = Math.max(250, Math.min(60_000, Math.floor(idleTimeoutMs / 4)));
    this.nextKeepaliveAt = now + interval;
    void sidecar.touch().catch(() => undefined);
  }

  public logicalPathForSession(uri: vscode.Uri, session: VaultSession): string {
    if (!this.isSessionCurrent(session)) {
      throw new SidecarLifecycleError("Inex vault session changed while opening the document");
    }
    return logicalPathRelativeToRoot(uri, session.root);
  }

  public ciphertextUri(logicalPath: string): vscode.Uri {
    const root = this.root;
    if (root === undefined) {
      throw new SidecarLifecycleError("Inex vault is locked");
    }
    const components = logicalFileComponents(logicalPath);
    const fileName = components.at(-1);
    if (fileName === undefined) {
      throw new SidecarLifecycleError("Logical document path is invalid");
    }
    return vscode.Uri.joinPath(
      root,
      ...components.slice(0, -1),
      `${fileName}.enc`,
    );
  }

  public dispose(): void {
    const sidecar = this.sidecar;
    this.sidecar = undefined;
    this.root = undefined;
    this.advanceGeneration();
    this.idleTimeoutMs = undefined;
    this.clearIdleDeadline();
    this.lockEmitter.fire();
    sidecar?.dispose();
    this.lockEmitter.dispose();
    this.stateEmitter.dispose();
  }

  private advanceGeneration(): void {
    this.generation =
      this.generation >= Number.MAX_SAFE_INTEGER ? 1 : this.generation + 1;
  }

  private resetIdleDeadline(): void {
    const idleTimeoutMs = this.idleTimeoutMs;
    if (idleTimeoutMs === undefined || !Number.isSafeInteger(idleTimeoutMs) || idleTimeoutMs <= 0) {
      return;
    }
    this.clearIdleDeadline();
    const warningLead = Math.min(60_000, Math.max(1_000, Math.floor(idleTimeoutMs / 5)));
    if (idleTimeoutMs > warningLead) {
      this.idleWarningTimer = setTimeout(() => {
        if (this.isUnlocked) {
          void vscode.window.showWarningMessage(
            "Inex will lock soon because the sidecar session has been idle. Save or continue editing to renew it.",
          );
        }
      }, idleTimeoutMs - warningLead);
    }
    const sidecar = this.sidecar;
    this.idleTimer = setTimeout(() => {
      if (sidecar !== undefined && this.sidecar === sidecar) {
        this.invalidateSession(sidecar);
        void vscode.window.showWarningMessage(
          "Inex locked after the sidecar idle timeout; encrypted custom-editor backup remains the recovery path for unsaved edits.",
        );
      }
    }, idleTimeoutMs);
    this.nextKeepaliveAt = Date.now() + Math.max(250, Math.min(60_000, Math.floor(idleTimeoutMs / 4)));
  }

  private clearIdleDeadline(): void {
    if (this.idleTimer !== undefined) {
      clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
    }
    if (this.idleWarningTimer !== undefined) {
      clearTimeout(this.idleWarningTimer);
      this.idleWarningTimer = undefined;
    }
  }

  private invalidateSession(sidecar: InexSidecar): void {
    if (this.sidecar !== sidecar) {
      return;
    }
    this.sidecar = undefined;
    this.root = undefined;
    this.idleTimeoutMs = undefined;
    this.clearIdleDeadline();
    this.advanceGeneration();
    this.lockEmitter.fire();
    this.stateEmitter.fire();
    sidecar.dispose();
  }
}

export interface VaultSession {
  readonly root: vscode.Uri;
  readonly sidecar: InexSidecar;
  readonly generation: number;
}

async function validateVaultRoot(root: vscode.Uri): Promise<void> {
  if (root.scheme !== "file" || root.query.length !== 0 || root.fragment.length !== 0) {
    throw new SidecarLifecycleError("Inex v1 supports local file vaults only");
  }
  try {
    const metadata = await vscode.workspace.fs.stat(vscode.Uri.joinPath(root, "vault.json"));
    if (
      (metadata.type & vscode.FileType.File) === 0 ||
      (metadata.type & vscode.FileType.SymbolicLink) !== 0
    ) {
      throw new Error("not a regular file");
    }
  } catch {
    throw new SidecarLifecycleError("Selected folder does not contain a regular vault.json");
  }
}

function logicalPathRelativeToRoot(uri: vscode.Uri, root: vscode.Uri): string {
  if (uri.scheme !== "file" || uri.query.length !== 0 || uri.fragment.length !== 0) {
    throw new SidecarLifecycleError("Encrypted document is outside the unlocked vault");
  }
  const relative = path.relative(root.fsPath, uri.fsPath);
  if (relative.length === 0 || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new SidecarLifecycleError("Encrypted document is outside the unlocked vault");
  }
  const portable = relative.split(path.sep).join("/");
  if (!portable.endsWith(".md.enc")) {
    throw new SidecarLifecycleError("Encrypted document name is not canonical");
  }
  const logicalPath = portable.slice(0, -".enc".length);
  logicalFileComponents(logicalPath);
  return logicalPath;
}
