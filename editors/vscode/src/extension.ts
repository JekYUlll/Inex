import * as vscode from "vscode";

import { VaultController } from "./controller.ts";
import { InexCrudActions } from "./crud.ts";
import { InexCustomEditorProvider } from "./customEditor.ts";
import { offerToOpenImportedVault } from "./importCompletion.ts";
import { RpcRemoteError } from "./rpc.ts";
import { importMarkdownRepository } from "./repositoryImport.ts";
import { choosePrivateAnnotation } from "./privateAnnotationPicker.ts";
import { showSensitiveInputBox, showSensitiveQuickPick } from "./sensitiveUi.ts";
import { InexTreeProvider } from "./tree.ts";

const VIEW_TYPE = "inex.markdownEditor";

let activeController: VaultController | undefined;
let activeEditorProvider: InexCustomEditorProvider | undefined;

export interface InexIntegrationTestApi {
  readonly unlock: (
    vaultPath: string,
    password: string,
    sidecarPath: string,
  ) => Promise<void>;
  readonly openDocument: (logicalPath: string) => Promise<void>;
  readonly waitUntilReady: (logicalPath: string) => Promise<void>;
  readonly markDirty: (logicalPath: string) => void;
  readonly waitForBackup: () => Promise<string>;
  readonly contentSha256: (logicalPath: string) => string;
  readonly recoverBackupAndSave: (
    logicalPath: string,
    backupPath: string,
  ) => Promise<string>;
  readonly createFolder: (logicalPath: string) => Promise<void>;
  readonly createEmptyDocument: (logicalPath: string) => Promise<void>;
  readonly renameDocument: (source: string, destination: string) => Promise<void>;
  readonly deleteDocument: (logicalPath: string) => Promise<void>;
  readonly listTree: () => Promise<readonly import("./sidecar.ts").TreeEntry[]>;
  readonly failNextMutationClose: () => void;
  readonly lock: () => Promise<void>;
}

export function activate(
  context: vscode.ExtensionContext,
): InexIntegrationTestApi | undefined {
  const integrationTestMode =
    context.extensionMode === vscode.ExtensionMode.Test &&
    process.env.INEX_VSCODE_INTEGRATION_TEST === "1";
  const controller = new VaultController(context);
  const tree = new InexTreeProvider(controller);
  const editor = new InexCustomEditorProvider(controller, integrationTestMode);
  const crud = new InexCrudActions(controller, tree, editor);
  activeController = controller;
  activeEditorProvider = editor;
  const syncVaultContext = () => {
    void vscode.commands.executeCommand("setContext", "inex.vaultUnlocked", controller.isUnlocked);
  };
  syncVaultContext();

  context.subscriptions.push(
    controller,
    tree,
    editor,
    controller.onDidChangeState(syncVaultContext),
    vscode.window.registerTreeDataProvider("inex.vault", tree),
    vscode.window.registerCustomEditorProvider(VIEW_TYPE, editor, {
      supportsMultipleEditorsPerDocument: false,
      webviewOptions: { retainContextWhenHidden: false },
    }),
    vscode.commands.registerCommand("inex.unlockVault", async () => {
      await runUiAction(async () => {
        if (controller.isUnlocked) {
          if (!(await editor.confirmLock())) {
            return;
          }
          await controller.lock();
        }
        const result = await controller.unlockInteractive();
        if (result === undefined) {
          return;
        }
        tree.refresh();
        if (result.warnings.length > 0) {
          await vscode.window.showWarningMessage(
            `Inex unlocked with ${result.warnings.length} KDF policy warning(s). Replace weak password slots from the CLI.`,
          );
        }
        await vscode.window.showInformationMessage("Inex vault unlocked in the local sidecar.");
      });
    }),
    vscode.commands.registerCommand("inex.lockVault", async () => {
      await runUiAction(async () => {
        if (!(await editor.confirmLock())) {
          return;
        }
        await controller.lock();
        tree.refresh();
        await vscode.window.showInformationMessage(
          "Inex vault locked, sidecar keys wiped, and owned editor buffers/webviews cleared on a best-effort basis.",
        );
      });
    }),
    vscode.commands.registerCommand("inex.importRepository", async (source?: unknown) => {
      await runUiAction(async () => {
        if (controller.isUnlocked) {
          await vscode.window.showInformationMessage(
            "Lock the current Inex vault before importing another repository.",
          );
          return;
        }
        const target = await importMarkdownRepository(
          context,
          source instanceof vscode.Uri ? source : undefined,
        );
        if (target === undefined) {
          return;
        }
        await offerToOpenImportedVault(target, {
          prompt: async (message, action) =>
            await vscode.window.showInformationMessage(message, action),
          openFolder: async (folder) => {
            await vscode.commands.executeCommand("vscode.openFolder", folder);
          },
        });
      });
    }),
    vscode.commands.registerCommand("inex.refreshTree", () => {
      tree.refresh();
    }),
    vscode.commands.registerCommand("inex.newEncryptedMarkdown", async (node?: unknown) => {
      await runUiAction(async () => {
        if (await ensureVaultUnlocked(controller)) {
          await crud.newEncryptedMarkdown(node);
        }
      });
    }),
    vscode.commands.registerCommand("inex.newFolder", async (node?: unknown) => {
      await runUiAction(async () => {
        if (await ensureVaultUnlocked(controller)) {
          await crud.newFolder(node);
        }
      });
    }),
    vscode.commands.registerCommand("inex.rename", async (node?: unknown) => {
      await runUiAction(async () => {
        if (await ensureVaultUnlocked(controller)) {
          await crud.rename(node);
        }
      });
    }),
    vscode.commands.registerCommand("inex.delete", async (node?: unknown) => {
      await runUiAction(async () => {
        if (await ensureVaultUnlocked(controller)) {
          await crud.delete(node);
        }
      });
    }),
    vscode.commands.registerCommand("inex.internal.openTreeEntry", async (node: unknown) => {
      await runUiAction(async () => {
        if (!isTreeNode(node)) {
          throw new Error("Inex tree entry is invalid");
        }
        await tree.openNode(node);
      });
    }),
    vscode.commands.registerCommand("inex.search", async () => {
      await runUiAction(async () => {
        if (!(await ensureVaultUnlocked(controller))) {
          return;
        }
        const session = controller.acquireSession();
        const query = await showSensitiveInputBox(
          {
            ignoreFocusOut: true,
            password: true,
            prompt: "Search query (hidden to avoid command/history persistence)",
            title: "Search Inex Vault",
            validateInput: (value) => {
              const bytes = Buffer.byteLength(value, "utf8");
              return bytes >= 1 && bytes <= 4096
                ? undefined
                : "Query must be 1–4096 UTF-8 bytes";
            },
          },
          controller.onDidLock,
        );
        if (query === undefined) {
          return;
        }
        if (!controller.isSessionCurrent(session)) {
          throw new Error("Inex vault session changed before search");
        }
        const hits = await session.sidecar.search(query);
        if (!controller.isSessionCurrent(session)) {
          throw new Error("Inex vault session changed during search");
        }
        const selected = await showSensitiveQuickPick(
          hits.map((hit) => ({
            label: hit.logicalPath,
            description: `${hit.line + 1}:${hit.utf16Column + 1}`,
            detail: hit.snippet,
            hit,
          })),
          { matchOnDescription: false, matchOnDetail: false, title: "Inex Search Results" },
          controller.onDidLock,
        );
        if (selected !== undefined) {
          if (!controller.isSessionCurrent(session)) {
            throw new Error("Inex vault session changed before opening the search result");
          }
          await vscode.commands.executeCommand(
            "vscode.openWith",
            controller.ciphertextUri(selected.hit.logicalPath),
            VIEW_TYPE,
          );
          if (!controller.isSessionCurrent(session)) {
            throw new Error("Inex vault session changed while opening the search result");
          }
          editor.reveal(
            selected.hit.logicalPath,
            selected.hit.startByte,
            selected.hit.endByte,
          );
        }
      });
    }),
    vscode.commands.registerCommand("inex.togglePrivateAnnotation", async () => {
      await runUiAction(async () => {
        if (editor.activeSelectionIsCompletePrivateBlock()) {
          const choice = await vscode.window.showWarningMessage(
            "Remove the selected private annotation? Its Markdown will become ordinary Umbra content after save.",
            { modal: true },
            "Remove Private Annotation",
          );
          if (choice === "Remove Private Annotation") {
            await editor.removePrivateAnnotationFromActive();
          }
          return;
        }
        await applyChosenPrivateAnnotation(controller, editor);
      });
    }),
    vscode.commands.registerCommand("inex.choosePrivateAnnotation", async () => {
      await runUiAction(async () => {
        await applyChosenPrivateAnnotation(controller, editor);
      });
    }),
    vscode.commands.registerCommand("inex.removePrivateAnnotation", async () => {
      await runUiAction(async () => {
        const choice = await vscode.window.showWarningMessage(
          "Remove the selected private annotation? Its Markdown will become ordinary Umbra content after save.",
          { modal: true },
          "Remove Private Annotation",
        );
        if (choice !== "Remove Private Annotation") return;
        await editor.removePrivateAnnotationFromActive();
      });
    }),
    vscode.commands.registerCommand("inex.applyPrivateAnnotationProfile", async (args?: unknown) => {
      await runUiAction(async () => {
        const profileId = isProfileArguments(args) ? args.profileId : undefined;
        if (profileId === undefined) {
          throw new Error("Private annotation profile ID is required");
        }
        await applyChosenPrivateAnnotation(controller, editor, profileId);
      });
    }),
    vscode.commands.registerCommand("inex.showSecurityStatus", async () => {
      const sidecar = controller.isUnlocked ? "unlocked in memory" : "locked";
      await vscode.window.showInformationMessage(
        `Inex is ${sidecar}. Backups are encrypted EDRY drafts and no plaintext TextDocument provider is registered. JavaScript/Webview zeroization is best effort; isolated-profile residue audit remains a release gate.`,
      );
    }),
  );

  if (!integrationTestMode) {
    return undefined;
  }
  return Object.freeze({
    unlock: async (vaultPath: string, password: string, sidecarPath: string) => {
      await controller.unlockForIntegrationTest(vaultPath, password, sidecarPath);
    },
    openDocument: async (logicalPath: string) => {
      await vscode.commands.executeCommand(
        "vscode.openWith",
        controller.ciphertextUri(logicalPath),
        VIEW_TYPE,
        { preview: false },
      );
      await editor.waitForIntegrationDocument(logicalPath);
    },
    waitUntilReady: (logicalPath: string) =>
      editor.waitForIntegrationDocument(logicalPath),
    markDirty: (logicalPath: string) => {
      editor.markIntegrationDocumentDirty(logicalPath);
    },
    waitForBackup: () => editor.waitForIntegrationBackup(),
    contentSha256: (logicalPath: string) => editor.integrationContentSha256(logicalPath),
    recoverBackupAndSave: (logicalPath: string, backupPath: string) =>
      editor.recoverIntegrationBackupAndSave(logicalPath, backupPath),
    createFolder: (logicalPath: string) => crud.createDirectory(logicalPath),
    createEmptyDocument: (logicalPath: string) =>
      crud.createEmptyMarkdown(logicalPath),
    renameDocument: (source: string, destination: string) =>
      crud.renameFile(source, destination),
    deleteDocument: (logicalPath: string) => crud.deleteFile(logicalPath),
    listTree: () => crud.listTree(),
    failNextMutationClose: () => editor.failNextMutationCloseForIntegrationTest(),
    lock: () => controller.lock(),
  });
}

export async function deactivate(): Promise<void> {
  activeEditorProvider?.wipeAllForLock();
  const controller = activeController;
  activeController = undefined;
  activeEditorProvider = undefined;
  if (controller !== undefined) {
    await controller.lock().catch(() => undefined);
  }
}

function isTreeNode(value: unknown): value is import("./tree.ts").InexTreeNode {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const candidate = value as {
    readonly entry?: { readonly kind?: unknown; readonly logicalPath?: unknown };
    readonly session?: unknown;
  };
  return (
    candidate.session !== undefined &&
    (candidate.entry?.kind === "file" ||
      candidate.entry?.kind === "directory" ||
      candidate.entry?.kind === "asset") &&
    typeof candidate.entry.logicalPath === "string"
  );
}

async function ensureVaultUnlocked(controller: VaultController): Promise<boolean> {
  if (controller.isUnlocked) {
    return true;
  }
  const choice = await vscode.window.showInformationMessage(
    "Unlock an Inex vault, or import an existing Markdown Git repository into a new encrypted vault.",
    "Unlock Vault",
    "Initialize from Markdown Repository",
  );
  if (choice === "Unlock Vault") {
    return (await controller.unlockInteractive()) !== undefined;
  }
  if (choice === "Initialize from Markdown Repository") {
    await vscode.commands.executeCommand("inex.importRepository");
  }
  return false;
}

async function applyChosenPrivateAnnotation(
  controller: VaultController,
  editor: InexCustomEditorProvider,
  profileId?: string,
): Promise<void> {
  if (!(await ensureVaultUnlocked(controller))) {
    return;
  }
  const session = controller.acquireSession();
  const sidecar = session.sidecar;
  const status = await sidecar.umbraStatus();
  if (!controller.isSessionCurrent(session)) {
    throw new Error("Inex vault session changed before Umbra unlock");
  }
  if (!status.unlocked) {
    if (!status.initialized) {
      const warning = await vscode.window.showWarningMessage(
        "Umbra passwords cannot be recovered. Forgetting it permanently loses Umbra private content. Continue?",
        { modal: true },
        "Initialize Umbra",
      );
      if (warning !== "Initialize Umbra") return;
    }
    let password = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        password: true,
        prompt: status.initialized ? "Umbra password" : "New Umbra password",
        title: status.initialized ? "Unlock Umbra" : "Initialize Umbra",
        validateInput: (value) => {
          const bytes = Buffer.byteLength(value, "utf8");
          return bytes >= 1 && bytes <= 1024 ? undefined : "Password must be 1–1024 UTF-8 bytes";
        },
      },
      controller.onDidLock,
    );
    if (password === undefined) return;
    try {
      if (status.initialized) {
        await sidecar.unlockUmbra(password);
      } else {
        await sidecar.initializeUmbra(password);
      }
      await sidecar.enableUmbra();
    } finally {
      password = undefined;
    }
  }
  if (!controller.isSessionCurrent(session)) {
    throw new Error("Inex vault session changed during Umbra unlock");
  }
  await editor.convertActiveDocumentToUmbra();
  const config = await sidecar.loadUmbraAnnotationConfig();
  const profile = profileId === undefined
    ? undefined
    : config.profiles.find((candidate) => candidate.id === profileId);
  if (profileId !== undefined && profile === undefined) {
    throw new Error("Private annotation profile is unavailable");
  }
  let coverText: string | undefined;
  if (profile?.promptForCover === true) {
    coverText = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        prompt: "Public cover text (visible in Outer Mode)",
        title: "Inex Outer Cover",
        validateInput: (value) => Buffer.byteLength(value, "utf8") > 0 ? undefined : "Cover text is required",
      },
      controller.onDidLock,
    );
    if (coverText === undefined) return;
  }
  const spec = profile === undefined
    ? await choosePrivateAnnotation(config, controller.onDidLock)
    : {
      kind: profile.kind,
      tagIds: profile.tagIds,
      outer: { mode: profile.outer, ...(coverText === undefined ? {} : { coverText }) },
    };
  if (spec === undefined) return;
  if (!controller.isSessionCurrent(session)) {
    throw new Error("Inex vault session changed during private annotation selection");
  }
  await editor.applyPrivateAnnotationToActive(spec);
}

function isProfileArguments(value: unknown): value is { readonly profileId: string } {
  return value !== null && typeof value === "object" &&
    typeof (value as { readonly profileId?: unknown }).profileId === "string" &&
    /^[a-z0-9][a-z0-9._-]{0,63}$/.test((value as { readonly profileId: string }).profileId);
}

async function runUiAction(action: () => Promise<void>): Promise<void> {
  try {
    await action();
  } catch (error: unknown) {
    const message =
      error instanceof RpcRemoteError || error instanceof Error
        ? error.message
        : "Inex operation failed";
    await vscode.window.showErrorMessage(message);
  }
}
