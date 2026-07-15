import * as vscode from "vscode";
import * as path from "node:path";

import { VaultController, type VaultSession } from "./controller.ts";
import { InexCrudActions } from "./crud.ts";
import { InexCustomEditorProvider } from "./customEditor.ts";
import { offerToOpenImportedVault } from "./importCompletion.ts";
import { RpcRemoteError } from "./rpc.ts";
import { importMarkdownRepository } from "./repositoryImport.ts";
import {
  chooseAnnotationProfileDraft,
  choosePrivateAnnotation,
} from "./privateAnnotationPicker.ts";
import {
  parsePrivateAnnotationPreferences,
  resolveToggleAnnotationAction,
  type PrivateAnnotationPreferences,
} from "./privateAnnotationPreferences.ts";
import { validatePlaintextExportDirectoryName } from "./plaintextExport.ts";
import type { PrivateAnnotationSpec, UmbraAnnotationProfile } from "./sidecar.ts";
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
  readonly exportOuterCopy: (destination: string) => Promise<void>;
  readonly verifyUmbraAnnotationLifecycle: (logicalPath: string, password: string) => Promise<void>;
  readonly verifyUmbraLock: (password: string) => Promise<void>;
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
  // Tags/profile semantics are private catalog data. Keep only a best-effort
  // session-local copy for shortcut behavior; never write it to VS Code settings.
  let lastAnnotationSpec: PrivateAnnotationSpec | undefined;
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
    controller.onDidLock(() => {
      lastAnnotationSpec = undefined;
    }),
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
    vscode.commands.registerCommand("inex.lockUmbra", async () => {
      await runUiAction(async () => {
        const locked = await lockUmbra(controller, editor);
        if (locked) {
          await vscode.window.showInformationMessage("Umbra locked; private projections and related preview state were cleared.");
        }
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
    vscode.commands.registerCommand("inex.exportPlaintextCopy", async () => {
      await runUiAction(async () => {
        if (!(await ensureVaultUnlocked(controller))) return;
        const parent = await vscode.window.showOpenDialog({
          canSelectFiles: false, canSelectFolders: true, canSelectMany: false,
          title: "Choose parent folder for plaintext export",
          openLabel: "Choose export parent",
        });
        if (parent === undefined || parent.length !== 1 || parent[0]?.scheme !== "file") return;
        const name = await vscode.window.showInputBox({
          title: "Plaintext export destination", prompt: "New folder name (must not already exist)",
          ignoreFocusOut: true, validateInput: validatePlaintextExportDirectoryName,
        });
        if (name === undefined) return;
        const invalidName = validatePlaintextExportDirectoryName(name);
        if (invalidName !== undefined) {
          throw new Error(`Inex plaintext export destination is invalid: ${invalidName}`);
        }
        const scope = await vscode.window.showQuickPick([
          { label: "Outer only", value: "outer" as const, description: "Excludes private Umbra content" },
          { label: "Include Umbra private content", value: "umbra" as const, description: "Requires Umbra password" },
        ], { title: "Plaintext export scope", ignoreFocusOut: true });
        if (scope === undefined) return;
        if (scope.value === "umbra" && (await ensureUmbraReady(controller)) === undefined) return;
        const session = controller.acquireSession();
        if (!controller.isSessionCurrent(session)) throw new Error("Inex vault session changed before export");
        const prepared = await session.sidecar.preparePlaintextExport(path.join(parent[0].fsPath, name), scope.value);
        const action = "Export plaintext copy";
        const confirmed = await vscode.window.showWarningMessage(
          `This creates ${prepared.files} Markdown file(s), ${prepared.assets} asset(s), and ${prepared.directories} folder(s) outside Inex protection. Git, backups, indexing, history, and deletion residue may retain plaintext.`,
          { modal: true, detail: "Inex cannot securely erase the exported copy." }, action,
        );
        if (confirmed !== action) return;
        if (!controller.isSessionCurrent(session)) throw new Error("Inex vault session changed during export confirmation");
        await session.sidecar.commitPlaintextExport(prepared);
        await vscode.window.showInformationMessage("Inex plaintext export completed.");
      });
    }),
    vscode.commands.registerCommand("inex.togglePrivateAnnotation", async () => {
      await runUiAction(async () => {
        const preferences = privateAnnotationPreferences();
        if (editor.activeSelectionIsCompletePrivateBlock()) {
          if (await confirmPrivateAnnotationRemoval(preferences)) {
            await editor.removePrivateAnnotationFromActive();
          }
          return;
        }
        const applied = await applyTogglePrivateAnnotation(
          controller,
          editor,
          preferences,
          lastAnnotationSpec,
        );
        if (applied !== undefined && preferences.rememberLastSelection) {
          lastAnnotationSpec = applied;
        }
      });
    }),
    vscode.commands.registerCommand("inex.choosePrivateAnnotation", async () => {
      await runUiAction(async () => {
        const preferences = privateAnnotationPreferences();
        const applied = await applyChosenPrivateAnnotation(controller, editor, undefined, preferences);
        if (applied !== undefined && preferences.rememberLastSelection) {
          lastAnnotationSpec = applied;
        }
      });
    }),
    vscode.commands.registerCommand("inex.removePrivateAnnotation", async () => {
      await runUiAction(async () => {
        if (!(await confirmPrivateAnnotationRemoval(privateAnnotationPreferences()))) return;
        await editor.removePrivateAnnotationFromActive();
      });
    }),
    vscode.commands.registerCommand("inex.editPrivateAnnotation", async () => {
      await runUiAction(async () => {
        const initialSpec = editor.activePrivateAnnotationSpec();
        const preferences = privateAnnotationPreferences();
        const applied = await applyChosenPrivateAnnotation(
          controller,
          editor,
          undefined,
          preferences,
          initialSpec,
        );
        if (applied !== undefined && preferences.rememberLastSelection) {
          lastAnnotationSpec = applied;
        }
      });
    }),
    vscode.commands.registerCommand("inex.managePrivateTags", async () => {
      await runUiAction(async () => {
        await managePrivateTags(controller);
      });
    }),
    vscode.commands.registerCommand("inex.reorderPrivateTags", async () => {
      await runUiAction(async () => {
        await reorderPrivateTags(controller);
      });
    }),
    vscode.commands.registerCommand("inex.managePrivateAnnotationProfiles", async () => {
      await runUiAction(async () => {
        await managePrivateAnnotationProfiles(controller);
      });
    }),
    vscode.commands.registerCommand("inex.applyPrivateAnnotationProfile", async (args?: unknown) => {
      await runUiAction(async () => {
        const profileId = isProfileArguments(args) ? args.profileId : undefined;
        if (profileId === undefined) {
          throw new Error("Private annotation profile ID is required");
        }
        const preferences = privateAnnotationPreferences();
        const applied = await applyChosenPrivateAnnotation(controller, editor, profileId, preferences);
        if (applied !== undefined && preferences.rememberLastSelection) {
          lastAnnotationSpec = applied;
        }
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
    exportOuterCopy: async (destination: string) => {
      const session = controller.acquireSession();
      const prepared = await session.sidecar.preparePlaintextExport(destination, "outer");
      if (!controller.isSessionCurrent(session)) {
        throw new Error("Inex vault session changed during integration plaintext export");
      }
      await session.sidecar.commitPlaintextExport(prepared);
      if (!controller.isSessionCurrent(session)) {
        throw new Error("Inex vault session changed after integration plaintext export");
      }
    },
    verifyUmbraAnnotationLifecycle: async (logicalPath: string, password: string) => {
      const session = controller.acquireSession();
      let status = await session.sidecar.umbraStatus();
      if (!status.initialized) {
        status = await session.sidecar.initializeUmbra(password);
      }
      if (!status.unlocked) {
        await session.sidecar.unlockUmbra(password);
      }
      await session.sidecar.enableUmbra();
      await editor.verifyIntegrationUmbraAnnotationLifecycle(logicalPath);
    },
    verifyUmbraLock: async (password: string) => {
      const session = controller.acquireSession();
      let status = await session.sidecar.umbraStatus();
      if (!status.initialized) {
        status = await session.sidecar.initializeUmbra(password);
      }
      if (!status.unlocked) {
        status = await session.sidecar.unlockUmbra(password);
      }
      await session.sidecar.enableUmbra();
      if (!(await lockUmbra(controller, editor))) {
        throw new Error("Inex integration Umbra lock unexpectedly found no unlocked Umbra session");
      }
      if ((await session.sidecar.umbraStatus()).unlocked) {
        throw new Error("Inex integration Umbra lock retained K_umbra in the sidecar");
      }
    },
    lock: () => controller.lock(),
  });
}

async function lockUmbra(
  controller: VaultController,
  editor: InexCustomEditorProvider,
): Promise<boolean> {
  if (!controller.isUnlocked) {
    await vscode.window.showInformationMessage("Unlock the Inex vault before locking Umbra.");
    return false;
  }
  const session = controller.acquireSession();
  try {
    const status = await session.sidecar.umbraStatus();
    if (!status.unlocked) {
      await vscode.window.showInformationMessage("Umbra is already locked.");
      return false;
    }
    await session.sidecar.lockUmbra();
    return true;
  } finally {
    // A transport failure leaves remote lock state unknown. Never retain an
    // Umbra projection locally in that case.
    editor.wipeUmbraForLock();
  }
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
  preferences: PrivateAnnotationPreferences = privateAnnotationPreferences(),
  initialSpec?: PrivateAnnotationSpec,
  selectedSpec?: PrivateAnnotationSpec,
): Promise<PrivateAnnotationSpec | undefined> {
  const ready = await ensureUmbraReady(controller);
  if (ready === undefined) return undefined;
  const { session, sidecar } = ready;
  await editor.convertActiveDocumentToUmbra();
  const config = await sidecar.loadUmbraAnnotationConfig();
  const profile = profileId === undefined
    ? undefined
    : config.profiles.find((candidate) => candidate.id === profileId);
  if (profileId !== undefined && profile === undefined) {
    throw new Error("Private annotation profile is unavailable");
  }
  let coverText: string | undefined;
  // A Cover outer strategy is structurally invalid without public cover text.
  // Prompt regardless of a malformed/legacy profile's promptForCover flag so
  // profile application cannot construct a request that the daemon must reject.
  if (profile?.outer === "cover") {
    coverText = await showSensitiveInputBox(
      {
        ignoreFocusOut: true,
        prompt: "Public cover text (visible in Outer Mode)",
        title: "Inex Outer Cover",
        validateInput: (value) => Buffer.byteLength(value, "utf8") > 0 ? undefined : "Cover text is required",
      },
      controller.onDidLock,
    );
    if (coverText === undefined) return undefined;
  }
  const spec = selectedSpec ?? (profile === undefined
    ? await choosePrivateAnnotation(config, controller.onDidLock, initialSpec)
    : {
      kind: profile.kind,
      tagIds: profile.tagIds,
      outer: { mode: profile.outer, ...(coverText === undefined ? {} : { coverText }) },
    });
  if (spec === undefined) return undefined;
  if (!controller.isSessionCurrent(session)) {
    throw new Error("Inex vault session changed during private annotation selection");
  }
  if (initialSpec === undefined) {
    await editor.applyPrivateAnnotationToActive(spec, preferences.noSelectionTarget);
  } else {
    await editor.editPrivateAnnotationAtActive(spec);
  }
  return spec;
}

async function applyTogglePrivateAnnotation(
  controller: VaultController,
  editor: InexCustomEditorProvider,
  preferences: PrivateAnnotationPreferences,
  lastAnnotationSpec: PrivateAnnotationSpec | undefined,
): Promise<PrivateAnnotationSpec | undefined> {
  const actionWithoutDefault = resolveToggleAnnotationAction(
    preferences,
    lastAnnotationSpec !== undefined,
    false,
  );
  if (actionWithoutDefault === "last" && lastAnnotationSpec !== undefined) {
    return await applyChosenPrivateAnnotation(
      controller,
      editor,
      undefined,
      preferences,
      undefined,
      lastAnnotationSpec,
    );
  }
  if (preferences.toggleBehavior === "useDefaultProfile") {
    const ready = await ensureUmbraReady(controller);
    if (ready === undefined) return undefined;
    const config = await ready.sidecar.loadUmbraAnnotationConfig();
    const profileId = config.defaults.defaultProfileId;
    if (
      resolveToggleAnnotationAction(
        preferences,
        false,
        profileId !== "" && config.profiles.some((profile) => profile.id === profileId),
      ) === "defaultProfile"
    ) {
      return await applyChosenPrivateAnnotation(controller, editor, profileId, preferences);
    }
  }
  return await applyChosenPrivateAnnotation(controller, editor, undefined, preferences);
}

async function ensureUmbraReady(
  controller: VaultController,
): Promise<{ readonly session: VaultSession; readonly sidecar: VaultSession["sidecar"] } | undefined> {
  if (!(await ensureVaultUnlocked(controller))) return undefined;
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
      if (warning !== "Initialize Umbra") return undefined;
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
    if (password === undefined) return undefined;
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
  return { session, sidecar };
}

async function managePrivateTags(controller: VaultController): Promise<void> {
  const ready = await ensureUmbraReady(controller);
  if (ready === undefined) return;
  const config = await ready.sidecar.loadUmbraAnnotationConfig();
  const items: vscode.QuickPickItem[] = [
    { label: "$(add) Create Private Tag", description: "Add an encrypted catalog entry" },
    ...config.tags.map((tag) => ({
      label: `$(tag) ${tag.label}`,
      description: tag.id,
      detail: tag.archived ? "Archived" : tag.description,
    })),
  ];
  const selected = await showSensitiveQuickPick(
    items,
    { title: "Manage Private Tags", placeHolder: "Create a tag or select one to rename/archive" },
    controller.onDidLock,
  );
  if (selected === undefined || !controller.isSessionCurrent(ready.session)) return;
  if (selected.label.startsWith("$(add)")) {
    await createPrivateTag(controller, ready.session, ready.sidecar);
    return;
  }
  const tag = config.tags.find((candidate) => candidate.id === selected.description);
  if (tag === undefined) throw new Error("Selected private tag is unavailable");
  const action = await vscode.window.showQuickPick(
    tag.archived ? ["Rename"] : ["Rename", "Archive"],
    { title: "Manage selected private tag", ignoreFocusOut: true },
  );
  if (action === undefined || !controller.isSessionCurrent(ready.session)) return;
  if (action === "Archive") {
    await ready.sidecar.archiveUmbraTag(tag.id);
    await ready.sidecar.loadUmbraAnnotationConfig();
    await vscode.window.showInformationMessage("Private tag archived.");
    return;
  }
  let label = await showSensitiveInputBox(
    {
      title: "Rename Private Tag",
      prompt: "Private display label",
      value: tag.label,
      ignoreFocusOut: true,
      validateInput: validatePrivateTagText,
    },
    controller.onDidLock,
  );
  if (label === undefined) return;
  try {
    await ready.sidecar.renameUmbraTag(tag.id, label);
    await ready.sidecar.loadUmbraAnnotationConfig();
    await vscode.window.showInformationMessage("Private tag renamed.");
  } finally {
    label = undefined;
  }
}

async function reorderPrivateTags(controller: VaultController): Promise<void> {
  const ready = await ensureUmbraReady(controller);
  if (ready === undefined) return;
  const config = await ready.sidecar.loadUmbraAnnotationConfig();
  if (config.tags.length < 2) {
    await vscode.window.showInformationMessage("Create at least two private tags before reordering.");
    return;
  }
  const selected = await showSensitiveQuickPick(
    config.tags.map((tag) => ({ label: `$(tag) ${tag.label}`, description: tag.id })),
    { title: "Reorder Private Tags", placeHolder: "Choose a private tag to move" },
    controller.onDidLock,
  );
  if (selected === undefined || !controller.isSessionCurrent(ready.session)) return;
  const index = config.tags.findIndex((tag) => tag.id === selected.description);
  if (index < 0) throw new Error("Selected private tag is unavailable");
  const positions = [
    { label: "Move to first", index: 0 },
    { label: "Move earlier", index: Math.max(0, index - 1) },
    { label: "Move later", index: Math.min(config.tags.length - 1, index + 1) },
    { label: "Move to last", index: config.tags.length - 1 },
  ].filter((option, optionIndex, all) =>
    option.index !== index && all.findIndex((candidate) => candidate.index === option.index) === optionIndex,
  );
  const position = await vscode.window.showQuickPick(positions, {
    title: "Move selected private tag",
    ignoreFocusOut: true,
  });
  if (position === undefined || !controller.isSessionCurrent(ready.session)) return;
  const ids = config.tags.map((tag) => tag.id);
  const [moved] = ids.splice(index, 1);
  if (moved === undefined) throw new Error("Selected private tag is unavailable");
  ids.splice(position.index, 0, moved);
  await ready.sidecar.reorderUmbraTags(ids);
  await ready.sidecar.loadUmbraAnnotationConfig();
  await vscode.window.showInformationMessage("Private tags reordered.");
}

async function createPrivateTag(
  controller: VaultController,
  session: VaultSession,
  sidecar: VaultSession["sidecar"],
): Promise<void> {
  let label = await showSensitiveInputBox(
    { title: "Create Private Tag", prompt: "Private display label", ignoreFocusOut: true, validateInput: validatePrivateTagText },
    controller.onDidLock,
  );
  let id: string | undefined;
  try {
    if (label === undefined || !controller.isSessionCurrent(session)) return;
    id = await showSensitiveInputBox(
      { title: "Create Private Tag", prompt: "Stable machine-readable ID", ignoreFocusOut: true, validateInput: validatePrivateTagId },
      controller.onDidLock,
    );
    if (id === undefined || !controller.isSessionCurrent(session)) return;
    await sidecar.createUmbraTag({
      id,
      label,
      description: "",
      aliases: [],
      sortOrder: 0,
      defaultSelected: false,
    });
    await sidecar.loadUmbraAnnotationConfig();
    await vscode.window.showInformationMessage("Private tag created.");
  } finally {
    id = undefined;
    label = undefined;
  }
}

async function managePrivateAnnotationProfiles(controller: VaultController): Promise<void> {
  const ready = await ensureUmbraReady(controller);
  if (ready === undefined) return;
  const config = await ready.sidecar.loadUmbraAnnotationConfig();
  const selected = await showSensitiveQuickPick(
    [
      { label: "$(add) Create Private Annotation Profile", description: "Add an encrypted reusable annotation" },
      ...config.profiles.map((profile) => ({
        label: `$(symbol-method) ${profile.label}`,
        description: profile.id,
        detail: `${profile.kind} / ${profile.outer}${config.defaults.defaultProfileId === profile.id ? " / Default" : ""}`,
      })),
    ],
    { title: "Manage Private Annotation Profiles", placeHolder: "Create a profile or select one to edit/remove" },
    controller.onDidLock,
  );
  if (selected === undefined || !controller.isSessionCurrent(ready.session)) return;
  if (selected.label.startsWith("$(add)")) {
    await createPrivateAnnotationProfile(controller, ready.session, ready.sidecar, config);
    return;
  }
  const profile = config.profiles.find((candidate) => candidate.id === selected.description);
  if (profile === undefined) throw new Error("Selected private annotation profile is unavailable");
  const action = await vscode.window.showQuickPick(
    config.defaults.defaultProfileId === profile.id
      ? ["Edit", "Clear Default", "Remove"]
      : ["Edit", "Set as Default", "Remove"],
    {
    title: "Manage selected private annotation profile",
    ignoreFocusOut: true,
    },
  );
  if (action === undefined || !controller.isSessionCurrent(ready.session)) return;
  if (action === "Set as Default" || action === "Clear Default") {
    await ready.sidecar.setUmbraDefaultAnnotationProfile(action === "Set as Default" ? profile.id : "");
    await ready.sidecar.loadUmbraAnnotationConfig();
    await vscode.window.showInformationMessage(
      action === "Set as Default"
        ? "Private annotation default profile set."
        : "Private annotation default profile cleared.",
    );
    return;
  }
  if (action === "Remove") {
    const confirmed = await vscode.window.showWarningMessage(
      "Remove this private annotation profile? Existing private annotations are unchanged.",
      { modal: true },
      "Remove Profile",
    );
    if (confirmed !== "Remove Profile" || !controller.isSessionCurrent(ready.session)) return;
    await ready.sidecar.removeUmbraAnnotationProfile(profile.id);
    await ready.sidecar.loadUmbraAnnotationConfig();
    await vscode.window.showInformationMessage("Private annotation profile removed.");
    return;
  }
  await editPrivateAnnotationProfile(controller, ready.session, ready.sidecar, config, profile);
}

async function createPrivateAnnotationProfile(
  controller: VaultController,
  session: VaultSession,
  sidecar: VaultSession["sidecar"],
  config: import("./sidecar.ts").UmbraAnnotationConfig,
): Promise<void> {
  let label = await showSensitiveInputBox(
    { title: "Create Private Annotation Profile", prompt: "Private profile label", ignoreFocusOut: true, validateInput: validatePrivateTagText },
    controller.onDidLock,
  );
  let id: string | undefined;
  try {
    if (label === undefined || !controller.isSessionCurrent(session)) return;
    id = await showSensitiveInputBox(
      { title: "Create Private Annotation Profile", prompt: "Stable machine-readable ID", ignoreFocusOut: true, validateInput: validatePrivateTagId },
      controller.onDidLock,
    );
    if (id === undefined || !controller.isSessionCurrent(session)) return;
    const draft = await chooseAnnotationProfileDraft(config, controller.onDidLock);
    if (draft === undefined || !controller.isSessionCurrent(session)) return;
    await sidecar.createUmbraAnnotationProfile(profileFromDraft(id, label, draft));
    await sidecar.loadUmbraAnnotationConfig();
    await vscode.window.showInformationMessage("Private annotation profile created.");
  } finally {
    id = undefined;
    label = undefined;
  }
}

async function editPrivateAnnotationProfile(
  controller: VaultController,
  session: VaultSession,
  sidecar: VaultSession["sidecar"],
  config: import("./sidecar.ts").UmbraAnnotationConfig,
  profile: UmbraAnnotationProfile,
): Promise<void> {
  let label = await showSensitiveInputBox(
    { title: "Edit Private Annotation Profile", prompt: "Private profile label", value: profile.label, ignoreFocusOut: true, validateInput: validatePrivateTagText },
    controller.onDidLock,
  );
  try {
    if (label === undefined || !controller.isSessionCurrent(session)) return;
    const draft = await chooseAnnotationProfileDraft(config, controller.onDidLock, profile);
    if (draft === undefined || !controller.isSessionCurrent(session)) return;
    await sidecar.editUmbraAnnotationProfile(profile.id, profileFromDraft(profile.id, label, draft));
    await sidecar.loadUmbraAnnotationConfig();
    await vscode.window.showInformationMessage("Private annotation profile updated.");
  } finally {
    label = undefined;
  }
}

function profileFromDraft(
  id: string,
  label: string,
  draft: import("./privateAnnotationPicker.ts").AnnotationProfileDraft,
): UmbraAnnotationProfile {
  return {
    id,
    label,
    kind: draft.kind,
    tagIds: draft.tagIds,
    outer: draft.outer,
    promptForCover: draft.outer === "cover",
  };
}

function validatePrivateTagText(value: string): string | undefined {
  const bytes = Buffer.byteLength(value, "utf8");
  return bytes >= 1 && bytes <= 4096 ? undefined : "Text must be 1–4096 UTF-8 bytes";
}

function validatePrivateTagId(value: string): string | undefined {
  return /^[a-z0-9][a-z0-9._-]{0,63}$/.test(value)
    ? undefined
    : "ID must match [a-z0-9][a-z0-9._-]{0,63}";
}

function privateAnnotationPreferences(): PrivateAnnotationPreferences {
  const configuration = vscode.workspace.getConfiguration("inex.privateAnnotation");
  return parsePrivateAnnotationPreferences({
    noSelectionTarget: configuration.get<unknown>("noSelectionTarget"),
    confirmBeforeUnwrap: configuration.get<unknown>("confirmBeforeUnwrap"),
    toggleBehavior: configuration.get<unknown>("toggleBehavior"),
    rememberLastSelection: configuration.get<unknown>("rememberLastSelection"),
  });
}

async function confirmPrivateAnnotationRemoval(
  preferences: PrivateAnnotationPreferences,
): Promise<boolean> {
  if (!preferences.confirmBeforeUnwrap) return true;
  const choice = await vscode.window.showWarningMessage(
    "Remove the selected private annotation? Its Markdown will become ordinary Umbra content after save.",
    { modal: true },
    "Remove Private Annotation",
  );
  return choice === "Remove Private Annotation";
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
