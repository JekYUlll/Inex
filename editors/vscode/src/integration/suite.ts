import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { promisify } from "node:util";

import * as vscode from "vscode";

const EXTENSION_ID = "horeb.inex-vscode";
const VIEW_TYPE = "inex.markdownEditor";
const LOGICAL_PATH = "canary.md";
const SECONDARY_LOGICAL_PATH = "plain.md";
const ASSET_LOGICAL_PATH = "images/pixel.png";
const EXPECTED_ASSET_CHUNK_BYTES = 1024 * 1024;
const MAX_TRACE_BYTES = 1024 * 1024;
const WAIT_TIMEOUT_MS = 20_000;
const execFileAsync = promisify(execFile);

interface InexIntegrationTestApi {
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
  readonly listTree: () => Promise<readonly {
    readonly kind: "directory" | "file" | "asset";
    readonly logicalPath: string;
  }[]>;
  readonly failNextMutationClose: () => void;
  readonly exportOuterCopy: (destination: string) => Promise<void>;
  readonly exportUmbraCopy: (destination: string) => Promise<void>;
  readonly verifyUmbraAnnotationLifecycle: (logicalPath: string, password: string) => Promise<void>;
  readonly verifyUmbraPasswordChange: (oldPassword: string, newPassword: string) => Promise<void>;
  readonly verifyUmbraLock: (password: string) => Promise<void>;
  readonly verifyOuterRevisionCompare: () => Promise<void>;
  readonly verifyOuterRevisionCompareFromScm: (logicalPath: string) => Promise<void>;
  readonly verifyUmbraRevisionCompare: () => Promise<void>;
  readonly verifyOuterProjection: () => Promise<void>;
  readonly verifyOuterProjectionFromTree: (logicalPath: string) => Promise<void>;
  readonly verifyRedactToOuter: (password: string) => Promise<void>;
  readonly createCrossEditorUmbraTag: () => Promise<void>;
  readonly createCrossEditorUmbraAnnotation: (logicalPath: string) => Promise<void>;
  readonly lock: () => Promise<void>;
}

interface FixtureEnvironment {
  readonly stage: "backup";
  readonly vaultPath: string;
  readonly sourcePath: string;
  readonly password: string;
  readonly sidecarPath: string;
  readonly sidecarTracePath: string;
  readonly userDataPath: string;
  readonly expectedSha256: string;
  readonly originalSha256: string;
  readonly repositoryRoot: string;
}

interface SidecarTraceEntry {
  readonly pid: number;
  readonly sequence: number;
  readonly method: string;
  readonly logicalPath?: string;
  readonly offset?: number;
  readonly maxBytes?: number;
}

interface AssetTraceCycle {
  readonly pid: number;
  readonly openSequence: number;
  readonly closeSequence: number;
}

type CustomEditorTab = vscode.Tab & { readonly input: vscode.TabInputCustom };

export async function run(): Promise<void> {
  const fixture = fixtureEnvironment();
  assert.equal(
    vscode.workspace.workspaceFolders?.length,
    1,
    "Feature-1 acceptance host did not open one ciphertext vault workspace",
  );
  assert.equal(
    samePath(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? "", fixture.vaultPath),
    true,
    "Feature-1 acceptance host remained on the plaintext source workspace",
  );
  const extension = vscode.extensions.getExtension<InexIntegrationTestApi>(EXTENSION_ID);
  assert.ok(extension, `Extension ${EXTENSION_ID} is unavailable`);
  const api = await extension.activate();
  assertIntegrationApi(api);
  const registeredCommands = new Set(await vscode.commands.getCommands(true));
  for (const command of [
    "inex.newEncryptedMarkdown",
    "inex.newFolder",
    "inex.rename",
    "inex.delete",
    "inex.importRepository",
    "inex.redactToOuter",
  ]) {
    assert.equal(registeredCommands.has(command), true, `Extension did not register ${command}`);
  }

  await runBackupRecoveryCycle(api, fixture);
}

async function runBackupRecoveryCycle(
  api: InexIntegrationTestApi,
  fixture: FixtureEnvironment,
): Promise<void> {
  await api.unlock(fixture.vaultPath, fixture.password, fixture.sidecarPath);
  await runPlaintextExportCycle(api, fixture);
  await runFeatureOneAssetLifecycle(api, fixture);
  await api.unlock(fixture.vaultPath, fixture.password, fixture.sidecarPath);
  await api.openDocument(SECONDARY_LOGICAL_PATH);
  await api.verifyUmbraAnnotationLifecycle(SECONDARY_LOGICAL_PATH, fixture.password);
  await api.verifyOuterProjection();
  await waitForSidecarTrace(
    fixture,
    (entries) => entries.some((entry) => entry.method === "umbra.document.openOuter"),
    "VS Code active-editor Outer projection did not reach the authenticated sidecar",
  );
  await execFileAsync("git", ["-C", fixture.vaultPath, "add", "plain.md.enc"]);
  await execFileAsync("git", [
    "-C", fixture.vaultPath,
    "-c", "user.email=inex-vscode-integration@example.invalid",
    "-c", "user.name=Inex VS Code Integration",
    "-c", "commit.gpgSign=false",
    "commit", "-q", "-m", "encrypted Umbra revision compare fixture",
  ]);
  await api.verifyUmbraRevisionCompare();
  await waitForSidecarTrace(
    fixture,
    (entries) => entries.some((entry) => entry.method === "revision.compare.umbra"),
    "VS Code Umbra revision compare did not reach the authenticated sidecar",
  );
  await api.verifyRedactToOuter(fixture.password);
  await waitForSidecarTrace(
    fixture,
    (entries) => {
      const lock = entries.find((entry) => entry.method === "umbra.lock");
      return lock !== undefined && entries.some(
        (entry) => entry.method === "umbra.document.openOuter" && entry.sequence > lock.sequence,
      );
    },
    "VS Code quick redaction did not lock Umbra before opening the Outer projection",
  );
  await runUmbraPlaintextExportCycle(api, fixture);
  await api.createCrossEditorUmbraTag();
  await api.createCrossEditorUmbraAnnotation(SECONDARY_LOGICAL_PATH);
  const replacementUmbraPassword = "Inex integration replacement Umbra password";
  await api.verifyUmbraPasswordChange(fixture.password, replacementUmbraPassword);
  await api.verifyUmbraLock(replacementUmbraPassword);
  await api.verifyOuterProjectionFromTree(SECONDARY_LOGICAL_PATH);
  await waitForSidecarTrace(
    fixture,
    (entries) => entries.filter((entry) => entry.method === "umbra.document.openOuter").length >= 2,
    "VS Code Outer-only tree projection did not reach the authenticated sidecar",
  );
  await verifySublimeCatalogRead(
    fixture,
    replacementUmbraPassword,
  );
  const umbraTrace = await waitForSidecarTrace(
    fixture,
    (entries) => entries.some((entry) => entry.method === "umbra.document.convert")
      && entries.filter((entry) => entry.method === "umbra.annotation.apply").length >= 3
      && entries.some((entry) => entry.method === "umbra.annotation.edit")
      && entries.filter((entry) => entry.method === "umbra.annotation.remove").length >= 2
      && entries.some((entry) => entry.method === "umbra.tag.create")
      && entries.some((entry) => entry.method === "umbra.password.change")
      && entries.some((entry) => entry.method === "umbra.lock"),
    "VS Code Umbra annotation lifecycle did not reach the authenticated sidecar",
  );
  const first = (method: string) => umbraTrace.find((entry) => entry.method === method);
  const all = (method: string) => umbraTrace.filter((entry) => entry.method === method);
  const orderedEntries = [
    first("umbra.document.convert"),
    all("umbra.annotation.apply")[0],
    first("umbra.annotation.edit"),
    all("umbra.annotation.remove")[0],
    all("umbra.annotation.apply")[1],
    all("umbra.annotation.remove")[1],
    first("umbra.tag.create"),
    all("umbra.annotation.apply")[2],
    first("umbra.password.change"),
    first("umbra.lock"),
  ];
  let previousUmbraSequence = -1;
  for (const entry of orderedEntries) {
    assert.ok(entry, "VS Code Umbra trace omitted an expected authenticated RPC");
    assert.equal(
      entry.sequence > previousUmbraSequence,
      true,
      `VS Code Umbra sidecar order is invalid at ${entry.method}`,
    );
    previousUmbraSequence = entry.sequence;
  }
  await runCrudCycle(api, fixture);
  await api.openDocument(LOGICAL_PATH);
  const tab = await waitForCustomTab(fixture.vaultPath, LOGICAL_PATH);
  assertNoPlaintextTextDocument(tab.input.uri, fixture.sourcePath);
  await api.verifyOuterRevisionCompare();
  await api.verifyOuterRevisionCompareFromScm(LOGICAL_PATH);
  await waitForSidecarTrace(
    fixture,
    (entries) => entries.filter((entry) => entry.method === "revision.compare.outer").length >= 2,
    "VS Code active-editor and Source Control Outer revision compares did not reach the authenticated sidecar",
  );
  assertNoPlaintextTextDocument(tab.input.uri, fixture.sourcePath);

  api.markDirty(LOGICAL_PATH);
  await waitFor(() => tab.isDirty, "Inex custom-editor tab did not become dirty");
  assert.equal(
    api.contentSha256(LOGICAL_PATH),
    fixture.expectedSha256,
    "The dirty editor content did not match the outer runner's expected digest",
  );

  const backupPath = await api.waitForBackup();
  await assertEncryptedBackup(backupPath, fixture.userDataPath);
  assertNoPlaintextTextDocument(tab.input.uri, fixture.sourcePath);
  assert.equal(
    vscode.workspace.getConfiguration("files").get("hotExit"),
    "onExitAndWindowClose",
    "The isolated profile did not enable the required Hot Exit mode",
  );
  const recoveryBackupPath = path.join(
    fixture.userDataPath,
    "inex-integration-recovery.edry",
  );
  await fs.copyFile(backupPath, recoveryBackupPath, fsConstants.COPYFILE_EXCL);
  await fs.chmod(recoveryBackupPath, 0o600);
  await assertEncryptedBackup(recoveryBackupPath, fixture.userDataPath);
  try {
    // Clean the workbench-owned document before locking so test shutdown cannot
    // request another backup from a deliberately locked document. The copied
    // EDRY envelope remains the recovery input for the exact backupId path.
    await vscode.commands.executeCommand("workbench.action.files.revert");
    await waitFor(() => !tab.isDirty, "Inex custom-editor tab did not become clean after revert");
    await api.lock();
    await api.unlock(fixture.vaultPath, fixture.password, fixture.sidecarPath);
    assert.equal(
      await api.recoverBackupAndSave(LOGICAL_PATH, recoveryBackupPath),
      fixture.expectedSha256,
      "The provider backupId recovery path did not restore the unsaved EDRY draft",
    );
    await api.lock();
    assertNoPlaintextTextDocument(tab.input.uri, fixture.sourcePath);
    console.log(
      "Inex Extension Host feature-1 asset, CRUD, and backup/recovery cycles passed",
    );
  } finally {
    await fs.rm(recoveryBackupPath, { force: true });
  }
}

async function runPlaintextExportCycle(
  api: InexIntegrationTestApi,
  fixture: FixtureEnvironment,
): Promise<void> {
  const destination = path.join(path.dirname(fixture.vaultPath), "authorized-plaintext-export");
  await assert.rejects(fs.lstat(destination), "plaintext export destination unexpectedly exists");
  try {
    await api.exportOuterCopy(destination);
    const markdown = await fs.readFile(path.join(destination, LOGICAL_PATH));
    assert.equal(
      createHash("sha256").update(markdown).digest("hex"),
      fixture.originalSha256,
      "Outer plaintext export did not reproduce the authenticated Markdown projection",
    );
    markdown.fill(0);
    const asset = await fs.readFile(path.join(destination, ASSET_LOGICAL_PATH));
    try {
      assert.equal(asset.subarray(0, 8).toString("hex"), "89504e470d0a1a0a");
    } finally {
      asset.fill(0);
    }
    await assert.rejects(
      fs.lstat(path.join(destination, `${LOGICAL_PATH}.enc`)),
      "plaintext export incorrectly retained an encrypted Markdown name",
    );
    assertNoPlaintextTextDocument(vscode.Uri.file(path.join(destination, LOGICAL_PATH)), fixture.sourcePath);
    const trace = await waitForSidecarTrace(
      fixture,
      (entries) => entries.some((entry) => entry.method === "vault.export.prepare")
        && entries.some((entry) => entry.method === "vault.export.commit"),
      "VS Code outer plaintext export did not issue the prepare/commit RPC transaction",
    );
    const prepare = trace.find((entry) => entry.method === "vault.export.prepare");
    const commit = trace.find((entry) => entry.method === "vault.export.commit");
    assert.ok(prepare);
    assert.ok(commit);
    assert.equal(
      commit.sequence > prepare.sequence,
      true,
      "VS Code plaintext export committed before prepare",
    );
  } finally {
    await fs.rm(destination, { recursive: true, force: true });
  }
  await assert.rejects(fs.lstat(destination), "test plaintext export was retained for the residue scan");
}

async function runUmbraPlaintextExportCycle(
  api: InexIntegrationTestApi,
  fixture: FixtureEnvironment,
): Promise<void> {
  const destination = path.join(path.dirname(fixture.vaultPath), "authorized-umbra-plaintext-export");
  await assert.rejects(fs.lstat(destination), "Umbra plaintext export destination unexpectedly exists");
  try {
    await api.exportUmbraCopy(destination);
    const markdown = await fs.readFile(path.join(destination, SECONDARY_LOGICAL_PATH), "utf8");
    assert.match(markdown, /:::inex-private\n/u, "Umbra export did not include the private annotation block");
    assert.match(markdown, /kind: comment\n/u, "Umbra export did not include private annotation metadata");
    assert.match(markdown, /---\n#\n:::/u, "Umbra export did not retain private Markdown content");
    const trace = await waitForSidecarTrace(
      fixture,
      (entries) => entries.some((entry) => entry.method === "vault.export.prepare")
        && entries.some((entry) => entry.method === "vault.export.commit"),
      "VS Code Umbra plaintext export did not issue the prepare/commit transaction",
    );
    const commits = trace.filter((entry) => entry.method === "vault.export.commit");
    assert.equal(commits.length >= 2, true, "VS Code did not commit both Outer and Umbra export transactions");
  } finally {
    await fs.rm(destination, { recursive: true, force: true });
  }
  await assert.rejects(fs.lstat(destination), "test Umbra plaintext export was retained for the residue scan");
}

async function runFeatureOneAssetLifecycle(
  api: InexIntegrationTestApi,
  fixture: FixtureEnvironment,
): Promise<void> {
  const importedEntries = await api.listTree();
  for (const expected of [
    { kind: "file", logicalPath: LOGICAL_PATH },
    { kind: "file", logicalPath: SECONDARY_LOGICAL_PATH },
    { kind: "asset", logicalPath: ASSET_LOGICAL_PATH },
  ] as const) {
    assert.deepEqual(
      importedEntries.find((entry) => entry.logicalPath === expected.logicalPath),
      expected,
      `Imported feature-1 tree omitted ${expected.logicalPath}`,
    );
  }

  await api.openDocument(LOGICAL_PATH);
  const assetTab = await waitForCustomTab(fixture.vaultPath, LOGICAL_PATH);
  await waitFor(
    () => assetTab.isActive,
    "The imported Markdown image fixture did not become the active custom editor",
  );
  assertNoPlaintextTextDocument(assetTab.input.uri, fixture.sourcePath);
  await waitForAssetCycles(fixture, 1);

  await api.openDocument(SECONDARY_LOGICAL_PATH);
  const secondaryTab = await waitForCustomTab(
    fixture.vaultPath,
    SECONDARY_LOGICAL_PATH,
  );
  await waitFor(
    () => secondaryTab.isActive && !assetTab.isActive,
    "Opening a second encrypted note did not hide the image-bearing editor",
  );
  assertNoPlaintextTextDocument(secondaryTab.input.uri, fixture.sourcePath);
  await new Promise((resolve) => setTimeout(resolve, 350));
  const hiddenEntries = await readSidecarTrace(fixture);
  const hiddenCycles = completedAssetCycles(hiddenEntries);
  assert.equal(
    hiddenCycles.length > 0,
    true,
    "The first relative-image preview did not complete before the editor was hidden",
  );
  assert.equal(
    countAssetOperations(hiddenEntries, "asset.open"),
    countAssetOperations(hiddenEntries, "asset.close"),
    "Hiding the image-bearing editor left an observed asset handle open",
  );

  await api.openDocument(LOGICAL_PATH);
  await waitFor(
    () => assetTab.isActive && !secondaryTab.isActive,
    "Reopening the imported Markdown note did not reveal its custom editor",
  );
  const resumedCycles = await waitForAssetCycles(fixture, hiddenCycles.length + 1);
  const resumedCycle = resumedCycles.at(-1);
  assert.ok(resumedCycle, "The revealed editor did not restart its relative-image preview");
  assert.equal(
    await vscode.window.tabGroups.close([assetTab, secondaryTab], true),
    true,
    "VS Code did not close the feature-1 preview fixtures",
  );
  await waitForNoCustomTab(fixture.vaultPath, LOGICAL_PATH);
  await waitForNoCustomTab(fixture.vaultPath, SECONDARY_LOGICAL_PATH);
  await assertCleanCiphertextGitWorktree(
    fixture.vaultPath,
    "opening and hiding the CRLF CustomEditor fixture",
  );

  await api.lock();
  const lockedEntries = await waitForSidecarTrace(
    fixture,
    (entries) => {
      const lock = entries.find(
        (entry) =>
          entry.pid === resumedCycle.pid &&
          entry.method === "vault.lock" &&
          entry.sequence > resumedCycle.closeSequence,
      );
      return (
        lock !== undefined &&
        entries.some(
          (entry) =>
            entry.pid === resumedCycle.pid &&
            entry.method === "system.shutdown" &&
            entry.sequence > lock.sequence,
        )
      );
    },
    "Locking the feature-1 vault did not lock and shut down the real sidecar",
  );
  const lock = lockedEntries.find(
    (entry) =>
      entry.pid === resumedCycle.pid &&
      entry.method === "vault.lock" &&
      entry.sequence > resumedCycle.closeSequence,
  );
  assert.ok(lock);
  assert.equal(
    lockedEntries.some(
      (entry) =>
        entry.pid === resumedCycle.pid &&
        entry.method.startsWith("asset.") &&
        entry.sequence > lock.sequence,
    ),
    false,
    "The preview lifecycle issued an asset RPC after vault.lock",
  );
  assertNoPlaintextTextDocument(assetTab.input.uri, fixture.sourcePath);
}

async function assertCleanCiphertextGitWorktree(
  vaultPath: string,
  context: string,
): Promise<void> {
  const { stdout, stderr } = await execFileAsync(
    "git",
    ["-C", vaultPath, "status", "--porcelain=v1", "-z"],
    { encoding: "utf8", maxBuffer: 1024 * 1024 },
  );
  assert.equal(stderr, "", `git status emitted stderr while ${context}`);
  assert.equal(stdout, "", `CustomEditor changed ciphertext without an edit while ${context}`);
}

async function runCrudCycle(
  api: InexIntegrationTestApi,
  fixture: FixtureEnvironment,
): Promise<void> {
  const source = "crud/new.md";
  const destination = "crud/renamed.md";
  const collision = "crud/existing.md";
  await api.createFolder("crud");
  await api.createEmptyDocument(source);
  const sourceTab = await waitForCustomTab(fixture.vaultPath, source);
  assertNoPlaintextTextDocument(sourceTab.input.uri, fixture.sourcePath);
  await assert.rejects(fs.lstat(path.join(fixture.vaultPath, "crud", "new.md")));
  const sourceCiphertext = await fs.lstat(
    path.join(fixture.vaultPath, "crud", "new.md.enc"),
  );
  assert.equal(sourceCiphertext.isFile(), true, "CRUD create did not write ciphertext");
  assert.equal(sourceCiphertext.isSymbolicLink(), false, "CRUD create wrote a symlink");
  assert.deepEqual(
    (await api.listTree()).filter((entry) => entry.logicalPath.startsWith("crud")),
    [
      { kind: "directory", logicalPath: "crud" },
      { kind: "file", logicalPath: source },
    ],
    "CRUD create did not refresh the authenticated tree",
  );

  api.failNextMutationClose();
  await assert.rejects(
    api.renameDocument(source, "crud/never-created.md"),
    "simulated tab-close refusal unexpectedly allowed rename",
  );
  await api.waitUntilReady(source);
  await waitForCustomTab(fixture.vaultPath, source);
  assert.equal(
    (await api.listTree()).some(
      (entry) => entry.logicalPath === "crud/never-created.md",
    ),
    false,
    "failed preparation reached the rename RPC",
  );

  await api.createEmptyDocument(collision);
  const collisionTab = await waitForCustomTab(fixture.vaultPath, collision);
  assert.equal(
    await vscode.window.tabGroups.close(collisionTab, true),
    true,
    "VS Code did not close the collision fixture",
  );
  await waitForNoCustomTab(fixture.vaultPath, collision);
  await assert.rejects(
    api.renameDocument(source, collision),
    "etag-conditional rename unexpectedly replaced an existing destination",
  );
  const recoveredSourceTab = await waitForCustomTab(fixture.vaultPath, source);
  assertNoPlaintextTextDocument(recoveredSourceTab.input.uri, fixture.sourcePath);
  assert.deepEqual(
    (await api.listTree()).filter((entry) => entry.logicalPath.startsWith("crud")),
    [
      { kind: "directory", logicalPath: "crud" },
      { kind: "file", logicalPath: collision },
      { kind: "file", logicalPath: source },
    ],
    "failed rename did not preserve the authenticated source and destination",
  );
  await api.openDocument(collision);
  await waitForCustomTab(fixture.vaultPath, collision);
  const crudDirectory = path.join(fixture.vaultPath, "crud");
  if (process.platform !== "win32" && process.getuid?.() !== 0) {
    await fs.chmod(crudDirectory, 0o500);
    try {
      await assert.rejects(
        api.deleteDocument(collision),
        "conditional delete unexpectedly succeeded without parent write permission",
      );
      const recoveredCollisionTab = await waitForCustomTab(
        fixture.vaultPath,
        collision,
      );
      assertNoPlaintextTextDocument(
        recoveredCollisionTab.input.uri,
        fixture.sourcePath,
      );
    } finally {
      await fs.chmod(crudDirectory, 0o700);
    }
  }
  await api.deleteDocument(collision);

  await api.renameDocument(source, destination);
  await waitForNoCustomTab(fixture.vaultPath, source);
  const destinationTab = await waitForCustomTab(fixture.vaultPath, destination);
  assertNoPlaintextTextDocument(destinationTab.input.uri, fixture.sourcePath);
  assert.deepEqual(
    (await api.listTree()).filter((entry) => entry.logicalPath.startsWith("crud")),
    [
      { kind: "directory", logicalPath: "crud" },
      { kind: "file", logicalPath: destination },
    ],
    "CRUD rename left a stale logical tree entry",
  );

  await api.deleteDocument(destination);
  await waitForNoCustomTab(fixture.vaultPath, destination);
  assert.deepEqual(
    (await api.listTree()).filter((entry) => entry.logicalPath.startsWith("crud")),
    [{ kind: "directory", logicalPath: "crud" }],
    "CRUD delete left a stale logical tree entry",
  );
  await assert.rejects(
    fs.lstat(path.join(fixture.vaultPath, "crud", "renamed.md.enc")),
  );
}

async function waitForCustomTab(
  vaultPath: string,
  logicalPath: string,
): Promise<CustomEditorTab> {
  let found: vscode.Tab | undefined;
  await waitFor(() => {
    found = vscode.window.tabGroups.all
      .flatMap((group) => group.tabs)
      .find((tab) => {
        if (!(tab.input instanceof vscode.TabInputCustom)) {
          return false;
        }
        return (
          tab.input.viewType === VIEW_TYPE &&
          samePath(tab.input.uri.fsPath, path.join(vaultPath, `${logicalPath}.enc`))
        );
      });
    return found !== undefined;
  }, "VS Code did not expose the opened Inex custom-editor tab");
  assert.ok(found);
  assert.ok(found.input instanceof vscode.TabInputCustom);
  assert.equal(found.input.uri.scheme, "file");
  assert.equal(found.input.viewType, VIEW_TYPE);
  return found as CustomEditorTab;
}

async function waitForNoCustomTab(vaultPath: string, logicalPath: string): Promise<void> {
  await waitFor(
    () =>
      !vscode.window.tabGroups.all.flatMap((group) => group.tabs).some(
        (tab) =>
          tab.input instanceof vscode.TabInputCustom &&
          tab.input.viewType === VIEW_TYPE &&
          samePath(tab.input.uri.fsPath, path.join(vaultPath, `${logicalPath}.enc`)),
      ),
    `VS Code retained a stale custom-editor tab for ${logicalPath}`,
  );
}

function assertNoPlaintextTextDocument(
  ciphertextUri: vscode.Uri,
  sourcePath: string,
): void {
  for (const document of vscode.workspace.textDocuments) {
    assert.notEqual(
      document.uri.toString(),
      ciphertextUri.toString(),
      "Ciphertext was exposed as a VS Code TextDocument",
    );
    assert.notEqual(
      document.uri.scheme,
      "inex",
      "A plaintext Inex virtual TextDocument was registered",
    );
    if (document.uri.scheme === "file") {
      assert.equal(
        isWithin(sourcePath, document.uri.fsPath),
        false,
        "Deleted plaintext source was exposed as a VS Code TextDocument",
      );
    }
  }
}

async function assertEncryptedBackup(
  backupPath: string,
  userDataPath: string,
): Promise<void> {
  const pathMetadata = await fs.lstat(backupPath);
  assert.equal(pathMetadata.isFile(), true, "Encrypted custom-editor backup is not a regular file");
  assert.equal(pathMetadata.isSymbolicLink(), false, "Encrypted custom-editor backup is a symlink");
  const backup = await fs.realpath(backupPath);
  const userData = await fs.realpath(userDataPath);
  assert.equal(
    isWithin(userData, backup),
    true,
    "Encrypted custom-editor backup escaped the isolated VS Code user-data directory",
  );
  const handle = await fs.open(backup, "r");
  try {
    const magic = Buffer.alloc(4);
    const { bytesRead } = await handle.read(magic, 0, magic.length, 0);
    assert.equal(bytesRead, magic.length, "Encrypted custom-editor backup is truncated");
    assert.equal(magic.toString("ascii"), "EDRY", "Custom-editor backup is not EDRY ciphertext");
  } finally {
    await handle.close();
  }
}

function fixtureEnvironment(): FixtureEnvironment {
  const stage = requiredEnvironment("INEX_TEST_STAGE");
  assert.equal(stage, "backup", "Invalid INEX_TEST_STAGE");
  const expectedSha256 = requiredEnvironment("INEX_TEST_EXPECTED_SHA256");
  assert.match(expectedSha256, /^[0-9a-f]{64}$/u, "Invalid expected content digest");
  const originalSha256 = requiredEnvironment("INEX_TEST_ORIGINAL_SHA256");
  assert.match(originalSha256, /^[0-9a-f]{64}$/u, "Invalid original content digest");
  return {
    stage,
    vaultPath: requiredEnvironment("INEX_TEST_VAULT_PATH"),
    sourcePath: requiredEnvironment("INEX_TEST_SOURCE_PATH"),
    password: requiredEnvironment("INEX_TEST_PASSWORD"),
    sidecarPath: requiredEnvironment("INEX_TEST_INEXD_PATH"),
    sidecarTracePath: requiredEnvironment("INEX_TEST_SIDECAR_TRACE_PATH"),
    userDataPath: requiredEnvironment("INEX_TEST_USER_DATA_PATH"),
    expectedSha256,
    originalSha256,
    repositoryRoot: requiredEnvironment("INEX_TEST_REPOSITORY_ROOT"),
  };
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  assert.ok(value !== undefined && value.length > 0, `${name} is required`);
  return value;
}

function assertIntegrationApi(value: unknown): asserts value is InexIntegrationTestApi {
  assert.ok(value !== null && typeof value === "object", "Integration-test API is unavailable");
  const candidate = value as Record<string, unknown>;
  for (const method of [
    "unlock",
    "openDocument",
    "waitUntilReady",
    "markDirty",
    "waitForBackup",
    "contentSha256",
    "recoverBackupAndSave",
    "createFolder",
    "createEmptyDocument",
    "renameDocument",
    "deleteDocument",
    "listTree",
    "failNextMutationClose",
    "exportOuterCopy",
    "exportUmbraCopy",
    "verifyUmbraAnnotationLifecycle",
    "verifyUmbraLock",
    "verifyOuterRevisionCompare",
    "verifyOuterRevisionCompareFromScm",
    "verifyUmbraRevisionCompare",
    "verifyOuterProjection",
    "verifyOuterProjectionFromTree",
    "createCrossEditorUmbraTag",
    "createCrossEditorUmbraAnnotation",
    "lock",
  ]) {
    assert.equal(typeof candidate[method], "function", `Integration-test API lacks ${method}`);
  }
}

async function verifySublimeCatalogRead(
  fixture: FixtureEnvironment,
  password: string,
): Promise<void> {
  const script = path.join(fixture.repositoryRoot, "editors", "sublime", "tests", "cross_editor_catalog.py");
  const output = await runPasswordStdinChild(
    "python3",
    [script, fixture.sidecarPath, fixture.vaultPath],
    password,
  );
  assert.equal(output.code, 0, "Sublime client could not read the VS Code-written Umbra catalog");
  assert.equal(output.stdout, "sublime-cross-editor-catalog-ok\n", "Sublime cross-editor catalog result is invalid");
  assert.equal(output.stderr, "", "Sublime cross-editor catalog emitted stderr");
}

async function runPasswordStdinChild(
  executable: string,
  childArguments: readonly string[],
  password: string,
): Promise<{ readonly code: number | null; readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, childArguments, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
      windowsHide: true,
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk: Buffer) => stderr.push(Buffer.from(chunk)));
    child.once("error", reject);
    child.once("close", (code) => {
      const result = {
        code,
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
      };
      for (const buffer of stdout) buffer.fill(0);
      for (const buffer of stderr) buffer.fill(0);
      resolve(result);
    });
    child.stdin.end(`${password}\n`);
    password = "";
  });
}

async function waitFor(predicate: () => boolean, message: string): Promise<void> {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (predicate()) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(message);
}

async function waitForAssetCycles(
  fixture: FixtureEnvironment,
  minimumCycles: number,
): Promise<readonly AssetTraceCycle[]> {
  const entries = await waitForSidecarTrace(
    fixture,
    (candidate) => completedAssetCycles(candidate).length >= minimumCycles,
    `Relative-image preview did not complete ${minimumCycles} real sidecar lifecycle(s)`,
  );
  return completedAssetCycles(entries);
}

async function waitForSidecarTrace(
  fixture: FixtureEnvironment,
  predicate: (entries: readonly SidecarTraceEntry[]) => boolean,
  message: string,
): Promise<readonly SidecarTraceEntry[]> {
  const deadline = Date.now() + WAIT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const entries = await readSidecarTrace(fixture);
    if (predicate(entries)) {
      return entries;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(message);
}

async function readSidecarTrace(
  fixture: FixtureEnvironment,
): Promise<readonly SidecarTraceEntry[]> {
  let metadata;
  try {
    metadata = await fs.lstat(fixture.sidecarTracePath);
  } catch (error: unknown) {
    if (isNodeError(error) && error.code === "ENOENT") {
      return [];
    }
    throw error;
  }
  assert.equal(metadata.isFile(), true, "Sidecar observation trace is not a regular file");
  assert.equal(metadata.isSymbolicLink(), false, "Sidecar observation trace is a symlink");
  assert.equal(metadata.size <= MAX_TRACE_BYTES, true, "Sidecar observation trace is oversized");
  const raw = await fs.readFile(fixture.sidecarTracePath, "utf8");
  assert.equal(
    raw.includes(fixture.password),
    false,
    "Sidecar observation trace exposed the integration password",
  );
  const finalNewline = raw.lastIndexOf("\n");
  if (finalNewline < 0) {
    return [];
  }
  const entries = raw
    .slice(0, finalNewline)
    .split("\n")
    .filter((line) => line.length > 0)
    .map((line) => parseSidecarTraceEntry(line));
  const lastSequenceByPid = new Map<number, number>();
  for (const entry of entries) {
    const previous = lastSequenceByPid.get(entry.pid) ?? 0;
    assert.equal(
      entry.sequence > previous,
      true,
      "Sidecar observation sequence is not strictly increasing",
    );
    lastSequenceByPid.set(entry.pid, entry.sequence);
  }
  return entries;
}

function parseSidecarTraceEntry(line: string): SidecarTraceEntry {
  const value: unknown = JSON.parse(line);
  assert.ok(value !== null && typeof value === "object", "Invalid sidecar trace record");
  const record = value as Record<string, unknown>;
  assert.equal(Number.isSafeInteger(record.pid), true, "Invalid sidecar trace PID");
  assert.equal(typeof record.pid === "number" && record.pid > 0, true);
  assert.equal(Number.isSafeInteger(record.sequence), true, "Invalid sidecar trace sequence");
  assert.equal(typeof record.sequence === "number" && record.sequence > 0, true);
  assert.equal(typeof record.method, "string", "Invalid sidecar trace method");
  assert.match(record.method as string, /^[A-Za-z][A-Za-z0-9.]{0,63}$/u);
  const allowed = new Set(["pid", "sequence", "method"]);
  if (record.method === "asset.open") {
    allowed.add("logicalPath");
    assert.equal(typeof record.logicalPath, "string", "Asset-open trace omitted its path");
  } else if (record.method === "asset.readChunk") {
    allowed.add("offset");
    allowed.add("maxBytes");
    assert.equal(Number.isSafeInteger(record.offset), true, "Invalid asset trace offset");
    assert.equal(Number.isSafeInteger(record.maxBytes), true, "Invalid asset trace chunk bound");
  }
  assert.deepEqual(
    Object.keys(record).sort(),
    [...allowed].sort(),
    "Sidecar trace recorded fields outside the safe observation schema",
  );
  return record as unknown as SidecarTraceEntry;
}

function completedAssetCycles(
  entries: readonly SidecarTraceEntry[],
): readonly AssetTraceCycle[] {
  const cycles: AssetTraceCycle[] = [];
  for (let index = 0; index < entries.length; index += 1) {
    const opened = entries[index];
    if (opened?.method !== "asset.open" || opened.logicalPath !== ASSET_LOGICAL_PATH) {
      continue;
    }
    const reads: SidecarTraceEntry[] = [];
    for (let cursor = index + 1; cursor < entries.length; cursor += 1) {
      const entry = entries[cursor];
      if (entry === undefined || entry.pid !== opened.pid) {
        continue;
      }
      if (entry.method === "asset.open") {
        break;
      }
      if (entry.method === "asset.readChunk") {
        reads.push(entry);
      }
      if (entry.method === "asset.close") {
        assert.equal(reads.length, 1, "Small PNG preview did not use one bounded asset read");
        assert.equal(reads[0]?.offset, 0, "Small PNG preview did not start at offset zero");
        assert.equal(
          reads[0]?.maxBytes,
          EXPECTED_ASSET_CHUNK_BYTES,
          "Small PNG preview did not use the sidecar chunk ceiling",
        );
        cycles.push({
          pid: opened.pid,
          openSequence: opened.sequence,
          closeSequence: entry.sequence,
        });
        break;
      }
    }
  }
  return cycles;
}

function countAssetOperations(
  entries: readonly SidecarTraceEntry[],
  method: "asset.open" | "asset.close",
): number {
  return entries.filter((entry) => entry.method === method).length;
}

function isNodeError(error: unknown): error is NodeJS.ErrnoException {
  return error instanceof Error && "code" in error;
}

function samePath(left: string, right: string): boolean {
  return path.resolve(left) === path.resolve(right);
}

function isWithin(parent: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
}
