import assert from "node:assert/strict";
import { constants as fsConstants } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";

import * as vscode from "vscode";

const EXTENSION_ID = "horeb.inex-vscode";
const VIEW_TYPE = "inex.markdownEditor";
const LOGICAL_PATH = "canary.md";
const WAIT_TIMEOUT_MS = 20_000;

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
    readonly kind: "directory" | "file";
    readonly logicalPath: string;
  }[]>;
  readonly failNextMutationClose: () => void;
  readonly lock: () => Promise<void>;
}

interface FixtureEnvironment {
  readonly stage: "backup";
  readonly vaultPath: string;
  readonly sourcePath: string;
  readonly password: string;
  readonly sidecarPath: string;
  readonly userDataPath: string;
  readonly expectedSha256: string;
}

type CustomEditorTab = vscode.Tab & { readonly input: vscode.TabInputCustom };

export async function run(): Promise<void> {
  const fixture = fixtureEnvironment();
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
  await runCrudCycle(api, fixture);
  await api.openDocument(LOGICAL_PATH);
  const tab = await waitForCustomTab(fixture.vaultPath, LOGICAL_PATH);
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
    console.log("Inex Extension Host CRUD and backup/recovery cycles passed");
  } finally {
    await fs.rm(recoveryBackupPath, { force: true });
  }
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
  return {
    stage,
    vaultPath: requiredEnvironment("INEX_TEST_VAULT_PATH"),
    sourcePath: requiredEnvironment("INEX_TEST_SOURCE_PATH"),
    password: requiredEnvironment("INEX_TEST_PASSWORD"),
    sidecarPath: requiredEnvironment("INEX_TEST_INEXD_PATH"),
    userDataPath: requiredEnvironment("INEX_TEST_USER_DATA_PATH"),
    expectedSha256,
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
    "lock",
  ]) {
    assert.equal(typeof candidate[method], "function", `Integration-test API lacks ${method}`);
  }
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

function samePath(left: string, right: string): boolean {
  return path.resolve(left) === path.resolve(right);
}

function isWithin(parent: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== "..");
}
