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

  await runBackupRecoveryCycle(api, fixture);
}

async function runBackupRecoveryCycle(
  api: InexIntegrationTestApi,
  fixture: FixtureEnvironment,
): Promise<void> {
  await api.unlock(fixture.vaultPath, fixture.password, fixture.sidecarPath);
  await api.openDocument(LOGICAL_PATH);
  const tab = await waitForCustomTab(fixture.vaultPath);
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
    console.log("Inex Extension Host backup/recovery cycle passed");
  } finally {
    await fs.rm(recoveryBackupPath, { force: true });
  }
}

async function waitForCustomTab(
  vaultPath: string,
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
          samePath(tab.input.uri.fsPath, path.join(vaultPath, `${LOGICAL_PATH}.enc`))
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
