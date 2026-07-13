import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Writable } from "node:stream";
import { fileURLToPath } from "node:url";
import { deflateSync } from "node:zlib";

import { runTests } from "@vscode/test-electron";

import {
  ResidueStreamDetector,
  residueSignatures,
  scanResidueRoots,
} from "./residueScanner.mjs";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const EXTENSION_ROOT = path.resolve(SCRIPT_DIRECTORY, "..");
const REPOSITORY_ROOT = path.resolve(EXTENSION_ROOT, "../..");
const EXTENSION_TESTS_PATH = path.join(EXTENSION_ROOT, "dist/test/suite/index.js");
const SIDECAR_TRACE_PROXY_SOURCE = path.join(SCRIPT_DIRECTORY, "sidecarTraceProxy.mjs");
const LOGICAL_PATH = "canary.md";
const SECONDARY_LOGICAL_PATH = "plain.md";
const ASSET_LOGICAL_PATH = "images/pixel.png";
const DIRTY_SUFFIX = "\n<!-- inex integration dirty -->\n";
const TEST_PASSWORD = "Inex-extension-residue-audit-2026";
const MAX_CAPTURE_BYTES = 256 * 1024;

class BoundedCapture extends Writable {
  #chunks = [];
  #bytes = 0;

  constructor(signatures) {
    super();
    this.detector = new ResidueStreamDetector(signatures);
  }

  _write(chunk, _encoding, callback) {
    const bytes = Buffer.from(chunk);
    this.detector.push(bytes);
    this.#chunks.push(bytes);
    this.#bytes += bytes.length;
    while (this.#bytes > MAX_CAPTURE_BYTES && this.#chunks.length > 1) {
      const removed = this.#chunks.shift();
      this.#bytes -= removed.length;
    }
    if (this.#bytes > MAX_CAPTURE_BYTES && this.#chunks.length === 1) {
      const only = this.#chunks[0];
      this.#chunks[0] = Buffer.from(only.subarray(only.length - MAX_CAPTURE_BYTES));
      this.#bytes = this.#chunks[0].length;
    }
    callback();
  }

  text() {
    return Buffer.concat(this.#chunks).toString("utf8");
  }

  get residueHit() {
    return this.detector.hit;
  }
}

const options = parseOptions(process.argv.slice(2));
const auditRoot = await fs.mkdtemp(path.join(os.tmpdir(), "inex-vscode-audit-"));
await fs.chmod(auditRoot, 0o700);

const fixture = fixturePaths(auditRoot);
const canary = `inex-residue:${randomBytes(96).toString("base64url")}`;
const originalPlaintext = `# Inex residue audit\n\n${canary}\n\n![Encrypted pixel](${ASSET_LOGICAL_PATH})\n`;
const secondaryPlaintext = `# Secondary encrypted note\n\n${canary}:secondary\n`;
const dirtyPlaintext = `${originalPlaintext}${DIRTY_SUFFIX}`;
const expectedSha256 = createHash("sha256").update(dirtyPlaintext, "utf8").digest("hex");
const signatures = residueSignatures(canary, [
  originalPlaintext,
  secondaryPlaintext,
  dirtyPlaintext,
]);
const redactions = signatures
  .map(({ bytes }) => bytes)
  .filter((bytes) => !bytes.includes(0))
  .map((bytes) => bytes.toString("utf8"));
let testFailure;
let residueHits = [];

try {
  await prepareFixture(
    fixture,
    originalPlaintext,
    secondaryPlaintext,
    buildCanaryPng(canary),
    signatures,
    redactions,
  );
  await importVault(fixture, options.inexPath, signatures, redactions);
  await removePlaintextSource(fixture.sourcePath);
  await runStage("backup", fixture, expectedSha256, options, signatures, redactions);
} catch (error) {
  testFailure = error;
} finally {
  await killRemainingIsolatedCodeProcesses(fixture.userDataPath).catch((error) => {
    testFailure ??= error;
  });
  await removePlaintextSource(fixture.sourcePath).catch(() => undefined);
  try {
    residueHits = await scanResidueRoots(residueRoots(auditRoot), signatures);
  } catch (error) {
    testFailure ??= error;
  }
}

if (residueHits.length > 0) {
  for (const hit of residueHits) {
    console.error(`residue hit: ${redact(hit.path, redactions)} [${hit.encoding}]`);
  }
  testFailure ??= new Error("Plaintext residue audit failed");
}

if (testFailure === undefined) {
  await fs.rm(auditRoot, { recursive: true, force: true });
  console.log(
    "Inex VS Code feature-1 import, asset preview, CRUD, backup/recovery, and residue audit passed",
  );
} else {
  console.error(`Inex VS Code integration audit retained at: ${auditRoot}`);
  console.error(safeError(testFailure, redactions));
  process.exitCode = 1;
}

async function prepareFixture(
  paths,
  plaintext,
  secondaryPlaintext,
  assetBytes,
  signatures,
  redactions,
) {
  for (const directory of [
    paths.sourcePath,
    paths.harnessPath,
    paths.userDataPath,
    paths.extensionsPath,
    paths.homePath,
    paths.xdgConfigPath,
    paths.xdgCachePath,
    paths.xdgDataPath,
    paths.xdgStatePath,
    paths.xdgRuntimePath,
    paths.windowsRoamingPath,
    paths.windowsLocalPath,
    paths.tempPath,
  ]) {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  }
  await fs.mkdir(path.join(paths.userDataPath, "User"), { recursive: true, mode: 0o700 });
  await fs.writeFile(
    path.join(paths.userDataPath, "User", "settings.json"),
    JSON.stringify({
      "files.hotExit": "onExitAndWindowClose",
      "window.restoreWindows": "all",
      "window.confirmBeforeClose": "never",
      "workbench.startupEditor": "none",
      "security.workspace.trust.enabled": false,
      "telemetry.telemetryLevel": "off",
    }),
    { mode: 0o600 },
  );
  await fs.writeFile(path.join(paths.sourcePath, LOGICAL_PATH), plaintext, { mode: 0o600 });
  await fs.writeFile(
    path.join(paths.sourcePath, SECONDARY_LOGICAL_PATH),
    secondaryPlaintext,
    { mode: 0o600 },
  );
  await fs.mkdir(path.dirname(path.join(paths.sourcePath, ASSET_LOGICAL_PATH)), {
    recursive: true,
    mode: 0o700,
  });
  await fs.writeFile(path.join(paths.sourcePath, ASSET_LOGICAL_PATH), assetBytes, {
    mode: 0o600,
  });
  assetBytes.fill(0);
  await fs.copyFile(SIDECAR_TRACE_PROXY_SOURCE, paths.sidecarProxyPath);
  await fs.chmod(paths.sidecarProxyPath, 0o700);
  await runGit(
    paths,
    ["-C", paths.sourcePath, "init", "-q", "--initial-branch=main"],
    signatures,
    redactions,
    "initialize source repository",
  );
  await runGit(
    paths,
    ["-C", paths.sourcePath, "add", "--all"],
    signatures,
    redactions,
    "stage source repository",
  );
  await runGit(
    paths,
    [
      "-C",
      paths.sourcePath,
      "-c",
      "user.email=inex-vscode-integration@example.invalid",
      "-c",
      "user.name=Inex VS Code Integration",
      "-c",
      "commit.gpgSign=false",
      "commit",
      "-q",
      "-m",
      "clean Markdown source fixture",
    ],
    signatures,
    redactions,
    "commit source repository",
  );
  const status = await runGit(
    paths,
    ["-C", paths.sourcePath, "status", "--porcelain=v1", "--untracked-files=all"],
    signatures,
    redactions,
    "audit source repository",
  );
  if (status.stdout.text().length !== 0) {
    throw new Error("Synthetic Markdown source repository is not clean");
  }
}

async function importVault(paths, inexPath, signatures, redactions) {
  await assertRegularExecutable(inexPath, "inex CLI");
  const result = await runChild(
    inexPath,
    ["import-repository", paths.sourcePath, paths.vaultPath],
    {
      ...isolatedEnvironment(paths),
      INEX_PASSWORD_STDIN: "1",
    },
    `${TEST_PASSWORD}\n${TEST_PASSWORD}\n`,
    signatures,
  );
  assertCapturesHaveNoResidue("inex import-repository", result.stdout, result.stderr);
  if (result.code !== 0) {
    throw new Error(
      `inex import-repository failed (${result.code}): ${redact(result.stdout.text(), redactions)}\n${redact(result.stderr.text(), redactions)}`,
    );
  }
  for (const field of [
    "import-mode: repository-copy",
    "markdown-files: 2",
    "asset-files: 1",
    "candidate-plaintext-file-objects: 0",
    "source-preserved: yes",
    "vault-publication: published",
    "git-root-parent-count: 0",
    "result: repository import complete",
  ]) {
    if (!result.stdout.text().includes(field)) {
      throw new Error(`inex import-repository omitted proof field: ${field}`);
    }
  }
  const vault = await fs.lstat(paths.vaultPath);
  if (!vault.isDirectory() || vault.isSymbolicLink()) {
    throw new Error("inex import-repository did not publish a regular vault directory");
  }
  for (const ciphertextPath of [
    path.join(paths.vaultPath, `${LOGICAL_PATH}.enc`),
    path.join(paths.vaultPath, `${SECONDARY_LOGICAL_PATH}.enc`),
    path.join(paths.vaultPath, `${ASSET_LOGICAL_PATH}.asset.enc`),
  ]) {
    const ciphertext = await fs.lstat(ciphertextPath);
    if (!ciphertext.isFile() || ciphertext.isSymbolicLink()) {
      throw new Error("inex import-repository omitted an expected ciphertext object");
    }
  }
  const targetStatus = await runGit(
    paths,
    ["-C", paths.vaultPath, "status", "--porcelain=v1", "--untracked-files=all"],
    signatures,
    redactions,
    "audit imported repository",
  );
  if (targetStatus.stdout.text().length !== 0) {
    throw new Error("Imported Inex repository is not clean");
  }
  const commitCount = await runGit(
    paths,
    ["-C", paths.vaultPath, "rev-list", "--count", "HEAD"],
    signatures,
    redactions,
    "audit imported root commit",
  );
  if (commitCount.stdout.text().trim() !== "1") {
    throw new Error("Imported Inex repository does not have one root commit");
  }
}

async function runStage(
  stage,
  paths,
  expectedSha256,
  runnerOptions,
  signatures,
  redactions,
) {
  // VS Code intentionally forces all workbench storage in-memory when an
  // extensionTestsLocationURI is present. The suite therefore verifies a real
  // scheduled backup followed by the provider's exact backupId recovery path;
  // cross-process dirty-tab restoration remains a separate manual release gate.
  await assertRegularExecutable(runnerOptions.inexdPath, "inexd sidecar");
  await assertRegularExecutable(paths.sidecarProxyPath, "sidecar trace proxy");
  const output = new BoundedCapture(signatures);
  const errors = new BoundedCapture(signatures);
  const testOptions = {
    extensionDevelopmentPath: EXTENSION_ROOT,
    extensionTestsPath: EXTENSION_TESTS_PATH,
    launchArgs: [
      paths.vaultPath,
      "--new-window",
      "--disable-extensions",
      `--user-data-dir=${paths.userDataPath}`,
      `--extensions-dir=${paths.extensionsPath}`,
      "--disable-telemetry",
      "--disable-crash-reporter",
      "--skip-add-to-recently-opened",
      "--disable-gpu",
    ],
    extensionTestsEnv: {
      ...isolatedEnvironment(paths),
      INEX_VSCODE_INTEGRATION_TEST: "1",
      INEX_TEST_STAGE: stage,
      INEX_TEST_VAULT_PATH: paths.vaultPath,
      INEX_TEST_SOURCE_PATH: paths.sourcePath,
      INEX_TEST_PASSWORD: TEST_PASSWORD,
      INEX_TEST_INEXD_PATH: paths.sidecarProxyPath,
      INEX_TEST_REAL_INEXD_PATH: runnerOptions.inexdPath,
      INEX_TEST_SIDECAR_TRACE_PATH: paths.sidecarTracePath,
      INEX_TEST_USER_DATA_PATH: paths.userDataPath,
      INEX_TEST_EXPECTED_SHA256: expectedSha256,
    },
    stdout: output,
    stderr: errors,
  };
  if (runnerOptions.vscodePath !== undefined) {
    testOptions.vscodeExecutablePath = runnerOptions.vscodePath;
  } else {
    testOptions.version = runnerOptions.version;
    testOptions.cachePath = path.join(EXTENSION_ROOT, ".vscode-test");
  }
  const outcome = runTests(testOptions).then(
    () => ({ ok: true }),
    (error) => ({ ok: false, error }),
  );
  let ended;
  try {
    ended = await withDeadline(
      outcome,
      60_000,
      "VS Code backup/recovery cycle exceeded the deadline",
    );
  } catch (error) {
    throw stageFailure(stage, output, errors, redactions, error);
  }
  assertCapturesHaveNoResidue(`VS Code ${stage}`, output, errors);
  if (!ended.ok) {
    throw stageFailure(stage, output, errors, redactions, ended.error);
  }
}

function stageFailure(stage, output, errors, redactions, cause) {
  assertCapturesHaveNoResidue(`VS Code ${stage}`, output, errors);
  const diagnostic = [output.text(), errors.text()]
    .filter((value) => value.length > 0)
    .map((value) => redact(value, redactions))
    .join("\n");
  return new Error(
    `VS Code ${stage} stage failed${diagnostic.length > 0 ? `:\n${diagnostic}` : ""}`,
    { cause },
  );
}

function isolatedEnvironment(paths) {
  return {
    ...process.env,
    HOME: paths.homePath,
    TMPDIR: paths.tempPath,
    XDG_CONFIG_HOME: paths.xdgConfigPath,
    XDG_CACHE_HOME: paths.xdgCachePath,
    XDG_DATA_HOME: paths.xdgDataPath,
    XDG_STATE_HOME: paths.xdgStatePath,
    XDG_RUNTIME_DIR: paths.xdgRuntimePath,
    USERPROFILE: paths.homePath,
    APPDATA: paths.windowsRoamingPath,
    LOCALAPPDATA: paths.windowsLocalPath,
    TEMP: paths.tempPath,
    TMP: paths.tempPath,
    VSCODE_CLI_DATA_DIR: path.join(paths.xdgDataPath, "vscode-cli"),
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
    GIT_TERMINAL_PROMPT: "0",
  };
}

function fixturePaths(root) {
  return {
    sourcePath: path.join(root, "plaintext-source"),
    vaultPath: path.join(root, "encrypted-vault"),
    harnessPath: path.join(root, "harness"),
    sidecarProxyPath: path.join(root, "harness", "inexd-trace-proxy.mjs"),
    sidecarTracePath: path.join(root, "harness", "sidecar-trace.jsonl"),
    userDataPath: path.join(root, "user-data"),
    extensionsPath: path.join(root, "extensions"),
    homePath: path.join(root, "home"),
    xdgConfigPath: path.join(root, "xdg-config"),
    xdgCachePath: path.join(root, "xdg-cache"),
    xdgDataPath: path.join(root, "xdg-data"),
    xdgStatePath: path.join(root, "xdg-state"),
    xdgRuntimePath: path.join(root, "xdg-runtime"),
    windowsRoamingPath: path.join(root, "windows-roaming"),
    windowsLocalPath: path.join(root, "windows-local"),
    tempPath: path.join(root, "tmp"),
  };
}

function buildCanaryPng(canaryValue) {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(1, 0);
  ihdr.writeUInt32BE(1, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const comment = Buffer.concat([
    Buffer.from("Comment\0", "latin1"),
    Buffer.from(canaryValue, "ascii"),
  ]);
  const scanline = Buffer.from([0, 0x33, 0x66, 0x99, 0xff]);
  const compressed = deflateSync(scanline);
  scanline.fill(0);
  const png = Buffer.concat([
    signature,
    pngChunk("IHDR", ihdr),
    pngChunk("tEXt", comment),
    pngChunk("IDAT", compressed),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
  ihdr.fill(0);
  comment.fill(0);
  compressed.fill(0);
  return png;
}

function pngChunk(type, data) {
  const typeBytes = Buffer.from(type, "ascii");
  const chunk = Buffer.alloc(12 + data.length);
  chunk.writeUInt32BE(data.length, 0);
  typeBytes.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(chunk.subarray(4, 8 + data.length)), 8 + data.length);
  typeBytes.fill(0);
  return chunk;
}

function crc32(bytes) {
  let value = 0xffff_ffff;
  for (const byte of bytes) {
    value ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value >>> 1) ^ ((value & 1) === 1 ? 0xedb8_8320 : 0);
    }
  }
  return (value ^ 0xffff_ffff) >>> 0;
}

function withDeadline(promise, timeoutMs, message) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(message)), timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

async function killRemainingIsolatedCodeProcesses(userDataPath) {
  const expectedUserDataArgument = `--user-data-dir=${userDataPath}`;
  const entries = await fs.readdir("/proc", { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory() || !/^\d+$/u.test(entry.name)) {
      continue;
    }
    let commandLine;
    try {
      commandLine = (await fs.readFile(`/proc/${entry.name}/cmdline`))
        .toString("utf8")
        .replaceAll("\0", " ");
    } catch (error) {
      if (error?.code === "ENOENT" || error?.code === "EACCES") {
        continue;
      }
      throw error;
    }
    if (!commandLine.includes(expectedUserDataArgument)) {
      continue;
    }
    try {
      process.kill(Number.parseInt(entry.name, 10), "SIGKILL");
    } catch (error) {
      if (error?.code !== "ESRCH") {
        throw error;
      }
    }
  }
}

function residueRoots(auditRoot) {
  return [
    auditRoot,
    path.join(EXTENSION_ROOT, ".vscode-test", "user-data"),
    path.join(EXTENSION_ROOT, ".vscode-test", "extensions"),
    path.join(REPOSITORY_ROOT, ".vscode-test", "user-data"),
    path.join(REPOSITORY_ROOT, ".vscode-test", "extensions"),
  ];
}

async function removePlaintextSource(sourcePath) {
  await fs.rm(sourcePath, { recursive: true, force: true });
  try {
    await fs.lstat(sourcePath);
  } catch (error) {
    if (error?.code === "ENOENT") {
      return;
    }
    throw error;
  }
  throw new Error("Plaintext import source still exists after fixture preparation");
}

async function assertRegularExecutable(executablePath, label) {
  const metadata = await fs.lstat(executablePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${label} is not a regular file`);
  }
  await fs.access(executablePath, fs.constants.X_OK);
}

async function runGit(paths, args, signatures, redactions, label) {
  const result = await runChild(
    "git",
    args,
    isolatedEnvironment(paths),
    "",
    signatures,
  );
  assertCapturesHaveNoResidue(`git ${label}`, result.stdout, result.stderr);
  if (result.code !== 0) {
    throw new Error(
      `git ${label} failed (${result.code}): ${redact(result.stdout.text(), redactions)}\n${redact(result.stderr.text(), redactions)}`,
    );
  }
  return result;
}

function runChild(executable, args, environment, input, signatures) {
  return new Promise((resolve, reject) => {
    const child = spawn(executable, args, {
      cwd: REPOSITORY_ROOT,
      env: environment,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdout = new BoundedCapture(signatures);
    const stderr = new BoundedCapture(signatures);
    child.stdout.pipe(stdout);
    child.stderr.pipe(stderr);
    child.once("error", reject);
    child.once("close", (code, signal) => {
      resolve({ code: code ?? signal ?? "unknown", stdout, stderr });
    });
    child.stdin.end(input);
  });
}

function assertCapturesHaveNoResidue(label, stdout, stderr) {
  if (stdout.residueHit !== undefined) {
    throw new Error(`${label} stdout contained residue [${stdout.residueHit}]`);
  }
  if (stderr.residueHit !== undefined) {
    throw new Error(`${label} stderr contained residue [${stderr.residueHit}]`);
  }
}

function parseOptions(arguments_) {
  let vscodePath;
  let version;
  let inexPath = path.join(REPOSITORY_ROOT, "target/debug/inex");
  let inexdPath = path.join(REPOSITORY_ROOT, "target/debug/inexd");
  for (const argument of arguments_) {
    if (argument.startsWith("--vscode=")) {
      vscodePath = path.resolve(argument.slice("--vscode=".length));
    } else if (argument.startsWith("--version=")) {
      version = argument.slice("--version=".length);
    } else if (argument.startsWith("--inex=")) {
      inexPath = path.resolve(argument.slice("--inex=".length));
    } else if (argument.startsWith("--inexd=")) {
      inexdPath = path.resolve(argument.slice("--inexd=".length));
    } else {
      throw new Error(`Unknown integration runner option: ${argument}`);
    }
  }
  if ((vscodePath === undefined) === (version === undefined)) {
    throw new Error("Specify exactly one of --vscode=<executable> or --version=<release>");
  }
  if (version !== undefined && !/^\d+\.\d+\.\d+$/u.test(version)) {
    throw new Error("VS Code compatibility version must be an exact stable release");
  }
  return { vscodePath, version, inexPath, inexdPath };
}

function redact(value, secrets) {
  let redacted = String(value);
  for (const secret of secrets) {
    redacted = redacted.split(secret).join("[REDACTED]");
  }
  return redacted;
}

function safeError(error, redactions) {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  return redact(message, redactions);
}
