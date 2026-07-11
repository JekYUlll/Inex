import { lstatSync } from "node:fs";
import * as path from "node:path";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

import {
  FrameDecoder,
  RpcProtocolError,
  RpcRemoteError,
  type JsonObject,
  type JsonValue,
  type RpcId,
  type RpcResponse,
  MAX_FRAME_BYTES,
  encodeRequest,
  responseResult,
} from "./rpc.ts";
import {
  LogicalPathError,
  logicalDirectoryComponents,
  logicalFileComponents,
} from "./logicalPath.ts";

const REQUEST_TIMEOUT_MS = 120_000;
const MAX_STDERR_BYTES = 64 * 1024;
const MAX_PENDING_CALLS = 128;
const MAX_OUTSTANDING_FRAME_BYTES = MAX_FRAME_BYTES + 64 * 1024;
const MAX_CLIENT_IDLE_TIMEOUT_MS = 60 * 60 * 1_000;
const MAX_DOCUMENT_BYTES = 16 * 1024 * 1024;
const MAX_DRAFT_ENVELOPE_BYTES = MAX_DOCUMENT_BYTES + 12 + 4096 + 16;
const PROTOCOL_MAJOR = 1;

export interface HelloResult {
  readonly server: "inexd";
  readonly serverVersion: string;
  readonly protocolMajor: 1;
  readonly capabilities: readonly string[];
}

export interface UnlockResult {
  readonly vaultId: string;
  readonly idleTimeoutMs: number;
  readonly warnings: readonly JsonValue[];
}

export interface TreeEntry {
  readonly kind: "directory" | "file";
  readonly logicalPath: string;
}

export interface DocumentMetadata {
  readonly fileId: string;
  readonly logicalPath: string;
  readonly createdAt: number;
  readonly modifiedAt: number;
  readonly flags: number;
}

export interface ReadResult {
  readonly content: Buffer;
  readonly etag: string;
  readonly metadata: DocumentMetadata;
}

export interface OpenResult extends ReadResult {
  readonly handle: string;
}

export interface WriteResult {
  readonly etag: string;
  readonly metadata: DocumentMetadata;
  readonly durability: "synced" | "notSynced";
}

export interface SearchHit {
  readonly logicalPath: string;
  readonly startByte: number;
  readonly endByte: number;
  readonly line: number;
  readonly utf16Column: number;
  readonly snippet: string;
}

export interface DraftEncryptResult {
  readonly envelope: Buffer;
  readonly etag: string;
  readonly metadata: DocumentMetadata;
}

export interface DraftDecryptResult {
  readonly content: Buffer;
  readonly baseEtag: string | null;
  readonly metadata: DocumentMetadata;
}

interface PendingCall {
  readonly method: string;
  readonly resolve: (value: JsonValue) => void;
  readonly reject: (reason: Error) => void;
  readonly timer: NodeJS.Timeout;
}

export class SidecarLifecycleError extends Error {
  public override readonly name = "SidecarLifecycleError";
}

export class InexSidecar {
  private readonly decoder = new FrameDecoder();
  private readonly pending = new Map<RpcId, PendingCall>();
  private child: ChildProcessWithoutNullStreams | undefined;
  private session: string | undefined;
  private nextId = 1;
  private stderrBytes = 0;
  private terminalError: Error | undefined;
  private outstandingFrameBytes = 0;
  private readonly executable: string;
  private readonly onSessionLost: ((error: Error) => void) | undefined;
  private readonly onSessionActivity: (() => void) | undefined;

  public constructor(
    executable: string,
    onSessionLost?: (error: Error) => void,
    onSessionActivity?: () => void,
  ) {
    this.executable = executable;
    this.onSessionLost = onSessionLost;
    this.onSessionActivity = onSessionActivity;
  }

  public get isRunning(): boolean {
    return this.child !== undefined && this.terminalError === undefined;
  }

  public get hasSession(): boolean {
    return this.session !== undefined;
  }

  public async start(clientVersion: string): Promise<HelloResult> {
    if (this.child !== undefined) {
      throw new SidecarLifecycleError("Inex sidecar is already started");
    }
    const child = spawn(this.executable, [], {
      shell: false,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.child = child;
    child.stdout.on("data", (chunk: Buffer) => {
      this.acceptStdout(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      this.stderrBytes = Math.min(MAX_STDERR_BYTES, this.stderrBytes + chunk.byteLength);
      chunk.fill(0);
    });
    child.stdin.on("error", () => {
      this.failTerminal(new SidecarLifecycleError("Inex sidecar stdin failed"));
    });
    child.stdout.on("error", () => {
      this.failTerminal(new SidecarLifecycleError("Inex sidecar stdout failed"));
    });
    child.stderr.on("error", () => {
      this.failTerminal(new SidecarLifecycleError("Inex sidecar stderr failed"));
    });
    child.once("error", () => {
      this.failTerminal(new SidecarLifecycleError("Inex sidecar process failed to start"));
    });
    child.once("exit", (code, signal) => {
      const clean = code === 0 && signal === null;
      this.failTerminal(
        new SidecarLifecycleError(
          clean ? "Inex sidecar exited" : "Inex sidecar exited unexpectedly",
        ),
      );
    });

    const result = parseHello(await this.callRaw("system.hello", {
      client: "vscode",
      clientVersion,
      protocolMajor: PROTOCOL_MAJOR,
    }));
    const requiredCapabilities = [
      "vault",
      "files",
      "documents",
      "encryptedDrafts",
      "search",
      "authenticatedPing",
    ];
    if (
      new Set(result.capabilities).size !== result.capabilities.length ||
      !requiredCapabilities.every((capability) => result.capabilities.includes(capability))
    ) {
      throw new RpcProtocolError("Inex sidecar capability negotiation failed");
    }
    return result;
  }

  public async unlock(vaultPath: string, password: string, slotId?: string): Promise<UnlockResult> {
    const params: JsonObject = { vaultPath, password };
    if (slotId !== undefined) {
      params.slotId = slotId;
    }
    const result = expectObject(await this.callRaw("vault.unlock", params));
    const session = expectCapability(result.session, "unlock session", 43);
    const idleTimeoutMs = expectSafeInteger(result.idleTimeoutMs, "idle timeout");
    if (idleTimeoutMs < 1_000 || idleTimeoutMs > MAX_CLIENT_IDLE_TIMEOUT_MS) {
      throw new RpcProtocolError("RPC idle timeout is invalid");
    }
    const vaultId = expectUuid(result.vaultId, "vault id");
    const warnings = expectArray(result.warnings, "unlock warnings");
    this.session = session;
    return {
      vaultId,
      idleTimeoutMs,
      warnings,
    };
  }

  public async lock(): Promise<void> {
    const session = this.requireSession();
    try {
      expectAcknowledgement(await this.callRaw("vault.lock", { session }));
    } finally {
      this.session = undefined;
    }
  }

  public async touch(): Promise<number> {
    const result = expectObject(
      await this.callRaw("system.ping", { session: this.requireSession() }),
    );
    if (result.ok !== true || result.sessionActive !== true) {
      throw new RpcProtocolError("RPC authenticated ping result is invalid");
    }
    const idleTimeoutMs = expectSafeInteger(result.idleTimeoutMs, "idle timeout");
    if (idleTimeoutMs < 1_000 || idleTimeoutMs > MAX_CLIENT_IDLE_TIMEOUT_MS) {
      throw new RpcProtocolError("RPC idle timeout is invalid");
    }
    return idleTimeoutMs;
  }

  public async listTree(prefix?: string): Promise<readonly TreeEntry[]> {
    const params = this.protectedParams();
    if (prefix !== undefined) {
      params.prefix = prefix;
    }
    const result = expectObject(await this.callRaw("vault.listTree", params));
    return expectArray(result.entries, "tree entries").map((entry) => {
      const object = expectObject(entry);
      const kind = expectString(object.kind, "tree entry kind");
      if (kind !== "directory" && kind !== "file") {
        throw new RpcProtocolError("RPC tree entry kind is invalid");
      }
      return {
        kind,
        logicalPath:
          kind === "file"
            ? expectLogicalFile(object.logicalPath, "tree logical path")
            : expectLogicalDirectory(object.logicalPath, "tree logical path"),
      };
    });
  }

  public async read(logicalPath: string): Promise<ReadResult> {
    const result = await this.callRaw("file.read", {
      ...this.protectedParams(),
      logicalPath,
    });
    return parseRead(result, logicalPath);
  }

  public async write(
    logicalPath: string,
    content: Uint8Array,
    condition: { readonly ifMatch: string } | { readonly ifNoneMatch: "*" },
  ): Promise<WriteResult> {
    const plaintext = Buffer.from(content);
    const contentBase64 = plaintext.toString("base64url");
    plaintext.fill(0);
    const params: JsonObject = {
      ...this.protectedParams(),
      logicalPath,
      contentBase64,
      ...condition,
    };
    const result = expectObject(await this.callRaw("file.write", params));
    const durability = expectString(result.durability, "write durability");
    if (durability !== "synced" && durability !== "notSynced") {
      throw new RpcProtocolError("RPC write durability is invalid");
    }
    return {
      etag: expectEtag(result.etag, "write etag"),
      metadata: parseMetadata(result.metadata, logicalPath),
      durability,
    };
  }

  public async openDocument(logicalPath: string): Promise<OpenResult> {
    const result = expectObject(
      await this.callRaw("document.open", {
        ...this.protectedParams(),
        logicalPath,
      }),
    );
    const read = parseRead(result, logicalPath);
    try {
      return {
        ...read,
        handle: expectCapability(result.handle, "document handle", 22),
      };
    } catch (error: unknown) {
      read.content.fill(0);
      throw error;
    }
  }

  public async closeDocument(handle: string): Promise<void> {
    expectAcknowledgement(
      await this.callRaw("document.close", { ...this.protectedParams(), handle }),
    );
  }

  public async encryptDraft(
    logicalPath: string,
    baseEtag: string,
    content: Uint8Array,
  ): Promise<DraftEncryptResult> {
    const plaintext = Buffer.from(content);
    const contentBase64 = plaintext.toString("base64url");
    plaintext.fill(0);
    const result = expectObject(
      await this.callRaw("draft.encrypt", {
        ...this.protectedParams(),
        logicalPath,
        baseEtag,
        contentBase64,
      }),
    );
    const envelope = decodeCanonicalBase64url(
      expectString(result.draftBase64, "draft envelope"),
      MAX_DRAFT_ENVELOPE_BYTES,
    );
    try {
      return {
        envelope,
        etag: expectEtag(result.etag, "draft etag"),
        metadata: parseMetadata(result.metadata, logicalPath),
      };
    } catch (error: unknown) {
      envelope.fill(0);
      throw error;
    }
  }

  public async decryptDraft(
    logicalPath: string,
    envelope: Uint8Array,
  ): Promise<DraftDecryptResult> {
    const ciphertext = Buffer.from(envelope);
    const draftBase64 = ciphertext.toString("base64url");
    ciphertext.fill(0);
    const result = expectObject(
      await this.callRaw("draft.decrypt", {
        ...this.protectedParams(),
        logicalPath,
        draftBase64,
      }),
    );
    const baseEtag = result.baseEtag;
    if (!(baseEtag === null || typeof baseEtag === "string")) {
      throw new RpcProtocolError("RPC draft base etag is invalid");
    }
    const content = decodeCanonicalBase64url(
      expectString(result.contentBase64, "draft content"),
      MAX_DOCUMENT_BYTES,
    );
    try {
      return {
        content,
        baseEtag: baseEtag === null ? null : expectEtag(baseEtag, "draft base etag"),
        metadata: parseMetadata(result.metadata, logicalPath),
      };
    } catch (error: unknown) {
      content.fill(0);
      throw error;
    }
  }

  public async evict(logicalPath?: string): Promise<void> {
    const params = this.protectedParams();
    if (logicalPath !== undefined) {
      params.logicalPath = logicalPath;
    }
    expectAcknowledgement(await this.callRaw("cache.evict", params));
  }

  public async search(query: string, limit = 50): Promise<readonly SearchHit[]> {
    if (
      Buffer.byteLength(query, "utf8") < 1 ||
      Buffer.byteLength(query, "utf8") > 4096 ||
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      limit > 1_000
    ) {
      throw new RpcProtocolError("Search request exceeds the client limit");
    }
    const result = expectObject(
      await this.callRaw("search.query", {
        ...this.protectedParams(),
        query,
        limit,
      }),
    );
    const entries = expectArray(result.results, "search results");
    if (entries.length > limit) {
      throw new RpcProtocolError("RPC search result count exceeds the request limit");
    }
    return entries.map((entry) => {
      const hit = expectObject(entry);
      const startByte = expectSafeInteger(hit.startByte, "search start");
      const endByte = expectSafeInteger(hit.endByte, "search end");
      const line = expectSafeInteger(hit.line, "search line");
      const utf16Column = expectSafeInteger(hit.utf16Column, "search column");
      if (
        startByte < 0 ||
        endByte < startByte ||
        endByte > 16 * 1024 * 1024 ||
        line < 0 ||
        utf16Column < 0
      ) {
        throw new RpcProtocolError("RPC search result range is invalid");
      }
      return {
        logicalPath: expectLogicalFile(hit.logicalPath, "search logical path"),
        startByte,
        endByte,
        line,
        utf16Column,
        snippet: expectBoundedString(hit.snippet, "search snippet", 8 * 1024),
      };
    });
  }

  public async shutdown(): Promise<void> {
    if (this.child === undefined || this.terminalError !== undefined) {
      this.session = undefined;
      return;
    }
    try {
      expectAcknowledgement(await this.callRaw("system.shutdown", {}));
    } finally {
      this.session = undefined;
    }
  }

  public dispose(): void {
    this.session = undefined;
    const child = this.child;
    this.child = undefined;
    this.decoder.clear();
    this.outstandingFrameBytes = 0;
    if (child !== undefined && child.exitCode === null && child.signalCode === null) {
      child.kill();
    }
    this.rejectPending(new SidecarLifecycleError("Inex sidecar was disposed"));
  }

  private protectedParams(): JsonObject {
    return { session: this.requireSession() };
  }

  private requireSession(): string {
    if (this.session === undefined) {
      throw new SidecarLifecycleError("Inex vault is locked");
    }
    return this.session;
  }

  private callRaw(method: string, params: JsonObject): Promise<JsonValue> {
    const child = this.child;
    if (child === undefined || this.terminalError !== undefined) {
      return Promise.reject(
        this.terminalError ?? new SidecarLifecycleError("Inex sidecar is not running"),
      );
    }
    if (this.pending.size >= MAX_PENDING_CALLS) {
      return Promise.reject(new SidecarLifecycleError("Inex sidecar call limit is reached"));
    }
    const id = this.allocateId();
    return new Promise<JsonValue>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.failTerminal(
          new SidecarLifecycleError(`Inex sidecar call timed out; ${mutationOutcome(method)}`),
        );
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { method, resolve, reject, timer });
      let frame: Buffer;
      try {
        frame = encodeRequest(id, method, params);
      } catch (error: unknown) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(asError(error));
        return;
      }
      if (
        frame.byteLength > MAX_OUTSTANDING_FRAME_BYTES - this.outstandingFrameBytes
      ) {
        frame.fill(0);
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new SidecarLifecycleError("Inex sidecar write queue byte limit is reached"));
        return;
      }
      this.outstandingFrameBytes += frame.byteLength;
      const frameBytes = frame.byteLength;
      try {
        child.stdin.write(frame, (error) => {
          this.outstandingFrameBytes = Math.max(
            0,
            this.outstandingFrameBytes - frameBytes,
          );
          frame.fill(0);
          if (error !== null && error !== undefined) {
            this.failTerminal(new SidecarLifecycleError("Inex sidecar request write failed"));
          }
        });
      } catch {
        this.outstandingFrameBytes = Math.max(
          0,
          this.outstandingFrameBytes - frameBytes,
        );
        frame.fill(0);
        this.failTerminal(new SidecarLifecycleError("Inex sidecar request write failed"));
      }
    });
  }

  private allocateId(): number {
    if (!Number.isSafeInteger(this.nextId) || this.nextId < 1) {
      throw new SidecarLifecycleError("Inex request id space is exhausted");
    }
    const id = this.nextId;
    this.nextId += 1;
    return id;
  }

  private acceptStdout(chunk: Buffer): void {
    try {
      for (const response of this.decoder.push(chunk)) {
        this.acceptResponse(response);
      }
    } catch (error: unknown) {
      this.failTerminal(asError(error));
    } finally {
      chunk.fill(0);
    }
  }

  private acceptResponse(response: RpcResponse): void {
    if (response.id === null) {
      this.failTerminal(new RpcProtocolError("Inex sidecar sent an uncorrelated error"));
      return;
    }
    const pending = this.pending.get(response.id);
    if (pending === undefined) {
      this.failTerminal(new RpcProtocolError("Inex sidecar sent an unknown response id"));
      return;
    }
    clearTimeout(pending.timer);
    this.pending.delete(response.id);
    try {
      pending.resolve(responseResult(response));
      if (methodRenewsSession(pending.method) && this.session !== undefined) {
        this.onSessionActivity?.();
      }
    } catch (error: unknown) {
      const normalized = asError(error);
      pending.reject(normalized);
      if (normalized instanceof RpcRemoteError && normalized.stableName === "SESSION_INVALID") {
        this.loseSession(normalized);
      }
    }
  }

  private failTerminal(error: Error): void {
    if (this.terminalError !== undefined) {
      return;
    }
    this.terminalError = error;
    const hadSession = this.session !== undefined;
    this.session = undefined;
    this.decoder.clear();
    this.outstandingFrameBytes = 0;
    this.rejectPending(error);
    const child = this.child;
    if (child !== undefined && child.exitCode === null && child.signalCode === null) {
      child.kill();
    }
    if (hadSession) {
      this.onSessionLost?.(error);
    }
  }

  private loseSession(error: Error): void {
    if (this.session === undefined) {
      return;
    }
    this.session = undefined;
    this.onSessionLost?.(error);
  }

  private rejectPending(error: Error): void {
    for (const pending of this.pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(error);
    }
    this.pending.clear();
  }
}

function methodRenewsSession(method: string): boolean {
  return (
    method === "system.ping" ||
    method === "vault.status" ||
    method === "vault.listTree" ||
    method.startsWith("file.") ||
    method.startsWith("document.") ||
    method.startsWith("draft.") ||
    method === "search.query" ||
    method === "cache.evict"
  );
}

export function resolveSidecarExecutable(
  configuredPath: string,
  extensionPath: string,
  platform: NodeJS.Platform = process.platform,
  architecture: string = process.arch,
): string {
  const candidate =
    configuredPath.length > 0
      ? configuredPath
      : path.join(
          extensionPath,
          "bin",
          `${platform}-${architecture}`,
          platform === "win32" ? "inexd.exe" : "inexd",
        );
  if (!path.isAbsolute(candidate)) {
    throw new SidecarLifecycleError("Inex sidecar path must be absolute");
  }
  let metadata;
  try {
    metadata = lstatSync(candidate);
  } catch {
    throw new SidecarLifecycleError("Inex sidecar executable was not found");
  }
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new SidecarLifecycleError("Inex sidecar path is not a regular file");
  }
  return candidate;
}

function parseHello(value: JsonValue): HelloResult {
  const result = expectObject(value);
  if (result.server !== "inexd" || result.protocolMajor !== PROTOCOL_MAJOR) {
    throw new RpcProtocolError("Inex sidecar protocol negotiation failed");
  }
  return {
    server: "inexd",
    serverVersion: expectString(result.serverVersion, "server version"),
    protocolMajor: 1,
    capabilities: expectArray(result.capabilities, "capabilities").map((capability) =>
      expectString(capability, "capability"),
    ),
  };
}

function parseRead(value: JsonValue, expectedLogicalPath: string): ReadResult {
  const result = expectObject(value);
  const content = decodeCanonicalBase64url(
    expectString(result.contentBase64, "document content"),
    MAX_DOCUMENT_BYTES,
  );
  try {
    return {
      content,
      etag: expectEtag(result.etag, "document etag"),
      metadata: parseMetadata(result.metadata, expectedLogicalPath),
    };
  } catch (error: unknown) {
    content.fill(0);
    throw error;
  }
}

function parseMetadata(
  value: JsonValue | undefined,
  expectedLogicalPath: string,
): DocumentMetadata {
  const metadata = expectObject(value);
  const logicalPath = expectLogicalFile(metadata.logicalPath, "metadata logical path");
  if (logicalPath !== expectedLogicalPath) {
    throw new RpcProtocolError("RPC metadata logical path does not match the request");
  }
  const createdAt = expectSafeInteger(metadata.createdAt, "creation time");
  const modifiedAt = expectSafeInteger(metadata.modifiedAt, "modification time");
  const flags = expectSafeInteger(metadata.flags, "content flags");
  if (createdAt < 0 || modifiedAt < 0 || flags < 0 || flags > 0xffff_ffff) {
    throw new RpcProtocolError("RPC document metadata is outside the v1 range");
  }
  return {
    fileId: expectUuid(metadata.fileId, "file id"),
    logicalPath,
    createdAt,
    modifiedAt,
    flags,
  };
}

function expectLogicalFile(value: JsonValue | undefined, _field: string): string {
  const text = expectString(value, _field);
  try {
    logicalFileComponents(text);
  } catch (error: unknown) {
    if (error instanceof LogicalPathError) {
      throw new RpcProtocolError("RPC logical file path is invalid");
    }
    throw error;
  }
  return text;
}

function expectLogicalDirectory(value: JsonValue | undefined, _field: string): string {
  const text = expectString(value, _field);
  try {
    const components = logicalDirectoryComponents(text);
    if (components.length === 0) {
      throw new LogicalPathError("Tree entries cannot represent the root");
    }
  } catch (error: unknown) {
    if (error instanceof LogicalPathError) {
      throw new RpcProtocolError("RPC logical directory path is invalid");
    }
    throw error;
  }
  return text;
}

function expectEtag(value: JsonValue | undefined, _field: string): string {
  const text = expectString(value, _field);
  if (!/^sha256:[0-9a-f]{64}$/u.test(text)) {
    throw new RpcProtocolError("RPC ciphertext etag is invalid");
  }
  return text;
}

function expectUuid(value: JsonValue | undefined, _field: string): string {
  const text = expectString(value, _field);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(text)) {
    throw new RpcProtocolError("RPC UUID is invalid");
  }
  return text;
}

function expectCapability(
  value: JsonValue | undefined,
  _field: string,
  encodedLength: number,
): string {
  const text = expectString(value, _field);
  if (text.length !== encodedLength || !/^[A-Za-z0-9_-]+$/u.test(text)) {
    throw new RpcProtocolError("RPC capability is invalid");
  }
  return text;
}

function decodeCanonicalBase64url(value: string, maximumBytes: number): Buffer {
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) {
    throw new RpcProtocolError("RPC binary field is not canonical base64url");
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.byteLength > maximumBytes || decoded.toString("base64url") !== value) {
    decoded.fill(0);
    throw new RpcProtocolError("RPC binary field is not canonical base64url");
  }
  return decoded;
}

function expectBoundedString(
  value: JsonValue | undefined,
  field: string,
  maximumBytes: number,
): string {
  const text = expectString(value, field);
  if (Buffer.byteLength(text, "utf8") > maximumBytes) {
    throw new RpcProtocolError(`RPC ${field} exceeds its byte limit`);
  }
  return text;
}

function expectAcknowledgement(value: JsonValue): void {
  const result = expectObject(value);
  if (result.ok !== true) {
    throw new RpcProtocolError("RPC acknowledgement is invalid");
  }
}

function expectObject(value: JsonValue | undefined): { [key: string]: JsonValue } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new RpcProtocolError("RPC result object is invalid");
  }
  return value;
}

function expectArray(value: JsonValue | undefined, _field: string): JsonValue[] {
  if (!Array.isArray(value)) {
    throw new RpcProtocolError("RPC result array is invalid");
  }
  return value;
}

function expectString(value: JsonValue | undefined, _field: string): string {
  if (typeof value !== "string") {
    throw new RpcProtocolError("RPC result string is invalid");
  }
  return value;
}

function expectSafeInteger(value: JsonValue | undefined, _field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new RpcProtocolError("RPC result integer is invalid");
  }
  return value;
}

function mutationOutcome(method: string): string {
  return method.startsWith("file.") || method.startsWith("vault.") || method.startsWith("draft.")
    ? "the storage outcome may be unknown"
    : "the request outcome is unknown";
}

function asError(value: unknown): Error {
  return value instanceof Error ? value : new SidecarLifecycleError("Inex sidecar failed");
}
