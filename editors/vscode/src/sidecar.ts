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
  assetPathComponents,
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
const MAX_ASSET_BYTES = 64 * 1024 * 1024;
const MAX_UMBRA_TAGS = 1_024;
const MAX_UMBRA_PROFILES = 1_024;
const MAX_UMBRA_TEXT_BYTES = 4 * 1024;
export const MAX_ASSET_CHUNK_BYTES = 1024 * 1024;
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
  readonly kind: "directory" | "file" | "asset";
  readonly logicalPath: string;
}

export interface VaultStatus {
  readonly opaqueAssetsV1: boolean;
}

export interface UmbraStatus {
  readonly initialized: boolean;
  readonly unlocked: boolean;
}

export interface PlaintextExportPrepare {
  readonly confirmation: string;
  readonly scope: "outer" | "umbra";
  readonly files: number;
  readonly assets: number;
  readonly directories: number;
}

export interface TextRange {
  readonly startByte: number;
  readonly endByte: number;
}

export interface RenderMap {
  readonly generation: Buffer;
  readonly projectionBytes: number;
  readonly privateSlots: readonly { readonly slotId: string; readonly range: TextRange }[];
  readonly outerSegments: readonly {
    readonly projectionRange: TextRange;
    readonly outerRange: TextRange;
  }[];
}

export interface UmbraProjection {
  readonly content: Buffer;
  readonly etag: string;
  readonly metadata: DocumentMetadata;
  readonly renderMap: RenderMap;
}

export type PrivateAnnotationKind = "block" | "comment";
export type OuterMode = "drop" | "cover" | "placeholder";

export interface PrivateAnnotationSpec {
  readonly kind: PrivateAnnotationKind;
  readonly tagIds: readonly string[];
  readonly outer: { readonly mode: OuterMode; readonly coverText?: string };
}

export interface UmbraTagDefinition {
  readonly id: string;
  readonly label: string;
  readonly description: string;
  readonly aliases: readonly string[];
  readonly sortOrder: number;
  readonly defaultSelected: boolean;
  readonly archived: boolean;
}

export interface UmbraAnnotationProfile {
  readonly id: string;
  readonly label: string;
  readonly kind: PrivateAnnotationKind;
  readonly tagIds: readonly string[];
  readonly outer: OuterMode;
  readonly promptForCover: boolean;
}

export interface UmbraAnnotationConfig {
  readonly tags: readonly UmbraTagDefinition[];
  readonly profiles: readonly UmbraAnnotationProfile[];
  readonly defaults: {
    readonly kind: PrivateAnnotationKind;
    readonly tagIds: readonly string[];
    readonly outer: OuterMode;
    readonly defaultProfileId: string;
  };
}

export interface UmbraAnnotationResult extends UmbraProjection {
  readonly metadata: DocumentMetadata;
  readonly durability: "synced" | "notSynced";
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

export interface AssetOpenResult {
  readonly handle: string;
  readonly size: number;
  readonly etag: string;
  readonly metadata: DocumentMetadata;
}

export interface AssetChunkResult {
  readonly offset: number;
  readonly content: Buffer;
  readonly eof: boolean;
}

export interface WriteResult {
  readonly etag: string;
  readonly metadata: DocumentMetadata;
  readonly durability: "synced" | "notSynced";
}

export interface StatResult {
  readonly size: number;
  readonly etag: string;
  readonly metadata: DocumentMetadata;
}

export interface RenameResult {
  readonly etag: string;
  readonly metadata: DocumentMetadata;
  readonly sourceDurability: "synced" | "notSynced";
  readonly destinationDurability: "synced" | "notSynced";
}

export interface DeleteResult {
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
  private negotiatedOpaqueAssetsV1 = false;
  private negotiatedUmbraV1 = false;
  private authenticatedOpaqueAssetsV1 = false;
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

  public get canReadOpaqueAssetsV1(): boolean {
    return (
      this.session !== undefined &&
      this.negotiatedOpaqueAssetsV1 &&
      this.authenticatedOpaqueAssetsV1
    );
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
    this.negotiatedOpaqueAssetsV1 = result.capabilities.includes("opaqueAssetsV1");
    this.negotiatedUmbraV1 = result.capabilities.includes("umbraV1");
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
    this.authenticatedOpaqueAssetsV1 = false;
    if (this.negotiatedOpaqueAssetsV1) {
      try {
        this.authenticatedOpaqueAssetsV1 = (await this.status()).opaqueAssetsV1;
      } catch (error: unknown) {
        this.session = undefined;
        throw error;
      }
    }
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
      this.authenticatedOpaqueAssetsV1 = false;
    }
  }

  public async status(): Promise<VaultStatus> {
    const result = expectObject(
      await this.callRaw("vault.status", { session: this.requireSession() }),
    );
    const features = expectObject(result.features);
    expectExactKeys(features, ["opaqueAssetsV1"], "vault feature");
    if (typeof features.opaqueAssetsV1 !== "boolean") {
      throw new RpcProtocolError("RPC authenticated vault feature is invalid");
    }
    return { opaqueAssetsV1: features.opaqueAssetsV1 };
  }

  public async preparePlaintextExport(
    destination: string,
    scope: "outer" | "umbra",
  ): Promise<PlaintextExportPrepare> {
    return parsePlaintextExportPrepare(await this.callRaw("vault.export.prepare", {
      ...this.protectedParams(), destination, scope,
    }), scope);
  }

  public async commitPlaintextExport(prepared: PlaintextExportPrepare): Promise<void> {
    const committed = parsePlaintextExportCommit(await this.callRaw("vault.export.commit", {
      ...this.protectedParams(), confirmation: prepared.confirmation,
    }));
    if (
      committed.scope !== prepared.scope
      || committed.files !== prepared.files
      || committed.assets !== prepared.assets
      || committed.directories !== prepared.directories
    ) {
      throw new RpcProtocolError("RPC plaintext export commit does not match its prepare result");
    }
  }

  public async umbraStatus(): Promise<UmbraStatus> {
    this.requireUmbraV1();
    return parseUmbraStatus(
      await this.callRaw("umbra.status", this.protectedParams()),
    );
  }

  public async initializeUmbra(password: string): Promise<UmbraStatus> {
    this.requireUmbraV1();
    try {
      return parseUmbraStatus(
        await this.callRaw("umbra.initialize", { ...this.protectedParams(), password }),
      );
    } finally {
      password = "";
    }
  }

  public async unlockUmbra(password: string): Promise<UmbraStatus> {
    this.requireUmbraV1();
    try {
      return parseUmbraStatus(
        await this.callRaw("umbra.unlock", { ...this.protectedParams(), password }),
      );
    } finally {
      password = "";
    }
  }

  public async changeUmbraPassword(password: string): Promise<void> {
    this.requireUmbraV1();
    try {
      expectAcknowledgement(
        await this.callRaw("umbra.password.change", { ...this.protectedParams(), password }),
      );
    } finally {
      password = "";
    }
  }

  public async lockUmbra(): Promise<void> {
    this.requireUmbraV1();
    const result = expectObject(
      await this.callRaw("umbra.lock", this.protectedParams()),
    );
    expectExactKeys(result, ["ok", "unlocked"], "Umbra lock");
    if (result.unlocked !== false) {
      throw new RpcProtocolError("RPC Umbra lock result is invalid");
    }
    expectAcknowledgement(result);
  }

  public async loadUmbraAnnotationConfig(): Promise<UmbraAnnotationConfig> {
    this.requireUmbraV1();
    return parseUmbraAnnotationConfig(
      await this.callRaw("umbra.config.get", this.protectedParams()),
    );
  }

  public async createUmbraTag(tag: Omit<UmbraTagDefinition, "archived">): Promise<void> {
    this.requireUmbraV1();
    const result = await this.callRaw("umbra.tag.create", {
      ...this.protectedParams(),
      tag: serializeUmbraTagDefinition(tag),
    });
    expectAcknowledgement(result);
  }

  public async renameUmbraTag(tagId: string, label: string): Promise<void> {
    this.requireUmbraV1();
    assertUmbraTagId(tagId);
    assertUmbraText(label, "Umbra tag label");
    const result = await this.callRaw("umbra.tag.rename", {
      ...this.protectedParams(),
      tagId,
      label,
    });
    expectAcknowledgement(result);
  }

  public async archiveUmbraTag(tagId: string): Promise<void> {
    this.requireUmbraV1();
    assertUmbraTagId(tagId);
    const result = await this.callRaw("umbra.tag.archive", {
      ...this.protectedParams(),
      tagId,
    });
    expectAcknowledgement(result);
  }

  public async reorderUmbraTags(tagIds: readonly string[]): Promise<void> {
    this.requireUmbraV1();
    if (tagIds.length === 0 || tagIds.length > MAX_UMBRA_TAGS) {
      throw new RpcProtocolError("Umbra tag order is invalid");
    }
    const seen = new Set<string>();
    for (const tagId of tagIds) {
      assertUmbraTagId(tagId);
      if (seen.has(tagId)) throw new RpcProtocolError("Umbra tag order is duplicated");
      seen.add(tagId);
    }
    const result = await this.callRaw("umbra.tag.reorder", {
      ...this.protectedParams(),
      tagIds: [...tagIds],
    });
    expectAcknowledgement(result);
  }

  public async createUmbraAnnotationProfile(profile: UmbraAnnotationProfile): Promise<void> {
    this.requireUmbraV1();
    const result = await this.callRaw("umbra.profile.create", {
      ...this.protectedParams(),
      profile: serializeUmbraProfile(profile),
    });
    expectAcknowledgement(result);
  }

  public async editUmbraAnnotationProfile(
    profileId: string,
    profile: UmbraAnnotationProfile,
  ): Promise<void> {
    this.requireUmbraV1();
    assertUmbraTagId(profileId);
    if (profile.id !== profileId) {
      throw new RpcProtocolError("Umbra profile ID cannot change during edit");
    }
    const result = await this.callRaw("umbra.profile.edit", {
      ...this.protectedParams(),
      profileId,
      profile: serializeUmbraProfile(profile),
    });
    expectAcknowledgement(result);
  }

  public async removeUmbraAnnotationProfile(profileId: string): Promise<void> {
    this.requireUmbraV1();
    assertUmbraTagId(profileId);
    const result = await this.callRaw("umbra.profile.remove", {
      ...this.protectedParams(),
      profileId,
    });
    expectAcknowledgement(result);
  }

  public async setUmbraDefaultAnnotationProfile(profileId: string): Promise<void> {
    this.requireUmbraV1();
    if (profileId !== "") {
      assertUmbraTagId(profileId);
    }
    const result = await this.callRaw("umbra.profile.setDefault", {
      ...this.protectedParams(),
      profileId,
    });
    expectAcknowledgement(result);
  }

  public async enableUmbra(): Promise<"synced" | "notSynced"> {
    this.requireUmbraV1();
    const result = expectObject(
      await this.callRaw("umbra.enable", this.protectedParams()),
    );
    expectExactKeys(result, ["durability", "ok"], "Umbra enable");
    expectAcknowledgement(result);
    return expectDurability(result.durability, "Umbra enable durability");
  }

  public async convertDocumentToUmbra(
    logicalPath: string,
    ifMatch: string,
  ): Promise<WriteResult> {
    this.requireUmbraV1();
    logicalFileComponents(logicalPath);
    validateEtag(ifMatch);
    return parseWriteResult(
      await this.callRaw("umbra.document.convert", {
        ...this.protectedParams(),
        logicalPath,
        ifMatch,
      }),
      logicalPath,
    );
  }

  public async openUmbraDocument(logicalPath: string): Promise<UmbraProjection> {
    this.requireUmbraV1();
    logicalFileComponents(logicalPath);
    return parseUmbraProjection(
      await this.callRaw("umbra.document.open", {
        ...this.protectedParams(),
        logicalPath,
      }),
      logicalPath,
    );
  }

  public async applyUmbraAnnotation(
    logicalPath: string,
    projection: UmbraProjection,
    selections: readonly TextRange[],
    spec: PrivateAnnotationSpec,
    mergeAdjacent = false,
  ): Promise<UmbraAnnotationResult> {
    this.requireUmbraV1();
    logicalFileComponents(logicalPath);
    validateEtag(projection.etag);
    const content = Buffer.from(projection.content);
    const contentBase64 = content.toString("base64url");
    content.fill(0);
    const result = await this.callRaw("umbra.annotation.apply", {
      ...this.protectedParams(),
      logicalPath,
      ifMatch: projection.etag,
      contentBase64,
      renderMap: serializeRenderMap(projection.renderMap),
      selections: selections.map(serializeRange),
      spec: serializeAnnotationSpec(spec),
      mergeAdjacent,
    });
    return parseUmbraAnnotationResult(result, logicalPath);
  }

  public async removeUmbraAnnotation(
    logicalPath: string,
    projection: UmbraProjection,
    selections: readonly TextRange[],
    mergeAdjacent = false,
  ): Promise<UmbraAnnotationResult> {
    this.requireUmbraV1();
    logicalFileComponents(logicalPath);
    validateEtag(projection.etag);
    const content = Buffer.from(projection.content);
    const contentBase64 = content.toString("base64url");
    content.fill(0);
    const result = await this.callRaw("umbra.annotation.remove", {
      ...this.protectedParams(),
      logicalPath,
      ifMatch: projection.etag,
      contentBase64,
      renderMap: serializeRenderMap(projection.renderMap),
      selections: selections.map(serializeRange),
      mergeAdjacent,
    });
    return parseUmbraAnnotationResult(result, logicalPath);
  }

  public async editUmbraAnnotation(
    logicalPath: string,
    projection: UmbraProjection,
    selections: readonly TextRange[],
    spec: PrivateAnnotationSpec,
    mergeAdjacent = false,
  ): Promise<UmbraAnnotationResult> {
    this.requireUmbraV1();
    logicalFileComponents(logicalPath);
    validateEtag(projection.etag);
    const content = Buffer.from(projection.content);
    const contentBase64 = content.toString("base64url");
    content.fill(0);
    const result = await this.callRaw("umbra.annotation.edit", {
      ...this.protectedParams(),
      logicalPath,
      ifMatch: projection.etag,
      contentBase64,
      renderMap: serializeRenderMap(projection.renderMap),
      selections: selections.map(serializeRange),
      spec: serializeAnnotationSpec(spec),
      mergeAdjacent,
    });
    return parseUmbraAnnotationResult(result, logicalPath);
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
      if (kind !== "directory" && kind !== "file" && kind !== "asset") {
        throw new RpcProtocolError("RPC tree entry kind is invalid");
      }
      if (kind === "asset" && !this.canReadOpaqueAssetsV1) {
        throw new RpcProtocolError(
          "RPC returned an asset without negotiated authenticated support",
        );
      }
      return {
        kind,
        logicalPath:
          kind === "file"
            ? expectLogicalFile(object.logicalPath, "tree logical path")
            : kind === "asset"
              ? expectAssetPath(object.logicalPath, "tree logical path")
              : expectLogicalDirectory(object.logicalPath, "tree logical path"),
      };
    });
  }

  public async openAsset(logicalPath: string): Promise<AssetOpenResult> {
    this.requireOpaqueAssetsV1();
    assetPathComponents(logicalPath);
    let value: JsonValue;
    try {
      value = await this.callRaw("asset.open", {
        ...this.protectedParams(),
        logicalPath,
      });
    } catch (error: unknown) {
      const normalized = asError(error);
      if (normalized instanceof RpcProtocolError) {
        this.failTerminal(normalized);
      }
      throw normalized;
    }
    try {
      return parseAssetOpenResult(value, logicalPath);
    } catch (error: unknown) {
      // The daemon may already own a fully authenticated plaintext handle,
      // but an invalid result can make that capability unknowable. Terminate
      // the process so its session store is destroyed rather than leaking an
      // allocation that the client can no longer close.
      const normalized = asError(error);
      this.failTerminal(normalized);
      throw normalized;
    }
  }

  public async readAssetChunk(
    handle: string,
    offset: number,
    maxBytes = MAX_ASSET_CHUNK_BYTES,
  ): Promise<AssetChunkResult> {
    this.requireOpaqueAssetsV1();
    expectCapability(handle, "asset handle", 22);
    if (
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      offset > MAX_ASSET_BYTES ||
      !Number.isSafeInteger(maxBytes) ||
      maxBytes < 1 ||
      maxBytes > MAX_ASSET_CHUNK_BYTES
    ) {
      throw new RpcProtocolError("Asset chunk request is outside the v1 range");
    }
    return parseAssetChunkResult(
      await this.callRaw("asset.readChunk", {
        ...this.protectedParams(),
        handle,
        offset,
        maxBytes,
      }),
      offset,
      maxBytes,
    );
  }

  public async closeAsset(handle: string): Promise<void> {
    this.requireOpaqueAssetsV1();
    expectCapability(handle, "asset handle", 22);
    try {
      expectAcknowledgement(
        await this.callRaw("asset.close", { ...this.protectedParams(), handle }),
      );
    } catch (error: unknown) {
      const normalized = asError(error);
      if (
        !(normalized instanceof RpcRemoteError) ||
        normalized.stableName !== "SESSION_INVALID"
      ) {
        // Any other failure leaves the disposition of a sensitive daemon-owned
        // allocation unknown. A terminal transport teardown is the only safe
        // recovery boundary.
        this.failTerminal(normalized);
      }
      throw normalized;
    }
  }

  public async read(logicalPath: string): Promise<ReadResult> {
    logicalFileComponents(logicalPath);
    const result = await this.callRaw("file.read", {
      ...this.protectedParams(),
      logicalPath,
    });
    return parseRead(result, logicalPath);
  }

  public async stat(logicalPath: string): Promise<StatResult> {
    logicalFileComponents(logicalPath);
    return parseStatResult(
      await this.callRaw("file.stat", {
        ...this.protectedParams(),
        logicalPath,
      }),
      logicalPath,
    );
  }

  public async write(
    logicalPath: string,
    content: Uint8Array,
    condition: { readonly ifMatch: string } | { readonly ifNoneMatch: "*" },
  ): Promise<WriteResult> {
    logicalFileComponents(logicalPath);
    if ("ifMatch" in condition) {
      validateEtag(condition.ifMatch);
    }
    const plaintext = Buffer.from(content);
    const contentBase64 = plaintext.toString("base64url");
    plaintext.fill(0);
    const params: JsonObject = {
      ...this.protectedParams(),
      logicalPath,
      contentBase64,
      ...condition,
    };
    return parseWriteResult(await this.callRaw("file.write", params), logicalPath);
  }

  public async mkdir(logicalPath: string): Promise<void> {
    const components = logicalDirectoryComponents(logicalPath);
    if (components.length === 0) {
      throw new LogicalPathError("The vault root already exists");
    }
    const result = expectObject(
      await this.callRaw("file.mkdir", {
        ...this.protectedParams(),
        logicalPath,
      }),
    );
    expectExactKeys(result, ["ok"], "directory creation");
    expectAcknowledgement(result);
  }

  public async renameFile(
    source: string,
    destination: string,
    sourceEtag: string,
  ): Promise<RenameResult> {
    logicalFileComponents(source);
    logicalFileComponents(destination);
    validateEtag(sourceEtag);
    if (source === destination) {
      throw new LogicalPathError("Rename destination must differ from the source");
    }
    return parseRenameResult(
      await this.callRaw("file.rename", {
        ...this.protectedParams(),
        from: source,
        to: destination,
        sourceEtag,
        destinationIfNoneMatch: "*",
      }),
      destination,
    );
  }

  public async deleteFile(
    logicalPath: string,
    ifMatch: string,
  ): Promise<DeleteResult> {
    logicalFileComponents(logicalPath);
    validateEtag(ifMatch);
    return parseDeleteResult(
      await this.callRaw("file.delete", {
        ...this.protectedParams(),
        logicalPath,
        ifMatch,
        recursive: false,
      }),
    );
  }

  public async openDocument(logicalPath: string): Promise<OpenResult> {
    logicalFileComponents(logicalPath);
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
      logicalFileComponents(logicalPath);
      params.logicalPath = logicalPath;
    }
    expectAcknowledgement(await this.callRaw("cache.evict", params));
  }

  public async search(query: string, limit = 50): Promise<readonly SearchHit[]> {
    return this.searchWithMethod("search.query", query, limit);
  }

  /** Search full Umbra projections while the independent Umbra session is unlocked. */
  public async searchUmbra(query: string, limit = 50): Promise<readonly SearchHit[]> {
    return this.searchWithMethod("umbra.search.query", query, limit);
  }

  private async searchWithMethod(
    method: "search.query" | "umbra.search.query",
    query: string,
    limit: number,
  ): Promise<readonly SearchHit[]> {
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
      await this.callRaw(method, {
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
      this.authenticatedOpaqueAssetsV1 = false;
      return;
    }
    try {
      expectAcknowledgement(await this.callRaw("system.shutdown", {}));
    } finally {
      this.session = undefined;
      this.authenticatedOpaqueAssetsV1 = false;
    }
  }

  public dispose(): void {
    this.session = undefined;
    this.authenticatedOpaqueAssetsV1 = false;
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

  private requireUmbraV1(): void {
    this.requireSession();
    if (!this.negotiatedUmbraV1) {
      throw new RpcProtocolError("Inex sidecar does not support Umbra v1");
    }
  }

  private requireSession(): string {
    if (this.session === undefined) {
      throw new SidecarLifecycleError("Inex vault is locked");
    }
    return this.session;
  }

  private requireOpaqueAssetsV1(): void {
    this.requireSession();
    if (!this.negotiatedOpaqueAssetsV1 || !this.authenticatedOpaqueAssetsV1) {
      throw new SidecarLifecycleError(
        "Opaque assets are unavailable for this sidecar or authenticated vault",
      );
    }
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
    this.authenticatedOpaqueAssetsV1 = false;
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
    this.authenticatedOpaqueAssetsV1 = false;
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
    method.startsWith("asset.") ||
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

function parseUmbraStatus(value: JsonValue): UmbraStatus {
  const result = expectObject(value);
  expectExactKeys(result, ["initialized", "unlocked"], "Umbra status");
  if (typeof result.initialized !== "boolean" || typeof result.unlocked !== "boolean") {
    throw new RpcProtocolError("RPC Umbra status is invalid");
  }
  return { initialized: result.initialized, unlocked: result.unlocked };
}

/** @internal Exported for exact encrypted Umbra config protocol-shape tests. */
export function parseUmbraAnnotationConfig(value: JsonValue): UmbraAnnotationConfig {
  const result = expectObject(value);
  expectExactKeys(result, ["defaults", "profiles", "tags"], "Umbra config");
  const tags = expectArray(result.tags, "Umbra tags");
  const profiles = expectArray(result.profiles, "Umbra profiles");
  if (tags.length > MAX_UMBRA_TAGS || profiles.length > MAX_UMBRA_PROFILES) {
    throw new RpcProtocolError("RPC Umbra config exceeds v1 limits");
  }
  const parsedTags = tags.map(parseUmbraTag);
  const seenTags = new Set<string>();
  for (const tag of parsedTags) {
    if (seenTags.has(tag.id)) {
      throw new RpcProtocolError("RPC Umbra tag IDs are duplicated");
    }
    seenTags.add(tag.id);
  }
  const parsedProfiles = profiles.map((profile) => parseUmbraProfile(profile, seenTags));
  const seenProfiles = new Set<string>();
  for (const profile of parsedProfiles) {
    if (seenProfiles.has(profile.id)) {
      throw new RpcProtocolError("RPC Umbra profile IDs are duplicated");
    }
    seenProfiles.add(profile.id);
  }
  const defaults = expectObject(result.defaults);
  expectExactKeys(defaults, ["defaultProfileId", "kind", "outer", "tagIds"], "Umbra defaults");
  const defaultProfileId = expectUmbraId(defaults.defaultProfileId, "Umbra default profile ID", true);
  if (defaultProfileId !== "" && !seenProfiles.has(defaultProfileId)) {
    throw new RpcProtocolError("RPC Umbra default profile is unavailable");
  }
  return {
    tags: parsedTags,
    profiles: parsedProfiles,
    defaults: {
      kind: expectAnnotationKind(defaults.kind, "Umbra default kind"),
      tagIds: parseUmbraTagIds(defaults.tagIds, seenTags, "Umbra default tags"),
      outer: expectOuterMode(defaults.outer, "Umbra default outer mode"),
      defaultProfileId,
    },
  };
}

function parseUmbraTag(value: JsonValue): UmbraTagDefinition {
  const tag = expectObject(value);
  expectExactKeys(
    tag,
    ["aliases", "archived", "defaultSelected", "description", "id", "label", "sortOrder"],
    "Umbra tag",
  );
  if (typeof tag.defaultSelected !== "boolean" || typeof tag.archived !== "boolean") {
    throw new RpcProtocolError("RPC Umbra tag flags are invalid");
  }
  const aliases = expectArray(tag.aliases, "Umbra tag aliases");
  if (aliases.length > MAX_UMBRA_TAGS) {
    throw new RpcProtocolError("RPC Umbra tag aliases exceed v1 limits");
  }
  return {
    id: expectUmbraId(tag.id, "Umbra tag ID"),
    label: expectBoundedString(tag.label, "Umbra tag label", MAX_UMBRA_TEXT_BYTES),
    description: expectBoundedString(tag.description, "Umbra tag description", MAX_UMBRA_TEXT_BYTES),
    aliases: aliases.map((alias) => expectBoundedString(alias, "Umbra tag alias", MAX_UMBRA_TEXT_BYTES)),
    sortOrder: expectSafeInteger(tag.sortOrder, "Umbra tag sort order"),
    defaultSelected: tag.defaultSelected,
    archived: tag.archived,
  };
}

function serializeUmbraTagDefinition(tag: Omit<UmbraTagDefinition, "archived">): JsonObject {
  assertUmbraTagId(tag.id);
  assertUmbraText(tag.label, "Umbra tag label");
  if (Buffer.byteLength(tag.description, "utf8") > MAX_UMBRA_TEXT_BYTES) {
    throw new RpcProtocolError("Umbra tag description is invalid");
  }
  if (tag.aliases.length > MAX_UMBRA_TAGS || !Number.isSafeInteger(tag.sortOrder)) {
    throw new RpcProtocolError("Umbra tag fields are invalid");
  }
  for (const alias of tag.aliases) assertUmbraText(alias, "Umbra tag alias");
  return {
    id: tag.id,
    label: tag.label,
    description: tag.description,
    aliases: [...tag.aliases],
    sortOrder: tag.sortOrder,
    defaultSelected: tag.defaultSelected,
  };
}

function serializeUmbraProfile(profile: UmbraAnnotationProfile): JsonObject {
  assertUmbraTagId(profile.id);
  assertUmbraText(profile.label, "Umbra profile label");
  if (profile.kind !== "block" && profile.kind !== "comment") {
    throw new RpcProtocolError("Umbra profile kind is invalid");
  }
  if (profile.outer !== "drop" && profile.outer !== "cover" && profile.outer !== "placeholder") {
    throw new RpcProtocolError("Umbra profile outer mode is invalid");
  }
  if ((profile.outer === "cover") !== profile.promptForCover) {
    throw new RpcProtocolError("Umbra profile cover prompt is invalid");
  }
  const tagIds = [...profile.tagIds];
  if (
    tagIds.length > MAX_UMBRA_TAGS ||
    tagIds.some((tagId, index) =>
      !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(tagId) || (index > 0 && tagIds[index - 1]! >= tagId),
    )
  ) {
    throw new RpcProtocolError("Umbra profile tags are invalid");
  }
  return {
    id: profile.id,
    label: profile.label,
    kind: profile.kind,
    tagIds,
    outer: profile.outer,
    promptForCover: profile.promptForCover,
  };
}

function assertUmbraTagId(tagId: string): void {
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(tagId)) {
    throw new RpcProtocolError("Umbra tag ID is invalid");
  }
}

function assertUmbraText(value: string, field: string): void {
  if (Buffer.byteLength(value, "utf8") < 1 || Buffer.byteLength(value, "utf8") > MAX_UMBRA_TEXT_BYTES) {
    throw new RpcProtocolError(`RPC ${field} is invalid`);
  }
}

function parseUmbraProfile(
  value: JsonValue,
  availableTagIds: ReadonlySet<string>,
): UmbraAnnotationProfile {
  const profile = expectObject(value);
  expectExactKeys(
    profile,
    ["id", "kind", "label", "outer", "promptForCover", "tagIds"],
    "Umbra profile",
  );
  if (typeof profile.promptForCover !== "boolean") {
    throw new RpcProtocolError("RPC Umbra profile cover flag is invalid");
  }
  return {
    id: expectUmbraId(profile.id, "Umbra profile ID"),
    label: expectBoundedString(profile.label, "Umbra profile label", MAX_UMBRA_TEXT_BYTES),
    kind: expectAnnotationKind(profile.kind, "Umbra profile kind"),
    tagIds: parseUmbraTagIds(profile.tagIds, availableTagIds, "Umbra profile tags"),
    outer: expectOuterMode(profile.outer, "Umbra profile outer mode"),
    promptForCover: profile.promptForCover,
  };
}

function parseUmbraTagIds(
  value: JsonValue | undefined,
  availableTagIds: ReadonlySet<string>,
  field: string,
): readonly string[] {
  const tags = expectArray(value, field);
  if (tags.length > MAX_UMBRA_TAGS) {
    throw new RpcProtocolError(`RPC ${field} exceeds v1 limits`);
  }
  const ids = tags.map((tag) => expectUmbraId(tag, field));
  if (
    ids.some((id, index) => (index > 0 && ids[index - 1]! >= id) || !availableTagIds.has(id))
  ) {
    throw new RpcProtocolError(`RPC ${field} are not canonical or available`);
  }
  return ids;
}

function expectUmbraId(
  value: JsonValue | undefined,
  field: string,
  allowEmpty = false,
): string {
  const id = expectString(value, field);
  if ((allowEmpty && id === "") || /^[a-z0-9][a-z0-9._-]{0,63}$/.test(id)) {
    return id;
  }
  throw new RpcProtocolError(`RPC ${field} is invalid`);
}

function expectAnnotationKind(
  value: JsonValue | undefined,
  field: string,
): PrivateAnnotationKind {
  const kind = expectString(value, field);
  if (kind === "block" || kind === "comment") {
    return kind;
  }
  throw new RpcProtocolError(`RPC ${field} is invalid`);
}

function expectOuterMode(value: JsonValue | undefined, field: string): OuterMode {
  const outer = expectString(value, field);
  if (outer === "drop" || outer === "cover" || outer === "placeholder") {
    return outer;
  }
  throw new RpcProtocolError(`RPC ${field} is invalid`);
}

/** @internal Exported for exact Umbra protocol-shape regression tests. */
export function parseUmbraProjection(
  value: JsonValue,
  expectedLogicalPath: string,
): UmbraProjection {
  const result = expectObject(value);
  expectExactKeys(result, ["contentBase64", "etag", "metadata", "renderMap"], "Umbra document open");
  const content = decodeCanonicalBase64url(
    expectString(result.contentBase64, "Umbra projection"),
    MAX_DOCUMENT_BYTES,
  );
  try {
    const etag = expectEtag(result.etag, "Umbra document etag");
    const renderMap = parseRenderMap(result.renderMap);
    if (content.byteLength !== renderMap.projectionBytes) {
      throw new RpcProtocolError("RPC Umbra projection length does not match its RenderMap");
    }
    logicalFileComponents(expectedLogicalPath);
    return { content, etag, metadata: parseMetadata(result.metadata, expectedLogicalPath), renderMap };
  } catch (error: unknown) {
    content.fill(0);
    throw error;
  }
}

/** @internal Exported for exact Umbra protocol-shape regression tests. */
export function parseUmbraAnnotationResult(
  value: JsonValue,
  expectedLogicalPath: string,
): UmbraAnnotationResult {
  const result = expectObject(value);
  expectExactKeys(
    result,
    ["contentBase64", "durability", "etag", "metadata", "renderMap"],
    "Umbra annotation result",
  );
  const projection = parseUmbraProjection(
    {
      contentBase64: result.contentBase64 ?? null,
      etag: result.etag ?? null,
      metadata: result.metadata ?? null,
      renderMap: result.renderMap ?? null,
    },
    expectedLogicalPath,
  );
  try {
    return {
      ...projection,
      metadata: parseMetadata(result.metadata, expectedLogicalPath),
      durability: expectDurability(result.durability, "Umbra annotation durability"),
    };
  } catch (error: unknown) {
    projection.content.fill(0);
    projection.renderMap.generation.fill(0);
    throw error;
  }
}

function parseRenderMap(value: JsonValue | undefined): RenderMap {
  const map = expectObject(value);
  expectExactKeys(
    map,
    ["generationBase64", "outerSegments", "privateSlots", "projectionBytes"],
    "Umbra RenderMap",
  );
  const generation = decodeCanonicalBase64url(
    expectString(map.generationBase64, "Umbra RenderMap generation"),
    32,
  );
  if (generation.byteLength !== 32) {
    generation.fill(0);
    throw new RpcProtocolError("RPC Umbra RenderMap generation is invalid");
  }
  try {
    const projectionBytes = expectSafeInteger(map.projectionBytes, "Umbra projection length");
    if (projectionBytes < 0 || projectionBytes > MAX_DOCUMENT_BYTES) {
      throw new RpcProtocolError("RPC Umbra projection length is outside the v1 range");
    }
    const privateSlots = expectArray(map.privateSlots, "Umbra private slots").map((value) => {
      const slot = expectObject(value);
      expectExactKeys(slot, ["endByte", "slotId", "startByte"], "Umbra private slot");
      return {
        slotId: expectString(slot.slotId, "Umbra slot id"),
        range: parseRange(slot.startByte, slot.endByte, "Umbra private slot range"),
      };
    });
    const outerSegments = expectArray(map.outerSegments, "Umbra outer segments").map((value) => {
      const segment = expectObject(value);
      expectExactKeys(
        segment,
        ["outerEndByte", "outerStartByte", "projectionEndByte", "projectionStartByte"],
        "Umbra outer segment",
      );
      return {
        projectionRange: parseRange(
          segment.projectionStartByte,
          segment.projectionEndByte,
          "Umbra projection segment",
        ),
        outerRange: parseRange(segment.outerStartByte, segment.outerEndByte, "Umbra outer range"),
      };
    });
    return { generation, projectionBytes, privateSlots, outerSegments };
  } catch (error: unknown) {
    generation.fill(0);
    throw error;
  }
}

function parseRange(start: JsonValue | undefined, end: JsonValue | undefined, field: string): TextRange {
  const startByte = expectSafeInteger(start, field);
  const endByte = expectSafeInteger(end, field);
  if (startByte < 0 || endByte <= startByte || endByte > MAX_DOCUMENT_BYTES) {
    throw new RpcProtocolError("RPC Umbra range is invalid");
  }
  return { startByte, endByte };
}

function serializeRange(range: TextRange): JsonObject {
  if (
    !Number.isSafeInteger(range.startByte) ||
    !Number.isSafeInteger(range.endByte) ||
    range.startByte < 0 ||
    range.endByte <= range.startByte ||
    range.endByte > MAX_DOCUMENT_BYTES
  ) {
    throw new RpcProtocolError("Umbra range is invalid");
  }
  return { startByte: range.startByte, endByte: range.endByte };
}

function serializeRenderMap(renderMap: RenderMap): JsonObject {
  if (renderMap.generation.byteLength !== 32 || renderMap.projectionBytes < 0) {
    throw new RpcProtocolError("Umbra RenderMap is invalid");
  }
  return {
    generationBase64: renderMap.generation.toString("base64url"),
    projectionBytes: renderMap.projectionBytes,
    privateSlots: renderMap.privateSlots.map((slot) => ({
      slotId: slot.slotId,
      ...serializeRange(slot.range),
    })),
    outerSegments: renderMap.outerSegments.map((segment) => ({
      projectionStartByte: segment.projectionRange.startByte,
      projectionEndByte: segment.projectionRange.endByte,
      outerStartByte: segment.outerRange.startByte,
      outerEndByte: segment.outerRange.endByte,
    })),
  };
}

function serializeAnnotationSpec(spec: PrivateAnnotationSpec): JsonObject {
  if (
    (spec.kind !== "block" && spec.kind !== "comment") ||
    (spec.outer.mode !== "drop" && spec.outer.mode !== "cover" && spec.outer.mode !== "placeholder") ||
    spec.tagIds.some((tag) => !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(tag)) ||
    !spec.tagIds.every((tag, index) => index === 0 || spec.tagIds[index - 1]! < tag) ||
    (spec.outer.mode === "cover") !== (spec.outer.coverText !== undefined) ||
    spec.outer.coverText === ""
  ) {
    throw new RpcProtocolError("Umbra annotation spec is invalid");
  }
  const outer: JsonObject = { mode: spec.outer.mode };
  if (spec.outer.coverText !== undefined) {
    outer.coverText = spec.outer.coverText;
  }
  return { kind: spec.kind, tagIds: [...spec.tagIds], outer };
}

/** @internal Exported for exact protocol-shape regression tests. */
export function parseAssetOpenResult(
  value: JsonValue,
  expectedLogicalPath: string,
): AssetOpenResult {
  assetPathComponents(expectedLogicalPath);
  const result = expectObject(value);
  expectExactKeys(result, ["etag", "handle", "metadata", "size"], "asset open");
  const size = expectSafeInteger(result.size, "asset size");
  if (size < 0 || size > MAX_ASSET_BYTES) {
    throw new RpcProtocolError("RPC asset size is outside the v1 range");
  }
  return {
    handle: expectCapability(result.handle, "asset handle", 22),
    size,
    etag: expectEtag(result.etag, "asset etag"),
    metadata: parseAssetMetadata(result.metadata, expectedLogicalPath),
  };
}

/** @internal Exported for exact protocol-shape regression tests. */
export function parseAssetChunkResult(
  value: JsonValue,
  expectedOffset: number,
  maximumBytes: number,
): AssetChunkResult {
  if (
    !Number.isSafeInteger(expectedOffset) ||
    expectedOffset < 0 ||
    expectedOffset > MAX_ASSET_BYTES ||
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > MAX_ASSET_CHUNK_BYTES
  ) {
    throw new RpcProtocolError("Asset chunk expectation is outside the v1 range");
  }
  const result = expectObject(value);
  expectExactKeys(result, ["contentBase64", "eof", "offset"], "asset chunk");
  const offset = expectSafeInteger(result.offset, "asset chunk offset");
  if (offset !== expectedOffset || typeof result.eof !== "boolean") {
    throw new RpcProtocolError("RPC asset chunk sequencing is invalid");
  }
  const content = decodeCanonicalBase64url(
    expectString(result.contentBase64, "asset chunk"),
    maximumBytes,
  );
  if (
    offset + content.byteLength > MAX_ASSET_BYTES ||
    (content.byteLength === 0 && result.eof !== true)
  ) {
    content.fill(0);
    throw new RpcProtocolError("RPC asset chunk range is invalid");
  }
  return { offset, content, eof: result.eof };
}

/** @internal Exported so protocol-shape tests can exercise the frozen v1 contract. */
export function parseStatResult(
  value: JsonValue,
  expectedLogicalPath: string,
): StatResult {
  logicalFileComponents(expectedLogicalPath);
  const result = expectObject(value);
  expectExactKeys(result, ["etag", "metadata", "size", "type"], "file stat");
  if (result.type !== "file") {
    throw new RpcProtocolError("RPC stat entry type is invalid");
  }
  const size = expectSafeInteger(result.size, "file size");
  if (size < 0 || size > MAX_DOCUMENT_BYTES) {
    throw new RpcProtocolError("RPC file size is outside the v1 range");
  }
  return {
    size,
    etag: expectEtag(result.etag, "stat etag"),
    metadata: parseMetadata(result.metadata, expectedLogicalPath),
  };
}

/** @internal Exported so protocol-shape tests can exercise the frozen v1 contract. */
export function parseWriteResult(
  value: JsonValue,
  expectedLogicalPath: string,
): WriteResult {
  logicalFileComponents(expectedLogicalPath);
  const result = expectObject(value);
  expectExactKeys(result, ["durability", "etag", "metadata"], "file write");
  return {
    etag: expectEtag(result.etag, "write etag"),
    metadata: parseMetadata(result.metadata, expectedLogicalPath),
    durability: expectDurability(result.durability, "write durability"),
  };
}

/** @internal Exported so protocol-shape tests can exercise the frozen v1 contract. */
export function parseRenameResult(
  value: JsonValue,
  expectedLogicalPath: string,
): RenameResult {
  logicalFileComponents(expectedLogicalPath);
  const result = expectObject(value);
  expectExactKeys(
    result,
    ["destinationDurability", "etag", "metadata", "sourceDurability"],
    "file rename",
  );
  return {
    etag: expectEtag(result.etag, "rename etag"),
    metadata: parseMetadata(result.metadata, expectedLogicalPath),
    sourceDurability: expectDurability(
      result.sourceDurability,
      "rename source durability",
    ),
    destinationDurability: expectDurability(
      result.destinationDurability,
      "rename destination durability",
    ),
  };
}

/** @internal Exported so protocol-shape tests can exercise the frozen v1 contract. */
export function parseDeleteResult(value: JsonValue): DeleteResult {
  const result = expectObject(value);
  expectExactKeys(result, ["durability", "ok"], "file delete");
  expectAcknowledgement(result);
  return {
    durability: expectDurability(result.durability, "delete durability"),
  };
}

export interface PlaintextExportCommit {
  readonly scope: "outer" | "umbra";
  readonly files: number;
  readonly assets: number;
  readonly directories: number;
}

/** @internal Exported so protocol-shape tests can exercise the frozen v1 contract. */
export function parsePlaintextExportPrepare(
  value: JsonValue,
  expectedScope: "outer" | "umbra",
): PlaintextExportPrepare {
  const result = expectObject(value);
  expectExactKeys(
    result,
    ["assets", "confirmation", "directories", "files", "scope"],
    "plaintext export prepare",
  );
  const scope = expectPlaintextExportScope(result.scope, "prepare");
  if (scope !== expectedScope) {
    throw new RpcProtocolError("RPC plaintext export scope is invalid");
  }
  return {
    confirmation: expectCapability(result.confirmation, "plaintext export confirmation", 43),
    scope,
    files: expectNonNegativeSafeInteger(result.files, "plaintext export files"),
    assets: expectNonNegativeSafeInteger(result.assets, "plaintext export assets"),
    directories: expectNonNegativeSafeInteger(result.directories, "plaintext export directories"),
  };
}

/** @internal Exported so protocol-shape tests can exercise the frozen v1 contract. */
export function parsePlaintextExportCommit(value: JsonValue): PlaintextExportCommit {
  const result = expectObject(value);
  expectExactKeys(
    result,
    ["assets", "directories", "durability", "files", "ok", "scope"],
    "plaintext export commit",
  );
  if (result.ok !== true) {
    throw new RpcProtocolError("RPC plaintext export commit is invalid");
  }
  expectDurability(result.durability, "plaintext export durability");
  return {
    scope: expectPlaintextExportScope(result.scope, "commit"),
    files: expectNonNegativeSafeInteger(result.files, "plaintext export files"),
    assets: expectNonNegativeSafeInteger(result.assets, "plaintext export assets"),
    directories: expectNonNegativeSafeInteger(result.directories, "plaintext export directories"),
  };
}

function parseMetadata(
  value: JsonValue | undefined,
  expectedLogicalPath: string,
): DocumentMetadata {
  return parseMetadataWithPath(value, expectedLogicalPath, expectLogicalFile);
}

function parseAssetMetadata(
  value: JsonValue | undefined,
  expectedLogicalPath: string,
): DocumentMetadata {
  return parseMetadataWithPath(value, expectedLogicalPath, expectAssetPath);
}

function parseMetadataWithPath(
  value: JsonValue | undefined,
  expectedLogicalPath: string,
  pathParser: (value: JsonValue | undefined, field: string) => string,
): DocumentMetadata {
  const metadata = expectObject(value);
  expectExactKeys(
    metadata,
    ["createdAt", "fileId", "flags", "logicalPath", "modifiedAt"],
    "document metadata",
  );
  const logicalPath = pathParser(metadata.logicalPath, "metadata logical path");
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

function expectAssetPath(value: JsonValue | undefined, _field: string): string {
  const text = expectString(value, _field);
  try {
    assetPathComponents(text);
  } catch (error: unknown) {
    if (error instanceof LogicalPathError) {
      throw new RpcProtocolError("RPC logical asset path is invalid");
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

function validateEtag(value: string): void {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) {
    throw new RpcProtocolError("RPC request etag is invalid");
  }
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

function expectDurability(
  value: JsonValue | undefined,
  field: string,
): "synced" | "notSynced" {
  const durability = expectString(value, field);
  if (durability !== "synced" && durability !== "notSynced") {
    throw new RpcProtocolError(`RPC ${field} is invalid`);
  }
  return durability;
}

function expectExactKeys(
  value: { [key: string]: JsonValue },
  expected: readonly string[],
  resultName: string,
): void {
  const keys = Object.keys(value).sort();
  if (
    keys.length !== expected.length ||
    keys.some((key, index) => key !== expected[index])
  ) {
    throw new RpcProtocolError(`RPC ${resultName} result has unknown or missing fields`);
  }
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

function expectNonNegativeSafeInteger(value: JsonValue | undefined, field: string): number {
  const integer = expectSafeInteger(value, field);
  if (integer < 0) {
    throw new RpcProtocolError(`RPC ${field} is invalid`);
  }
  return integer;
}

function expectPlaintextExportScope(
  value: JsonValue | undefined,
  phase: "prepare" | "commit",
): "outer" | "umbra" {
  if (value !== "outer" && value !== "umbra") {
    throw new RpcProtocolError(`RPC plaintext export ${phase} scope is invalid`);
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
