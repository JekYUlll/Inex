import { TextDecoder } from "node:util";

export const MAX_FRAME_BYTES = 24 * 1024 * 1024;
export const MAX_HEADER_BYTES = 8 * 1024;
const MAX_TRANSPORT_CHUNK_BYTES = MAX_FRAME_BYTES + MAX_HEADER_BYTES;
const MAX_BUFFERED_TRANSPORT_BYTES = 2 * MAX_TRANSPORT_CHUNK_BYTES;

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export type JsonObject = { [key: string]: JsonValue };
export type RpcId = number | string;

export interface RpcErrorObject {
  readonly code: number;
  readonly message: string;
  readonly data: Readonly<{ name: string; [key: string]: JsonValue }>;
}

export type RpcResponse =
  | { readonly jsonrpc: "2.0"; readonly id: RpcId; readonly result: JsonValue }
  | { readonly jsonrpc: "2.0"; readonly id: RpcId | null; readonly error: RpcErrorObject };

export class RpcProtocolError extends Error {
  public override readonly name = "RpcProtocolError";

  public constructor(message: string) {
    super(message);
  }
}

export class RpcRemoteError extends Error {
  public override readonly name = "RpcRemoteError";
  public readonly code: number;
  public readonly stableName: string;

  public constructor(code: number, stableName: string, message: string) {
    super(message);
    this.code = code;
    this.stableName = stableName;
  }
}

export class FrameDecoder {
  private pending = Buffer.alloc(0);
  private expectedBodyBytes: number | undefined;

  public push(chunk: Uint8Array): RpcResponse[] {
    if (chunk.byteLength === 0) {
      return [];
    }
    const previous = this.pending;
    if (
      chunk.byteLength > MAX_TRANSPORT_CHUNK_BYTES ||
      previous.byteLength > MAX_BUFFERED_TRANSPORT_BYTES - chunk.byteLength
    ) {
      this.fail("RPC response transport chunk exceeds its byte limit");
    }
    this.pending = Buffer.concat([previous, chunk]);
    previous.fill(0);
    const responses: RpcResponse[] = [];
    while (true) {
      if (this.expectedBodyBytes === undefined) {
        const boundary = this.pending.indexOf("\r\n\r\n", 0, "ascii");
        if (boundary < 0) {
          if (this.pending.byteLength > MAX_HEADER_BYTES) {
            this.fail("RPC response header exceeds its byte limit");
          }
          break;
        }
        if (boundary + 4 > MAX_HEADER_BYTES) {
          this.fail("RPC response header exceeds its byte limit");
        }
        const complete = this.pending;
        const header = complete.subarray(0, boundary);
        try {
          this.expectedBodyBytes = parseContentLength(header);
        } catch (error: unknown) {
          this.clear();
          throw error;
        }
        this.pending = complete.subarray(boundary + 4);
        complete.subarray(0, boundary + 4).fill(0);
      }

      const expected = this.expectedBodyBytes;
      if (expected === undefined || this.pending.byteLength < expected) {
        break;
      }
      const body = this.pending.subarray(0, expected);
      this.pending = this.pending.subarray(expected);
      this.expectedBodyBytes = undefined;
      try {
        responses.push(parseResponseBody(body));
      } finally {
        body.fill(0);
      }
    }
    return responses;
  }

  public finish(): void {
    if (this.pending.byteLength !== 0 || this.expectedBodyBytes !== undefined) {
      this.fail("RPC response stream ended in a partial frame");
    }
  }

  public clear(): void {
    this.pending.fill(0);
    this.pending = Buffer.alloc(0);
    this.expectedBodyBytes = undefined;
  }

  private fail(message: string): never {
    this.clear();
    throw new RpcProtocolError(message);
  }
}

export function encodeRequest(id: RpcId, method: string, params: JsonObject): Buffer {
  if (!isValidId(id) || method.length === 0) {
    throw new RpcProtocolError("RPC request id or method is invalid");
  }
  let serialized: string;
  try {
    serialized = JSON.stringify({ jsonrpc: "2.0", id, method, params });
  } catch {
    throw new RpcProtocolError("RPC request serialization failed");
  }
  const body = Buffer.from(serialized, "utf8");
  if (body.byteLength > MAX_FRAME_BYTES) {
    body.fill(0);
    throw new RpcProtocolError("RPC request exceeds its byte limit");
  }
  const header = Buffer.from(`Content-Length: ${body.byteLength}\r\n\r\n`, "ascii");
  const frame = Buffer.concat([header, body]);
  body.fill(0);
  return frame;
}

export function responseResult(response: RpcResponse): JsonValue {
  if ("error" in response) {
    const contract = ERROR_CONTRACT.get(response.error.code);
    if (
      contract === undefined ||
      contract.name !== response.error.data.name ||
      contract.message !== response.error.message
    ) {
      throw new RpcProtocolError("RPC error contract is invalid");
    }
    throw new RpcRemoteError(
      response.error.code,
      response.error.data.name,
      contract.message,
    );
  }
  return response.result;
}

function parseContentLength(header: Buffer): number {
  for (const byte of header) {
    if (byte > 0x7f) {
      throw new RpcProtocolError("RPC response header is not ASCII");
    }
  }
  const lines = header.toString("ascii").split("\r\n");
  if (lines.length !== 1) {
    throw new RpcProtocolError("RPC response has unsupported headers");
  }
  const match = /^[ \t]*content-length[ \t]*:[ \t]*([0-9]+)[ \t]*$/iu.exec(lines[0] ?? "");
  if (match === null) {
    throw new RpcProtocolError("RPC response Content-Length is invalid");
  }
  const digits = match[1];
  if (digits === undefined || digits.length > 20) {
    throw new RpcProtocolError("RPC response Content-Length is invalid");
  }
  const length = Number(digits);
  if (!Number.isSafeInteger(length) || length < 0 || length > MAX_FRAME_BYTES) {
    throw new RpcProtocolError("RPC response exceeds its byte limit");
  }
  return length;
}

function parseResponseBody(body: Buffer): RpcResponse {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new RpcProtocolError("RPC response body is not UTF-8");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new RpcProtocolError("RPC response body is not JSON");
  }
  return validateResponse(parsed);
}

function validateResponse(value: unknown): RpcResponse {
  if (!isRecord(value) || value.jsonrpc !== "2.0") {
    throw new RpcProtocolError("RPC response envelope is invalid");
  }
  const keys = Object.keys(value);
  const hasResult = Object.hasOwn(value, "result");
  const hasError = Object.hasOwn(value, "error");
  if (keys.length !== 3 || hasResult === hasError) {
    throw new RpcProtocolError("RPC response envelope is invalid");
  }
  if (hasResult) {
    if (!isValidId(value.id) || !isJsonValue(value.result)) {
      throw new RpcProtocolError("RPC success response is invalid");
    }
    return { jsonrpc: "2.0", id: value.id, result: value.result };
  }
  if (!(value.id === null || isValidId(value.id)) || !isErrorObject(value.error)) {
    throw new RpcProtocolError("RPC error response is invalid");
  }
  return { jsonrpc: "2.0", id: value.id, error: value.error };
}

function isErrorObject(value: unknown): value is RpcErrorObject {
  if (!isRecord(value) || Object.keys(value).length !== 3) {
    return false;
  }
  if (!Number.isSafeInteger(value.code) || typeof value.message !== "string") {
    return false;
  }
  return (
    isRecord(value.data) &&
    typeof value.data.name === "string" &&
    Object.values(value.data).every(isJsonValue)
  );
}

function isValidId(value: unknown): value is RpcId {
  return (
    (typeof value === "number" && Number.isSafeInteger(value)) ||
    (typeof value === "string" && Buffer.byteLength(value, "utf8") <= 4096)
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isJsonValue(value: unknown): value is JsonValue {
  const pending: { readonly value: unknown; readonly depth: number }[] = [
    { value, depth: 0 },
  ];
  let values = 0;
  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined || current.depth > 64 || ++values > 100_000) {
      return false;
    }
    const item = current.value;
    if (
      item === null ||
      typeof item === "boolean" ||
      typeof item === "string" ||
      (typeof item === "number" && Number.isFinite(item))
    ) {
      continue;
    }
    if (Array.isArray(item)) {
      for (const child of item) {
        pending.push({ value: child, depth: current.depth + 1 });
      }
      continue;
    }
    if (!isRecord(item)) {
      return false;
    }
    for (const child of Object.values(item)) {
      pending.push({ value: child, depth: current.depth + 1 });
    }
  }
  return true;
}

const ERROR_CONTRACT = new Map<number, Readonly<{ name: string; message: string }>>([
  [-32700, { name: "PARSE_ERROR", message: "Parse error" }],
  [-32600, { name: "INVALID_REQUEST", message: "Invalid Request" }],
  [-32601, { name: "METHOD_NOT_FOUND", message: "Method not found" }],
  [-32602, { name: "INVALID_PARAMS", message: "Invalid params" }],
  [-32603, { name: "INTERNAL_ERROR", message: "Internal error" }],
  [-32000, { name: "AUTH_FAILED", message: "Authentication failed" }],
  [-32001, { name: "SESSION_INVALID", message: "Session is invalid or expired" }],
  [-32002, { name: "VAULT_INVALID", message: "Vault configuration is invalid" }],
  [-32003, { name: "PATH_INVALID", message: "Logical path is invalid" }],
  [-32004, { name: "NOT_FOUND", message: "Logical entry was not found" }],
  [-32005, { name: "ALREADY_EXISTS", message: "Logical entry already exists" }],
  [-32006, { name: "ETAG_CONFLICT", message: "Ciphertext etag conflict" }],
  [-32007, { name: "INTEGRITY_FAILED", message: "Encrypted document integrity check failed" }],
  [-32008, { name: "LIMIT_EXCEEDED", message: "Request exceeds the configured limit" }],
  [-32009, { name: "IO_FAILED", message: "Storage operation failed" }],
  [-32010, { name: "KDF_POLICY", message: "KDF parameters violate policy" }],
  [-32011, { name: "UNSUPPORTED", message: "Feature is unsupported" }],
  [-32012, { name: "BUSY", message: "Vault mutation is busy" }],
  [
    -32013,
    {
      name: "PUBLICATION_RECONCILE_REQUIRED",
      message: "Repository publication reconciliation is required",
    },
  ],
  [
    -32014,
    {
      name: "PUBLICATION_MANUAL_AUDIT_REQUIRED",
      message: "Repository publication marker requires manual audit",
    },
  ],
]);
