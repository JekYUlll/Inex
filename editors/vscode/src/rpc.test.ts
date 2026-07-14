import assert from "node:assert/strict";
import test from "node:test";

import {
  FrameDecoder,
  MAX_FRAME_BYTES,
  MAX_HEADER_BYTES,
  RpcProtocolError,
  RpcRemoteError,
  encodeRequest,
  responseResult,
} from "./rpc.ts";

function frame(body: string): Buffer {
  return Buffer.from(`Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`, "utf8");
}

test("decoder accepts partial and adjacent strict responses", () => {
  const decoder = new FrameDecoder();
  const first = frame('{"jsonrpc":"2.0","id":1,"result":{"ok":true}}');
  const second = frame(
    '{"jsonrpc":"2.0","id":"two","error":{"code":-32001,"message":"Session is invalid or expired","data":{"name":"SESSION_INVALID"}}}',
  );
  const joined = Buffer.concat([first, second]);
  assert.deepEqual(decoder.push(joined.subarray(0, 7)), []);
  const responses = decoder.push(joined.subarray(7));
  assert.equal(responses.length, 2);
  assert.deepEqual(responseResult(responses[0]!), { ok: true });
  assert.throws(() => responseResult(responses[1]!), RpcRemoteError);
  decoder.finish();
});

test("decoder rejects stdout noise, batch JSON, and malformed envelopes", () => {
  const cases = [
    Buffer.from("noise"),
    frame("[]"),
    frame('{"jsonrpc":"2.0","id":1,"result":true,"extra":false}'),
    frame('{"jsonrpc":"2.0","id":1,"result":true,"error":{}}'),
  ];
  for (const encoded of cases) {
    const decoder = new FrameDecoder();
    if (encoded.toString("utf8") === "noise") {
      decoder.push(encoded);
      assert.throws(() => decoder.finish(), RpcProtocolError);
    } else {
      assert.throws(() => decoder.push(encoded), RpcProtocolError);
    }
  }
});

test("decoder enforces framing bounds before body allocation", () => {
  const decoder = new FrameDecoder();
  assert.throws(
    () => decoder.push(Buffer.from(`Content-Length: ${MAX_FRAME_BYTES + 1}\r\n\r\n`)),
    RpcProtocolError,
  );
  const headerBomb = new FrameDecoder();
  assert.throws(() => headerBomb.push(Buffer.alloc(8193, 0x41)), RpcProtocolError);
});

test("decoder rejects an oversized transport chunk before copying it", () => {
  const decoder = new FrameDecoder();
  const oversized = {
    byteLength: MAX_FRAME_BYTES + MAX_HEADER_BYTES + 1,
  } as Uint8Array;
  assert.throws(
    () => decoder.push(oversized),
    /transport chunk exceeds its byte limit/u,
  );
});

test("request encoder emits one canonical frame and rejects unsafe ids", () => {
  const encoded = encodeRequest(7, "system.ping", {});
  assert.match(encoded.toString("utf8"), /^Content-Length: [0-9]+\r\n\r\n/);
  const boundary = encoded.indexOf("\r\n\r\n");
  const body = JSON.parse(encoded.subarray(boundary + 4).toString("utf8")) as unknown;
  assert.deepEqual(body, { jsonrpc: "2.0", id: 7, method: "system.ping", params: {} });
  encoded.fill(0);
  assert.throws(() => encodeRequest(Number.MAX_SAFE_INTEGER + 1, "system.ping", {}));
});

test("publication barrier errors retain their actionable contracts", () => {
  for (const [code, name, message] of [
    [
      -32013,
      "PUBLICATION_RECONCILE_REQUIRED",
      "Repository publication reconciliation is required",
    ],
    [
      -32014,
      "PUBLICATION_MANUAL_AUDIT_REQUIRED",
      "Repository publication marker requires manual audit",
    ],
  ] as const) {
    assert.throws(
      () =>
        responseResult({
          jsonrpc: "2.0",
          id: 1,
          error: { code, message, data: { name } },
        }),
      (error: unknown) =>
        error instanceof RpcRemoteError &&
        error.code === code &&
        error.stableName === name &&
        error.message === message,
    );
  }
});
