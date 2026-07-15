import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import test from "node:test";
import { runInNewContext } from "node:vm";

const source = readFileSync(
  path.join(process.cwd(), "src", "customEditor.ts"),
  "utf8",
);
const runtime = /<script nonce="\$\{nonce\}">\n([\s\S]*?)\n<\/script>/u.exec(source)?.[1];

test("editor webview keeps the exact closed network/filesystem CSP", () => {
  const csp = /Content-Security-Policy" content="([^"]+)"/u.exec(source)?.[1];
  assert.equal(
    csp,
    "default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; img-src blob:",
  );
  assert.doesNotMatch(csp ?? "", /https?:|data:|file:|connect-src|media-src|frame-src/u);
  assert.match(source, /localResourceRoots: \[\]/u);
  assert.doesNotMatch(source, /asWebviewUri|registerFileSystemProvider/u);
});

test("webview raster validator executes and blocks active or malformed formats", () => {
  assert.ok(runtime, "editor webview runtime was not found");
  const element = {
    addEventListener: () => undefined,
    append: () => undefined,
    replaceChildren: () => undefined,
    setSelectionRange: () => undefined,
    focus: () => undefined,
    value: "",
    hidden: true,
    selectionStart: 0,
    childElementCount: 0,
  };
  const context = {
    acquireVsCodeApi: () => ({ postMessage: () => undefined }),
    document: {
      getElementById: () => element,
      createElement: () => ({ ...element, remove: () => undefined }),
    },
    window: { addEventListener: () => undefined },
    URL: { createObjectURL: () => "blob:test", revokeObjectURL: () => undefined },
    Blob,
    TextEncoder,
    Uint8Array,
    ArrayBuffer,
    Map,
    Set,
    Number,
    String,
    setTimeout,
    clearTimeout,
  } as Record<string, unknown>;
  runInNewContext(`${runtime}\nglobalThis.validateRaster = validatedRasterType;`, context);
  const validate = context.validateRaster as (bytes: Uint8Array) => string | undefined;

  assert.equal(validate(minimalPng(1, 1)), "image/png");
  assert.equal(validate(minimalJpeg(2, 3)), "image/jpeg");
  assert.equal(validate(minimalLosslessWebP(4, 5)), "image/webp");
  assert.equal(validate(extendedLosslessWebP(4, 5, 4, 5)), "image/webp");
  const mismatched = extendedLosslessWebP(1, 1, 16_384, 16_384);
  assert.equal(mismatched.byteLength, 44);
  assert.equal(validate(mismatched), undefined);
  assert.equal(
    validate(webpContainer([webpVp8x(1, 1), webpVp8x(1, 1), webpVp8l(1, 1)])),
    undefined,
  );
  assert.equal(
    validate(webpContainer([webpVp8l(1, 1), webpVp8x(1, 1)])),
    undefined,
  );
  assert.equal(
    validate(webpContainer([webpVp8l(1, 1), webpVp8l(1, 1)])),
    undefined,
  );
  for (const reservedIndex of [0, 1, 2] as const) {
    const reserved: [number, number, number] = [0, 0, 0];
    reserved[reservedIndex] = 1;
    assert.equal(
      validate(webpContainer([webpVp8x(1, 1, 0, reserved), webpVp8l(1, 1)])),
      undefined,
    );
  }
  assert.equal(
    validate(webpContainer([webpVp8x(1, 1, 0x02), webpVp8l(1, 1)])),
    undefined,
  );
  assert.equal(
    validate(
      webpContainer([
        webpVp8x(1, 1),
        webpChunk("ANIM", Buffer.alloc(6)),
        webpVp8l(1, 1),
      ]),
    ),
    undefined,
  );
  assert.equal(
    validate(
      webpContainer([
        webpVp8x(1, 1),
        webpChunk("ANMF", Buffer.alloc(16)),
        webpVp8l(1, 1),
      ]),
    ),
    undefined,
  );
  assert.equal(validate(Buffer.from("<svg><script/></svg>")), undefined);
  assert.equal(validate(animatedPng()), undefined);
  assert.equal(validate(minimalPng(16_385, 1)), undefined);
});

test("rapid input suspends previews without outrunning host generations", () => {
  assert.ok(runtime, "editor webview runtime was not found");
  const editorListeners = new Map<string, Array<() => void>>();
  const windowListeners = new Map<string, Array<(event: { data: unknown }) => void>>();
  const editor = fakeElement((type, listener) => {
    const listeners = editorListeners.get(type) ?? [];
    listeners.push(listener as () => void);
    editorListeners.set(type, listeners);
  });
  const previews = fakeElement();
  const button = fakeElement();
  const context = runtimeContext(
    (id) => id === "editor" ? editor : id === "previews" ? previews : button,
    (type, listener) => {
      const listeners = windowListeners.get(type) ?? [];
      listeners.push(listener);
      windowListeners.set(type, listeners);
    },
  );
  runInNewContext(
    `${runtime}\nglobalThis.previewState=()=>({generation:previewGeneration,editEpoch,suspended:previewSuspended,transfers:transfers.size});`,
    context,
  );
  const state = context.previewState as () => {
    generation: number;
    editEpoch: number;
    suspended: boolean;
    transfers: number;
  };
  const message = (data: unknown) => {
    for (const listener of windowListeners.get("message") ?? []) {
      listener({ data });
    }
  };
  const input = () => {
    for (const listener of editorListeners.get("input") ?? []) {
      listener();
    }
  };

  message({ type: "previewReset", generation: 2, editEpoch: 0 });
  message({
    type: "assetStart",
    generation: 2,
    editEpoch: 0,
    transferId: "2:0",
    logicalPath: "image.png",
    size: 1,
  });
  assert.deepEqual({ ...state() }, {
    generation: 2,
    editEpoch: 0,
    suspended: false,
    transfers: 1,
  });
  input();
  message({ type: "previewReset", generation: 4, editEpoch: 0 });
  message({
    type: "assetStart",
    generation: 4,
    editEpoch: 0,
    transferId: "4:stale",
    logicalPath: "stale.png",
    size: 1,
  });
  assert.deepEqual({ ...state() }, {
    generation: 2,
    editEpoch: 1,
    suspended: true,
    transfers: 0,
  });
  for (let index = 1; index < 20; index += 1) {
    input();
  }
  assert.deepEqual({ ...state() }, {
    generation: 2,
    editEpoch: 20,
    suspended: true,
    transfers: 0,
  });

  message({ type: "previewReset", generation: 6, editEpoch: 20 });
  message({ type: "previewReset", generation: 5, editEpoch: 19 });
  message({
    type: "assetStart",
    generation: 5,
    editEpoch: 19,
    transferId: "5:0",
    logicalPath: "stale.png",
    size: 1,
  });
  assert.deepEqual({ ...state() }, {
    generation: 6,
    editEpoch: 20,
    suspended: false,
    transfers: 0,
  });
  message({
    type: "assetStart",
    generation: 6,
    editEpoch: 20,
    transferId: "6:0",
    logicalPath: "current.png",
    size: 1,
  });
  assert.deepEqual({ ...state() }, {
    generation: 6,
    editEpoch: 20,
    suspended: false,
    transfers: 1,
  });
});

test("webview applies consecutive reveals, synchronizes selection, and scrolls later headings", () => {
  const windowListeners = new Map<string, Array<(event: { data: unknown }) => void>>();
  const messages: unknown[] = [];
  const editor = fakeElement() as Record<string, unknown>;
  let selection: readonly [number, number] | undefined;
  let focusCount = 0;
  editor.clientHeight = 60;
  editor.scrollTop = 0;
  editor.setSelectionRange = (start: number, end: number) => {
    selection = [start, end];
    editor.selectionStart = start;
    editor.selectionEnd = end;
  };
  editor.focus = () => { focusCount += 1; };
  const context = runtimeContext(
    (id) => id === "editor" ? editor : fakeElement(),
    (type, listener) => {
      const listeners = windowListeners.get(type) ?? [];
      listeners.push(listener);
      windowListeners.set(type, listeners);
    },
  );
  context.acquireVsCodeApi = () => ({ postMessage: (message: unknown) => messages.push(message) });
  runInNewContext(runtime!, context);
  const post = (data: unknown) => {
    for (const listener of windowListeners.get("message") ?? []) {
      listener({ data });
    }
  };
  const content = "zero\n第二\nthird\n";
  post({ type: "content", content, readOnly: false });
  const firstStart = Buffer.byteLength("zero\n", "utf8");
  const firstEnd = firstStart + Buffer.byteLength("第二", "utf8");
  const secondStart = Buffer.byteLength("zero\n第二\n", "utf8");
  const secondEnd = secondStart + Buffer.byteLength("third", "utf8");
  post({ type: "reveal", startByte: firstStart, endByte: firstEnd });
  assert.deepEqual(selection, [5, 7]);
  post({ type: "reveal", startByte: secondStart, endByte: secondEnd });
  assert.deepEqual(selection, [8, 13]);
  assert.equal(focusCount, 2);
  assert.equal(editor.scrollTop, 20);
  const selectionMessages = messages.filter((message) =>
    typeof message === "object" && message !== null && (message as { type?: unknown }).type === "selection",
  ) as Array<{ selections: readonly { readonly startByte: number; readonly endByte: number }[] }>;
  assert.deepEqual(selectionMessages.map((message) => {
    const range = message.selections.at(-1);
    return range === undefined ? undefined : { startByte: range.startByte, endByte: range.endByte };
  }), [
    { startByte: firstStart, endByte: firstEnd },
    { startByte: secondStart, endByte: secondEnd },
  ]);
  post({ type: "reveal", startByte: firstStart + 1, endByte: firstEnd });
  post({ type: "reveal", startByte: secondEnd, endByte: secondEnd + 2 });
  assert.deepEqual(selection, [8, 13]);
  assert.equal(focusCount, 2, "invalid byte ranges must not move focus or selection");
});

function minimalPng(width: number, height: number): Uint8Array {
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    pngChunk("IHDR", Buffer.concat([u32be(width), u32be(height), Buffer.from([8, 2, 0, 0, 0])])),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function animatedPng(): Uint8Array {
  const png = minimalPng(1, 1);
  return Buffer.concat([
    png.subarray(0, png.length - 12),
    pngChunk("acTL", Buffer.alloc(8)),
    png.subarray(png.length - 12),
  ]);
}

function pngChunk(type: string, data: Uint8Array): Buffer {
  return Buffer.concat([
    u32be(data.byteLength),
    Buffer.from(type, "ascii"),
    data,
    Buffer.alloc(4),
  ]);
}

function minimalJpeg(width: number, height: number): Uint8Array {
  return Buffer.from([
    0xff, 0xd8,
    0xff, 0xc0, 0x00, 0x11, 0x08,
    (height >>> 8) & 0xff, height & 0xff,
    (width >>> 8) & 0xff, width & 0xff,
    0x03, 0x01, 0x11, 0x00, 0x02, 0x11, 0x00, 0x03, 0x11, 0x00,
    0xff, 0xda, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3f, 0x00,
    0xff, 0xd9,
  ]);
}

function minimalLosslessWebP(width: number, height: number): Uint8Array {
  return webpContainer([webpVp8l(width, height)]);
}

function extendedLosslessWebP(
  canvasWidth: number,
  canvasHeight: number,
  frameWidth: number,
  frameHeight: number,
): Uint8Array {
  return webpContainer([
    webpVp8x(canvasWidth, canvasHeight),
    webpVp8l(frameWidth, frameHeight),
  ]);
}

function webpVp8x(
  width: number,
  height: number,
  flags = 0,
  reserved: readonly [number, number, number] = [0, 0, 0],
): Buffer {
  const payload = Buffer.alloc(10);
  payload[0] = flags;
  payload.set(reserved, 1);
  writeU24le(payload, 4, width - 1);
  writeU24le(payload, 7, height - 1);
  return webpChunk("VP8X", payload);
}

function webpVp8l(width: number, height: number): Buffer {
  const widthMinusOne = width - 1;
  const heightMinusOne = height - 1;
  const payload = Buffer.from([
    0x2f,
    widthMinusOne & 0xff,
    ((widthMinusOne >>> 8) & 0x3f) | ((heightMinusOne & 0x03) << 6),
    (heightMinusOne >>> 2) & 0xff,
    (heightMinusOne >>> 10) & 0x0f,
  ]);
  return webpChunk("VP8L", payload);
}

function webpChunk(type: string, payload: Uint8Array): Buffer {
  return Buffer.concat([
    Buffer.from(type, "ascii"),
    u32le(payload.byteLength),
    payload,
    Buffer.alloc(payload.byteLength & 1),
  ]);
}

function webpContainer(chunks: readonly Uint8Array[]): Buffer {
  const body = Buffer.concat([Buffer.from("WEBP", "ascii"), ...chunks]);
  return Buffer.concat([Buffer.from("RIFF", "ascii"), u32le(body.length), body]);
}

function writeU24le(buffer: Buffer, offset: number, value: number): void {
  buffer[offset] = value & 0xff;
  buffer[offset + 1] = (value >>> 8) & 0xff;
  buffer[offset + 2] = (value >>> 16) & 0xff;
}

function fakeElement(
  register: (type: string, listener: (...arguments_: never[]) => void) => void = () => undefined,
): Record<string, unknown> {
  return {
    addEventListener: register,
    append: () => undefined,
    replaceChildren: () => undefined,
    setSelectionRange: () => undefined,
    focus: () => undefined,
    value: "",
    hidden: true,
    selectionStart: 0,
    childElementCount: 0,
  };
}

function runtimeContext(
  getElementById: (id: string) => Record<string, unknown>,
  addWindowListener: (
    type: string,
    listener: (event: { data: unknown }) => void,
  ) => void,
): Record<string, unknown> {
  return {
    acquireVsCodeApi: () => ({ postMessage: () => undefined }),
    document: {
      getElementById,
      createElement: () => ({ ...fakeElement(), remove: () => undefined }),
    },
    window: { addEventListener: addWindowListener },
    URL: { createObjectURL: () => "blob:test", revokeObjectURL: () => undefined },
    Blob,
    TextEncoder,
    Uint8Array,
    ArrayBuffer,
    Map,
    Set,
    Number,
    String,
    setTimeout: () => 1,
    clearTimeout: () => undefined,
  };
}

function u32be(value: number): Buffer {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}

function u32le(value: number): Buffer {
  const result = Buffer.alloc(4);
  result.writeUInt32LE(value);
  return result;
}
