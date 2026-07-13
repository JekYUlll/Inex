#!/usr/bin/env node

import { spawn } from "node:child_process";
import {
  accessSync,
  appendFileSync,
  chmodSync,
  constants as fsConstants,
  lstatSync,
} from "node:fs";
import * as path from "node:path";

const MAX_HEADER_BYTES = 64 * 1024;
const MAX_REQUEST_BYTES = 64 * 1024 * 1024;

const realSidecarPath = requiredAbsolutePath("INEX_TEST_REAL_INEXD_PATH");
const tracePath = requiredAbsolutePath("INEX_TEST_SIDECAR_TRACE_PATH");
assertRegularExecutable(realSidecarPath);

const childEnvironment = { ...process.env };
delete childEnvironment.INEX_TEST_REAL_INEXD_PATH;
delete childEnvironment.INEX_TEST_SIDECAR_TRACE_PATH;

const child = spawn(realSidecarPath, [], {
  env: childEnvironment,
  shell: false,
  stdio: ["pipe", "pipe", "pipe"],
  windowsHide: true,
});

let pending = Buffer.alloc(0);
let sequence = 0;
let stopping = false;

child.stdout.pipe(process.stdout);
child.stderr.pipe(process.stderr);

process.stdin.on("data", (chunk) => {
  try {
    observeRequests(Buffer.from(chunk));
  } catch {
    stopForObserverFailure();
    return;
  }
  if (!child.stdin.write(chunk)) {
    process.stdin.pause();
  }
});
child.stdin.on("drain", () => process.stdin.resume());
process.stdin.on("end", () => child.stdin.end());
process.stdin.on("error", () => child.stdin.destroy());

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.on(signal, () => {
    stopping = true;
    child.kill(signal);
  });
}

child.once("error", () => {
  process.exitCode = 70;
});
child.once("exit", (code, signal) => {
  pending.fill(0);
  pending = Buffer.alloc(0);
  if (stopping && signal !== null) {
    process.exitCode = 0;
    return;
  }
  process.exitCode = code ?? 70;
});

function observeRequests(chunk) {
  const combined = Buffer.concat([pending, chunk]);
  pending.fill(0);
  pending = combined;
  while (pending.length > 0) {
    const headerEnd = pending.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
      if (pending.length > MAX_HEADER_BYTES) {
        throw new Error("oversized RPC header");
      }
      return;
    }
    if (headerEnd > MAX_HEADER_BYTES) {
      throw new Error("oversized RPC header");
    }
    const header = pending.subarray(0, headerEnd).toString("ascii");
    const match = /^Content-Length: ([0-9]+)$/imu.exec(header);
    if (match === null) {
      throw new Error("missing RPC content length");
    }
    const bodyLength = Number.parseInt(match[1], 10);
    if (!Number.isSafeInteger(bodyLength) || bodyLength < 0 || bodyLength > MAX_REQUEST_BYTES) {
      throw new Error("invalid RPC content length");
    }
    const bodyStart = headerEnd + 4;
    const frameEnd = bodyStart + bodyLength;
    if (pending.length < frameEnd) {
      return;
    }
    const body = Buffer.from(pending.subarray(bodyStart, frameEnd));
    const remainder = Buffer.from(pending.subarray(frameEnd));
    pending.fill(0);
    pending = remainder;
    try {
      observeRequestBody(body);
    } finally {
      body.fill(0);
    }
  }
}

function observeRequestBody(body) {
  const request = JSON.parse(body.toString("utf8"));
  if (
    request === null ||
    typeof request !== "object" ||
    typeof request.method !== "string" ||
    !/^[A-Za-z][A-Za-z0-9.]{0,63}$/u.test(request.method)
  ) {
    throw new Error("invalid RPC request");
  }
  const entry = {
    pid: process.pid,
    sequence: sequence += 1,
    method: request.method,
  };
  if (request.method === "asset.open") {
    const logicalPath = request.params?.logicalPath;
    if (typeof logicalPath === "string" && /^[A-Za-z0-9._/-]{1,512}$/u.test(logicalPath)) {
      entry.logicalPath = logicalPath;
    }
  } else if (request.method === "asset.readChunk") {
    const { offset, maxBytes } = request.params ?? {};
    if (Number.isSafeInteger(offset) && offset >= 0) {
      entry.offset = offset;
    }
    if (Number.isSafeInteger(maxBytes) && maxBytes > 0) {
      entry.maxBytes = maxBytes;
    }
  }
  appendFileSync(tracePath, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
  chmodSync(tracePath, 0o600);
}

function stopForObserverFailure() {
  if (stopping) {
    return;
  }
  stopping = true;
  pending.fill(0);
  pending = Buffer.alloc(0);
  child.kill("SIGKILL");
  process.exitCode = 70;
}

function requiredAbsolutePath(name) {
  const value = process.env[name];
  if (value === undefined || value.length === 0 || !path.isAbsolute(value)) {
    throw new Error(`${name} must be an absolute path`);
  }
  return value;
}

function assertRegularExecutable(executablePath) {
  const metadata = lstatSync(executablePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("real inexd must be a regular file");
  }
  accessSync(executablePath, fsConstants.X_OK);
}
