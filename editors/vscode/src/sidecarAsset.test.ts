import assert from "node:assert/strict";
import { chmodSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import test from "node:test";

import { RpcProtocolError } from "./rpc.ts";
import {
  InexSidecar,
  parseAssetChunkResult,
  parseAssetOpenResult,
} from "./sidecar.ts";

const ETAG = `sha256:${"a".repeat(64)}`;
const METADATA = {
  fileId: "12345678-1234-4234-9234-123456789abc",
  logicalPath: "images/station.png",
  createdAt: 1,
  modifiedAt: 2,
  flags: 0,
};

test("asset RPC parsers accept exact bounded canonical responses", () => {
  const opened = parseAssetOpenResult(
    {
      handle: "A".repeat(22),
      size: 3,
      etag: ETAG,
      metadata: METADATA,
    },
    "images/station.png",
  );
  assert.equal(opened.size, 3);
  const chunk = parseAssetChunkResult(
    { offset: 0, contentBase64: Buffer.from("abc").toString("base64url"), eof: true },
    0,
    1024 * 1024,
  );
  assert.equal(chunk.content.toString("utf8"), "abc");
  chunk.content.fill(0);
});

test("asset RPC parsers reject substitution, noncanonical data, and stalled chunks", () => {
  assert.throws(
    () =>
      parseAssetOpenResult(
        {
          handle: "A".repeat(22),
          size: 3,
          etag: ETAG,
          metadata: { ...METADATA, logicalPath: "images/other.png" },
        },
        "images/station.png",
      ),
    RpcProtocolError,
  );
  assert.throws(
    () => parseAssetChunkResult({ offset: 1, contentBase64: "", eof: false }, 0, 1),
    RpcProtocolError,
  );
  assert.throws(
    () => parseAssetChunkResult({ offset: 0, contentBase64: "YQ==", eof: true }, 0, 1),
    RpcProtocolError,
  );
});

test(
  "sidecar enables assets only after hello and authenticated vault status",
  { skip: process.platform === "win32" },
  async () => {
    const root = path.join(os.tmpdir(), `inex-vscode-asset-rpc-${process.pid}-${Date.now()}`);
    const executable = path.join(root, "asset-sidecar.mjs");
    try {
      mkdirSync(root, { recursive: true });
      writeFileSync(executable, fakeAssetSidecar());
      chmodSync(executable, 0o700);
      const sidecar = new InexSidecar(executable);
      await sidecar.start("test");
      assert.equal(sidecar.canReadOpaqueAssetsV1, false);
      await sidecar.unlock(root, "password");
      assert.equal(sidecar.canReadOpaqueAssetsV1, true);
      assert.deepEqual(await sidecar.listTree(), [
        { kind: "asset", logicalPath: "images/station.png" },
      ]);
      const opened = await sidecar.openAsset("images/station.png");
      const chunk = await sidecar.readAssetChunk(opened.handle, 0, 1024 * 1024);
      assert.equal(chunk.content.toString("utf8"), "png");
      assert.equal(chunk.eof, true);
      chunk.content.fill(0);
      await sidecar.closeAsset(opened.handle);
      await sidecar.lock();
      assert.equal(sidecar.canReadOpaqueAssetsV1, false);
      sidecar.dispose();
    } finally {
      rmSync(root, { force: true, recursive: true });
    }
  },
);

for (const failure of ["invalid-open-result", "close-error"] as const) {
  test(
    `asset ${failure} terminally destroys the daemon-owned plaintext handle`,
    { skip: process.platform === "win32" },
    async () => {
      const root = path.join(
        os.tmpdir(),
        `inex-vscode-asset-failure-${failure}-${process.pid}-${Date.now()}`,
      );
      const executable = path.join(root, "asset-sidecar.mjs");
      const statePath = path.join(root, "open-assets.log");
      try {
        mkdirSync(root, { recursive: true });
        writeFileSync(executable, fakeAssetSidecar({ failure, statePath }));
        chmodSync(executable, 0o700);
        let sessionsLost = 0;
        const sidecar = new InexSidecar(executable, () => {
          sessionsLost += 1;
        });
        await sidecar.start("test");
        await sidecar.unlock(root, "password");
        if (failure === "invalid-open-result") {
          await assert.rejects(
            sidecar.openAsset("images/station.png"),
            RpcProtocolError,
          );
        } else {
          const opened = await sidecar.openAsset("images/station.png");
          await assert.rejects(sidecar.closeAsset(opened.handle));
        }
        assert.equal(sessionsLost, 1, "terminal asset failure did not notify the controller");
        assert.equal(sidecar.hasSession, false);
        assert.equal(sidecar.isRunning, false, "terminal asset failure left the child usable");
        await waitForOpenAssetsWiped(statePath);
        sidecar.dispose();
      } finally {
        rmSync(root, { force: true, recursive: true });
      }
    },
  );
}

function fakeAssetSidecar(options?: {
  readonly failure: "invalid-open-result" | "close-error";
  readonly statePath: string;
}): string {
  const statePath = JSON.stringify(options?.statePath ?? null);
  const invalidOpen = options?.failure === "invalid-open-result";
  const closeError = options?.failure === "close-error";
  return `#!/usr/bin/env node
import {appendFileSync} from 'node:fs';
const statePath=${statePath};
const invalidOpen=${JSON.stringify(invalidOpen)};
const closeError=${JSON.stringify(closeError)};
let openAssets=0;
let pending=Buffer.alloc(0);
function record(){if(statePath!==null)appendFileSync(statePath,String(openAssets)+'\\n');}
function wipeAndExit(){openAssets=0;record();process.exit(0);}
record();
process.on('SIGTERM',wipeAndExit);
process.stdin.on('data',(chunk)=>{pending=Buffer.concat([pending,chunk]);drain();});
function drain(){for(;;){const boundary=pending.indexOf('\\r\\n\\r\\n');if(boundary<0)return;const header=pending.subarray(0,boundary).toString('ascii');const match=/^Content-Length: ([0-9]+)$/u.exec(header);if(match===null)process.exit(2);const length=Number(match[1]);if(pending.length<boundary+4+length)return;const request=JSON.parse(pending.subarray(boundary+4,boundary+4+length).toString('utf8'));pending=pending.subarray(boundary+4+length);respond(request);}}
function respond(request){let result,error;switch(request.method){case 'system.hello':result={server:'inexd',serverVersion:'test',protocolMajor:1,capabilities:['vault','files','documents','encryptedDrafts','search','authenticatedPing','opaqueAssetsV1']};break;case 'vault.unlock':result={session:'S'.repeat(43),vaultId:'12345678-1234-4234-9234-123456789abc',idleTimeoutMs:60000,warnings:[]};break;case 'vault.status':result={features:{opaqueAssetsV1:true}};break;case 'vault.listTree':result={entries:[{kind:'asset',logicalPath:'images/station.png'}]};break;case 'asset.open':openAssets=1;record();result={handle:'H'.repeat(22),size:3,etag:'sha256:'+'a'.repeat(64),metadata:{fileId:'12345678-1234-4234-9234-123456789abc',logicalPath:invalidOpen?'images/substituted.png':'images/station.png',createdAt:1,modifiedAt:2,flags:0}};break;case 'asset.readChunk':result={offset:0,contentBase64:Buffer.from('png').toString('base64url'),eof:true};break;case 'asset.close':if(closeError){error={code:-32603,message:'Internal error',data:{name:'INTERNAL_ERROR'}};}else{openAssets=0;record();result={ok:true};}break;case 'vault.lock':openAssets=0;record();result={ok:true};break;default:process.exit(3);}const response=error===undefined?{jsonrpc:'2.0',id:request.id,result}:{jsonrpc:'2.0',id:request.id,error};const body=JSON.stringify(response);process.stdout.write('Content-Length: '+Buffer.byteLength(body)+'\\r\\n\\r\\n'+body);}
`;
}

async function waitForOpenAssetsWiped(statePath: string): Promise<void> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    let log = "";
    try {
      log = readFileSync(statePath, "utf8");
    } catch {
      await delay(10);
      continue;
    }
    if (/1\n(?:0\n)+$/u.test(log)) {
      return;
    }
    await delay(10);
  }
  assert.fail("fake sidecar did not report wiping its open asset allocation");
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
