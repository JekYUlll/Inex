import assert from "node:assert/strict";
import test from "node:test";

import { formatSecurityStatus } from "./securityStatus.ts";

test("security status does not imply Umbra availability while Outer is locked", () => {
  assert.equal(
    formatSecurityStatus(false, { initialized: true, unlocked: true }),
    "Inex Outer vault is locked. Umbra private data is unavailable.",
  );
});

test("security status distinguishes every Outer-unlocked Umbra state", () => {
  assert.match(formatSecurityStatus(true, undefined), /could not be verified/);
  assert.match(formatSecurityStatus(true, { initialized: false, unlocked: false }), /not been initialized/);
  assert.match(formatSecurityStatus(true, { initialized: true, unlocked: false }), /initialized but locked/);
  assert.match(formatSecurityStatus(true, { initialized: true, unlocked: true }), /and Umbra are unlocked/);
});
