import assert from "node:assert/strict";
import test from "node:test";

import {
  OPEN_NEW_VAULT_ACTION,
  offerToOpenImportedVault,
} from "./importCompletion.ts";

test("successful import offers a workspace reload into the ciphertext vault", async () => {
  const target = { fsPath: "/encrypted/new-vault" };
  const opened: unknown[] = [];
  let message = "";
  assert.equal(
    await offerToOpenImportedVault(target, {
      prompt: async (candidate, action) => {
        message = candidate;
        assert.equal(action, OPEN_NEW_VAULT_ACTION);
        return action;
      },
      openFolder: async (candidate) => {
        opened.push(candidate);
      },
    }),
    true,
  );
  assert.match(message, /initialized or reconciled/u);
  assert.match(message, /does not copy its plaintext Git history/u);
  assert.match(message, /VS Code will reload/u);
  assert.match(message, /unlock it explicitly/u);
  assert.deepEqual(opened, [target]);
});

test("dismissing import completion keeps the current workspace unchanged", async () => {
  let opened = false;
  assert.equal(
    await offerToOpenImportedVault("/encrypted/new-vault", {
      prompt: async () => undefined,
      openFolder: async () => {
        opened = true;
      },
    }),
    false,
  );
  assert.equal(opened, false);
});
