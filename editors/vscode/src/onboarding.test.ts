import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import test from "node:test";

test("locked vault onboarding exposes unlock/import and gates CRUD by context", () => {
  const packageJson = JSON.parse(
    readFileSync(path.join(process.cwd(), "package.json"), "utf8"),
  ) as {
    contributes: {
      commands: Array<{ command: string; enablement?: string }>;
      viewsWelcome: Array<{ view: string; contents: string; when: string }>;
      menus: { "view/title": Array<{ command: string; when: string }> };
    };
  };
  const welcome = packageJson.contributes.viewsWelcome.find(
    (entry) => entry.view === "inex.vault",
  );
  assert.equal(welcome?.when, "!inex.vaultUnlocked");
  assert.match(welcome?.contents ?? "", /inex\.unlockVault/u);
  assert.match(welcome?.contents ?? "", /inex\.importRepository/u);
  for (const command of [
    "inex.newEncryptedMarkdown",
    "inex.newFolder",
    "inex.rename",
    "inex.delete",
  ]) {
    assert.equal(
      packageJson.contributes.commands.find((entry) => entry.command === command)?.enablement,
      "inex.vaultUnlocked",
    );
  }
  const titleCommands = packageJson.contributes.menus["view/title"];
  assert.match(
    titleCommands.find((entry) => entry.command === "inex.newFolder")?.when ?? "",
    /inex\.vaultUnlocked/u,
  );
});
