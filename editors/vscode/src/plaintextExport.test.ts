import assert from "node:assert/strict";
import test from "node:test";

import { validatePlaintextExportDirectoryName } from "./plaintextExport.ts";

test("plaintext export destination names are exactly one non-dot path component", () => {
  for (const name of ["export", "diary backup", "私人导出", ".hidden"]) {
    assert.equal(validatePlaintextExportDirectoryName(name), undefined, name);
  }
  for (const name of ["", ".", "..", "a/b", "a\\b", "a\0b", "a\nb"]) {
    assert.notEqual(validatePlaintextExportDirectoryName(name), undefined, JSON.stringify(name));
  }
});
