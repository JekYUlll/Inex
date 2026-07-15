import assert from "node:assert/strict";
import test from "node:test";

import { parseOuterRevisionCompare } from "./sidecar.ts";

test("Outer revision compare parser accepts only the fixed bounded contract", () => {
  const parsed = parseOuterRevisionCompare({
    leftRole: "head",
    leftContentBase64: Buffer.from("new\n", "utf8").toString("base64url"),
    rightRole: "headParent",
    rightContentBase64: Buffer.from("old\n", "utf8").toString("base64url"),
  });
  assert.equal(parsed.leftContent.toString("utf8"), "new\n");
  assert.equal(parsed.rightContent.toString("utf8"), "old\n");
  parsed.leftContent.fill(0);
  parsed.rightContent.fill(0);
});

test("Outer revision compare parser rejects substituted roles, fields, and encoding", () => {
  for (const value of [
    {
      leftRole: "headParent",
      leftContentBase64: "",
      rightRole: "head",
      rightContentBase64: "",
    },
    {
      leftRole: "head",
      leftContentBase64: "=",
      rightRole: "headParent",
      rightContentBase64: "",
    },
    {
      leftRole: "head",
      leftContentBase64: "",
      rightRole: "headParent",
      rightContentBase64: "",
      oid: "must-not-be-accepted",
    },
  ]) {
    assert.throws(() => parseOuterRevisionCompare(value));
  }
});
