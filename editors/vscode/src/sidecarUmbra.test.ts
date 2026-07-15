import assert from "node:assert/strict";
import test from "node:test";

import { RpcProtocolError, type JsonObject } from "./rpc.ts";
import {
  parseUmbraAnnotationConfig,
  parseUmbraAnnotationResult,
  parseUmbraOuterProjection,
  parseUmbraProjection,
} from "./sidecar.ts";

const ETAG = `sha256:${"a".repeat(64)}`;
const METADATA = {
  fileId: "12345678-1234-4234-9234-123456789abc",
  logicalPath: "private.md",
  createdAt: 1,
  modifiedAt: 2,
  flags: 0,
};

function renderMap(): JsonObject {
  return {
    generationBase64: Buffer.alloc(32, 7).toString("base64url"),
    projectionBytes: 7,
    privateSlots: [],
    outerSegments: [
      {
        projectionStartByte: 0,
        projectionEndByte: 7,
        outerStartByte: 0,
        outerEndByte: 7,
      },
    ],
  };
}

test("Umbra projection parser binds content length and strict RenderMap shape", () => {
  const parsed = parseUmbraProjection(
    {
      contentBase64: Buffer.from("private").toString("base64url"),
      etag: ETAG,
      metadata: METADATA,
      renderMap: renderMap(),
    },
    "private.md",
  );
  assert.equal(parsed.content.toString(), "private");
  assert.equal(parsed.renderMap.generation.byteLength, 32);
  parsed.content.fill(0);
  parsed.renderMap.generation.fill(0);

  assert.throws(
    () =>
      parseUmbraProjection(
        {
          contentBase64: Buffer.from("private").toString("base64url"),
          etag: ETAG,
          metadata: METADATA,
          renderMap: { ...renderMap(), projectionBytes: 6 },
        },
        "private.md",
      ),
    RpcProtocolError,
  );
});

test("Umbra Outer projection parser accepts only the public bounded response", () => {
  const parsed = parseUmbraOuterProjection(
    { contentBase64: Buffer.from("public\n").toString("base64url"), etag: ETAG, metadata: METADATA },
    "private.md",
  );
  assert.equal(parsed.content.toString(), "public\n");
  parsed.content.fill(0);
  assert.throws(
    () => parseUmbraOuterProjection(
      { contentBase64: "", etag: ETAG, metadata: METADATA, renderMap: {} },
      "private.md",
    ),
    RpcProtocolError,
  );
});

test("Umbra annotation parser requires fresh projection, metadata, and durability", () => {
  const parsed = parseUmbraAnnotationResult(
    {
      contentBase64: Buffer.from("private").toString("base64url"),
      etag: ETAG,
      metadata: METADATA,
      durability: "synced",
      renderMap: renderMap(),
    },
    "private.md",
  );
  assert.equal(parsed.durability, "synced");
  assert.equal(parsed.metadata.logicalPath, "private.md");
  parsed.content.fill(0);
  parsed.renderMap.generation.fill(0);
});

test("Umbra config parser accepts only encrypted-catalog identifiers and references", () => {
  const parsed = parseUmbraAnnotationConfig({
    tags: [
      {
        id: "comment-content",
        label: "Comment",
        description: "General private annotation",
        aliases: ["comment"],
        sortOrder: 10,
        defaultSelected: true,
        archived: false,
      },
    ],
    profiles: [
      {
        id: "private-comment",
        label: "Private comment",
        kind: "comment",
        tagIds: ["comment-content"],
        outer: "drop",
        promptForCover: false,
      },
    ],
    defaults: {
      kind: "comment",
      tagIds: ["comment-content"],
      outer: "drop",
      defaultProfileId: "private-comment",
    },
  });
  assert.equal(parsed.tags[0]?.id, "comment-content");
  assert.equal(parsed.profiles[0]?.label, "Private comment");

  assert.throws(
    () =>
      parseUmbraAnnotationConfig({
        tags: [],
        profiles: [],
        defaults: { kind: "comment", tagIds: ["missing"], outer: "drop", defaultProfileId: "" },
      }),
    RpcProtocolError,
  );
});
