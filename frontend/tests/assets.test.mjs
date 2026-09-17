import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import test from "node:test";

const ASSET_LIMIT_BYTES = 100 * 1024;
const assets = ["aegis-shield.webp", "aegis-shield-dark.webp"];

test("brand assets stay optimized for initial page load", async () => {
  for (const asset of assets) {
    const details = await stat(new URL(`../src/assets/${asset}`, import.meta.url));
    assert.ok(
      details.size <= ASSET_LIMIT_BYTES,
      `${asset} is ${details.size} bytes; expected at most ${ASSET_LIMIT_BYTES}`,
    );
  }
});

test("runtime components use the optimized brand assets", async () => {
  const sources = await Promise.all(
    ["App.jsx", "SecurityWorkbenchModal.jsx"].map((file) =>
      readFile(new URL(`../src/${file}`, import.meta.url), "utf8"),
    ),
  );
  for (const source of sources) {
    assert.match(source, /aegis-shield(?:-dark)?\.webp/);
    assert.doesNotMatch(source, /aegis-shield(?:-dark)?\.png/);
  }
});
