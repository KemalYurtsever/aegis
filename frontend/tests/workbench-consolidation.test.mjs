import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../src/SecurityWorkbenchModal.jsx", import.meta.url), "utf8");

test("assessment workspace consolidates overlapping manual tools", () => {
  assert.match(source, /function AssessmentTool\(\{ devices \}\)/);
  assert.match(source, /<LabCliTool devices=\{devices\} \/>/);
  assert.match(source, /<TestConnectionPortTool devices=\{devices\} \/>/);
  assert.match(source, /<TracerouteTool devices=\{devices\} \/>/);
  assert.match(source, /new Set\(\["lab-cli", "traceroute", "test-connection"\]\)/);
  assert.match(source, /Automated workflow/);
  assert.match(source, /Manual checks/);
  assert.match(source, /role="tablist" aria-label="Assessment mode"/);
  assert.doesNotMatch(source, /\["lab-cli", "Network CLI", "13"\]/);
});
