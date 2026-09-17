import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const workbench = readFileSync(
  new URL("../src/SecurityWorkbenchModal.jsx", import.meta.url),
  "utf8",
);
const app = readFileSync(new URL("../src/App.jsx", import.meta.url), "utf8");
const readme = readFileSync(new URL("../../README.md", import.meta.url), "utf8");
const guide = readFileSync(
  new URL("../../docs/PROJECT_GUIDE.md", import.meta.url),
  "utf8",
);
const roadmap = readFileSync(
  new URL("../../docs/PROTOTYPE_ROADMAP.md", import.meta.url),
  "utf8",
);

test("workbench provides a goal-based first-use path", () => {
  assert.match(workbench, /How Aegis turns a host into an action/);
  assert.match(workbench, /Assess a registered device/);
  assert.match(workbench, /Refresh vulnerability data/);
  assert.match(workbench, /Prioritize existing evidence/);
  assert.match(workbench, /const TOOL_GROUPS =/);
  assert.match(workbench, /Start here/);
  assert.match(workbench, /Review evidence/);
  assert.match(workbench, /Local utilities/);
});

test("CVE mirror explains data state and result meaning", () => {
  assert.match(workbench, /Ready for matching/);
  assert.match(workbench, /a match is a review candidate, not proof/);
  assert.match(workbench, /Nmap supplies product, version and preferably an exact CPE/);
  assert.match(workbench, /Recommended after the first Full import/);
});

test("CVE results distinguish matches from fingerprint coverage", () => {
  assert.match(app, /services CVE-ready/);
  assert.match(app, /A zero-match result does not cover unidentified services/);
  assert.match(workbench, /CVE evidence/);
  assert.match(workbench, /CVE matches/);
  assert.match(workbench, /function AttackSurfaceStepOutput/);
  assert.match(workbench, /Legacy saved result: fingerprint coverage was not recorded/);
  assert.match(workbench, /View preserved JSON/);
});

test("automated assessments explain service-directed tools and expose saved evidence", () => {
  assert.match(workbench, /Automatic service checks/);
  assert.match(workbench, /Certificates|certificate names and cipher suites do not/);
  assert.match(workbench, /Collected evidence and command/);
  assert.match(app, /Automatic tool reports/);
  assert.match(app, /conflicting versions are withheld/);
  assert.match(app, /!unresolvedPorts\.has\(finding\.port\)/);
});

test("repository entry point links the operator guide and improvement roadmap", () => {
  assert.match(readme, /docs\/PROJECT_GUIDE\.md/);
  assert.match(readme, /docs\/PROTOTYPE_ROADMAP\.md/);
  assert.match(guide, /The five-stage workflow/);
  assert.match(guide, /Result interpretation/);
  assert.match(roadmap, /Priority 0/);
  assert.match(roadmap, /Success criteria/);
});
