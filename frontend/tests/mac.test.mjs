import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { changeMacDirectly, macApplyPayload, macChangeRequest, newRandomMac, normalizeMac } from "../src/mac.js";

const target = "02:11:22:33:44:55";
const interfaceId = "11111111-1111-1111-1111-111111111111";
function readyPlan(mode = "manual") {
  return { interface_id: interfaceId, mode, previous_mac: "02:00:00:00:00:01", target_mac: target,
    plan_token: "synthetic-server-preview-token", can_apply: true, rollback_script: "Synthetic rollback fixture" };
}
test("manual MAC parsing handles supported forms and rejects unsafe values", () => {
  for (const value of [target, target.toLowerCase(), target.replaceAll(":", "-"), target.replaceAll(":", "")]) {
    assert.equal(normalizeMac(value), target);
  }
  for (const value of ["0".repeat(12), "ff:ff:ff:ff:ff:ff", "01:00:5e:00:00:fb", "02:11-22:33:44:55", "not a MAC"]) {
    assert.throws(() => normalizeMac(value));
  }
});
test("random MAC generation sets local bit, clears multicast and avoids local collisions", () => {
  for (let index = 0; index < 64; index += 1) {
    const value = newRandomMac([target]);
    assert.equal(parseInt(value.slice(0, 2), 16) & 3, 2);
    assert.notEqual(value, target);
  }
  assert.throws(() => newRandomMac([target], { getRandomValues(bytes) { bytes.set([2, 17, 34, 51, 68, 85]); return bytes; } }));
});
test("apply binds the exact preview and factory restore omits replacement", () => {
  const plan = { interface_id: "11111111-1111-1111-1111-111111111111", mode: "random", previous_mac: "02:00:00:00:00:01", target_mac: target, plan_token: "synthetic-server-preview-token" };
  assert.equal(macApplyPayload(plan).mac_address, target);
  assert.equal(macApplyPayload(plan).expected_mac, plan.previous_mac);
  assert.equal(macApplyPayload(plan).acknowledgement, "CHANGE LOCAL MAC");
  assert.equal(macApplyPayload(plan).plan_token, plan.plan_token);
  assert.throws(() => macApplyPayload({ ...plan, plan_token: undefined }));
  assert.equal(macApplyPayload({ ...plan, mode: "restore" }).mac_address, null);
});
test("request normalizes entered addresses and omits replacement for factory restore", () => {
  assert.deepEqual(macChangeRequest(interfaceId, "manual", target.replaceAll(":", "-")),
    { interface_id: interfaceId, mode: "manual", mac_address: target });
  assert.deepEqual(macChangeRequest(interfaceId, "restore", "ignored input"),
    { interface_id: interfaceId, mode: "restore", mac_address: null });
  assert.equal(macChangeRequest(interfaceId, "random", target).mac_address, target);
  assert.throws(() => macChangeRequest("", "manual", target));
  assert.throws(() => macChangeRequest(interfaceId, "unknown", target));
  assert.throws(() => macChangeRequest(interfaceId, "manual", "invalid"));
});
for (const mode of ["manual", "random", "restore"]) {
  test(`one action prepares and immediately applies ${mode} MAC without a user confirmation`, async () => {
    const calls = [];
    const plan = readyPlan(mode);
    const result = { status: "APPLIED", actual_mac: target };
    const payload = macChangeRequest(interfaceId, mode, target);
    const changed = await changeMacDirectly(payload, {
      async prepare(request) { calls.push("prepare"); assert.deepEqual(request, payload); return plan; },
      onPrepared(prepared) { calls.push("prepared"); assert.equal(prepared, plan); },
      async apply(request) {
        calls.push("apply");
        assert.deepEqual(request, macApplyPayload(plan));
        assert.equal(request.mac_address, mode === "restore" ? null : target);
        return result;
      },
    });
    assert.deepEqual(calls, ["prepare", "prepared", "apply"]);
    assert.equal(changed.plan, plan);
    assert.equal(changed.result, result);
  });
}
test("a preparation failure never dispatches a MAC mutation", async () => {
  await assert.rejects(changeMacDirectly({}, {
    async prepare() { throw new Error("Unsupported driver"); },
    async apply() { assert.fail("Mutation was dispatched"); },
  }), /Unsupported driver/);
});
test("a non-elevated backend stops before apply", async () => {
  await assert.rejects(changeMacDirectly({}, {
    async prepare() { return { ...readyPlan(), can_apply: false }; },
    async apply() { assert.fail("Non-elevated mutation was dispatched"); },
  }), /Yönetici/);
});
test("missing internal plan token stops before apply", async () => {
  await assert.rejects(changeMacDirectly({}, {
    async prepare() { return { ...readyPlan(), plan_token: undefined }; },
    async apply() { assert.fail("Unsigned mutation was dispatched"); },
  }), /planı oluşturulamadı/);
});
test("closing the panel during preparation prevents a delayed mutation", async () => {
  assert.equal(await changeMacDirectly({}, {
    async prepare() { return readyPlan(); },
    isActive: () => false,
    onPrepared() { assert.fail("Closed panel was updated"); },
    async apply() { assert.fail("Closed panel dispatched a mutation"); },
  }), null);
});
test("mutation errors retain rollback details and are not automatically retried", async () => {
  let saved;
  let calls = 0;
  await assert.rejects(changeMacDirectly({}, {
    async prepare() { return readyPlan(); },
    onPrepared(plan) { saved = plan; },
    async apply() { calls += 1; throw new Error("Network disconnected; state unknown"); },
  }), /state unknown/);
  assert.equal(calls, 1);
  assert.equal(saved.rollback_script, "Synthetic rollback fixture");
});
test("driver mismatch is returned as unverified, not a successful change", async () => {
  const result = { status: "NOT_VERIFIED", actual_mac: "02:00:00:00:00:01" };
  const changed = await changeMacDirectly({}, {
    async prepare() { return readyPlan(); },
    async apply() { return result; },
  });
  assert.equal(changed.result, result);
});
test("every new action obtains a fresh single-use plan", async () => {
  let count = 0;
  const tokens = [];
  const operations = {
    async prepare() { return { ...readyPlan(), plan_token: `synthetic-plan-${++count}` }; },
    async apply(request) { tokens.push(request.plan_token); return { status: "APPLIED", actual_mac: target }; },
  };
  await changeMacDirectly({}, operations);
  await changeMacDirectly({}, operations);
  assert.deepEqual(tokens, ["synthetic-plan-1", "synthetic-plan-2"]);
});
test("MAC panel submits directly without a preview step or confirmation checkbox", () => {
  const panel = readFileSync(new URL("../src/MacManagementPanel.jsx", import.meta.url), "utf8");
  const workbench = readFileSync(new URL("../src/SecurityWorkbenchModal.jsx", import.meta.url), "utf8");
  assert.match(workbench, /\["mac", "MAC management", "MAC"\]/);
  assert.match(workbench, /<MacManagementPanel \/>/);
  assert.match(panel, /onSubmit=\{apply\}/);
  assert.match(panel, /changeMacDirectly\(macChangeRequest\(selected, mode, mac\)/);
  assert.match(panel, /busy \|\| !supported \|\| !state\.can_apply/);
  assert.match(panel, /changing\.current = true/);
  assert.match(panel, /Yönetici scriptini indir/);
  assert.doesNotMatch(panel, /Değişikliği önizle|acknowledged|type="checkbox"|window\.confirm/);
  assert.match(panel, /aegis-mac-rollback\.ps1/);
  assert.doesNotMatch(panel, /localStorage|sessionStorage/);
});
