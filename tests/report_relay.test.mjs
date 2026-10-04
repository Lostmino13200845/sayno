// Tests the report relay's validation and email building without Google services (run by CI: node tests/report_relay.test.mjs).
import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const src = fs.readFileSync(new URL("../backend/report-relay.gs", import.meta.url), "utf8");
const ctx = vm.createContext({ console });
vm.runInContext(src, ctx);
const build = (d) => vm.runInContext(`buildReport(${JSON.stringify(d)}, new Date("2026-10-04T12:00:00Z"))`, ctx);

let n = 0;
const ok = (name, fn) => { fn(); n++; console.log("PASS", name); };

ok("website report goes to the team and the anti-phishing organisations", () => {
  const r = build({ type: "website", fields: { url: "https://rbc-card-activation.help/secure", who: "RBC", via: "Text message" }, asked: ["Card number, expiry or CVV"] });
  assert.equal(r.ok, true);
  assert.deepEqual(r.to, ["sayoshield@gmail.com", "reportphishing@apwg.org"]);
  assert.match(r.subject, /^\[SAYNO report\] Scam website or link: rbc-card-activation\.help$/);
  assert.match(r.body, /Link: https:\/\/rbc-card-activation\.help\/secure/);
  assert.match(r.body, /Pretending to be: RBC/);
  assert.match(r.body, /- Card number, expiry or CVV/);
  assert.match(r.body, /Reported: 2026-10-04 \(UTC\)/);
  assert.match(r.body, /name and email address are not included/);
});

ok("phone call without a link stays with the team", () => {
  const r = build({ type: "call", fields: { sender: "+1 555 0100", who: "Canada Revenue Agency (CRA)" }, asked: ["Pay a fine or tax debt"] });
  assert.equal(r.ok, true);
  assert.deepEqual(r.to, ["sayoshield@gmail.com"]);
});

ok("scam email goes out even without a link", () => {
  const r = build({ type: "email", fields: { sender: "billing@bad.example", message: "Pay now" }, asked: [] });
  assert.equal(r.ok, true);
  assert.deepEqual(r.to, ["sayoshield@gmail.com", "reportphishing@apwg.org"]);
});

ok("rejects unknown types, bad links, bad addresses and missing blanks", () => {
  assert.equal(build({ type: "nope", fields: {} }).ok, false);
  assert.equal(build({ type: "website", fields: { url: "javascript:alert(1)" } }).ok, false);
  assert.equal(build({ type: "website", fields: {} }).ok, false);
  assert.equal(build({ type: "email", fields: { sender: "not-an-email", message: "x" } }).ok, false);
  assert.equal(build({ type: "text", fields: { sender: "123" } }).ok, false);
  assert.equal(build(null).ok, false);
});

ok("header injection and control characters are stripped", () => {
  const r = build({ type: "website", fields: { url: "https://evil.example/a", who: "RBC\r\nBcc: victim@example.com" }, asked: ["x\u0000y"] });
  assert.equal(r.ok, true);
  assert.ok(!/\r/.test(r.subject) && !/\n/.test(r.subject));
  assert.ok(!r.body.includes("\u0000"));
});

ok("recipients can never come from the request", () => {
  const r = build({ type: "website", to: "attacker@example.com", cc: "x@y.z", fields: { url: "https://evil.example/", to: "attacker@example.com" } });
  assert.equal(r.ok, true);
  assert.ok(!r.to.includes("attacker@example.com"));
});

ok("lengths are capped", () => {
  const r = build({ type: "text", fields: { sender: "1".repeat(900), message: "a".repeat(9000) } });
  assert.equal(r.ok, true);
  assert.ok(r.body.length < 3000);
});

console.log(`${n} relay tests passed`);
