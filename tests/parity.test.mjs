// The extension rates links and messages on the device (heuristics.js, engine.js). This checks it gives exactly
// the same scores, levels and findings as the Python engine (tests/parity_vectors.json is written from engine.py).
// Run:  node tests/parity.test.mjs
import { readFileSync } from "node:fs";
import { analyzeUrl } from "../extension/heuristics.js";
import { analyzeText } from "../extension/engine.js";

const vectors = JSON.parse(readFileSync(new URL("./parity_vectors.json", import.meta.url), "utf-8"));
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const pairs = fs => fs.map(f => [f.weight, f.message]);
let bad = 0;
const fail = (what, want, got) => { bad++; console.error(`MISMATCH ${what}\n  python: ${JSON.stringify(want)}\n  js:     ${JSON.stringify(got)}`); };

for (const v of vectors.urls) {
  const r = analyzeUrl(v.url);
  const got = [r.score, r.level, pairs(r.findings)];
  if (!same(got, [v.score, v.level, v.findings])) fail("link " + v.url, [v.score, v.level, v.findings], got);
}
for (const v of vectors.texts) {
  const r = await analyzeText(v.text);
  const got = {
    score: r.score, level: r.level, textScore: r.text.score, textFindings: pairs(r.text.findings),
    urls: r.urls.map(u => ({ score: u.score, level: u.level, findings: pairs(u.findings), url: u.url })),
    emails: r.emails.map(e => ({ score: e.score, level: e.level, findings: pairs(e.findings), email: e.email })),
    advice: r.advice,
  };
  const want = { score: v.score, level: v.level, textScore: v.textScore, textFindings: v.textFindings, urls: v.urls, emails: v.emails, advice: v.advice };
  if (!same(got, want)) fail("message " + JSON.stringify(v.text.slice(0, 60)), want, got);
}
const total = vectors.urls.length + vectors.texts.length;
console.log(bad ? `${bad} of ${total} differ` : `all ${total} link and message verdicts match the Python engine`);
process.exit(bad ? 1 : 0);
