// The extension rates links on the device with heuristics.js; this checks it gives exactly the same score,
// level and findings as the Python engine (tests/parity_vectors.json is written from engine.analyze_url).
// Run:  node tests/parity.test.mjs
import { readFileSync } from "node:fs";
import { analyzeUrl } from "../extension/heuristics.js";

const vectors = JSON.parse(readFileSync(new URL("./parity_vectors.json", import.meta.url), "utf-8"));
let bad = 0;
for (const v of vectors) {
  const r = analyzeUrl(v.url);
  const got = JSON.stringify([r.score, r.level, r.findings.map(f => [f.weight, f.message])]);
  const want = JSON.stringify([v.score, v.level, v.findings]);
  if (got !== want) { bad++; console.error(`MISMATCH ${v.url}\n  python: ${want}\n  js:     ${got}`); }
}
console.log(bad ? `${bad} of ${vectors.length} differ` : `all ${vectors.length} link verdicts match the Python engine`);
process.exit(bad ? 1 : 0);
