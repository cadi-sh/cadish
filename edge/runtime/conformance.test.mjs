// conformance.test.mjs — the JS half of the cross-runtime conformance suite.
//
// Plain Node, NO dependencies (so it runs anywhere node does, in CI without an
// npm install). It loads the SAME generated IR + golden decisions the Go test
// produced (test/conformance/generated/*), runs edge/runtime/interpreter.js over
// every case, and asserts the JS decision equals the Go golden byte-for-byte
// (after canonical JSON ordering). Go green + this green ⇒ the two runtimes are
// synchronized by construction.
//
// Usage:  node edge/runtime/conformance.test.mjs
// Regenerate goldens first with:  CONFORMANCE_UPDATE=1 go test ./test/conformance

import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { decide } from "./interpreter.js";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const fixturesDir = join(repoRoot, "test", "conformance", "fixtures");
const generatedDir = join(repoRoot, "test", "conformance", "generated");

// stableStringify produces a canonical JSON string with object keys sorted, so
// two structurally-equal decisions compare equal regardless of key order.
function stableStringify(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(v[k])).join(",") + "}";
}

function loadJSON(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

let totalCases = 0;
let failures = 0;
const fixtureFiles = readdirSync(fixturesDir)
  .filter((f) => f.endsWith(".json"))
  .sort();

if (fixtureFiles.length === 0) {
  console.error("no fixtures found under", fixturesDir);
  process.exit(1);
}

for (const file of fixtureFiles) {
  const fx = loadJSON(join(fixturesDir, file));
  const name = fx.name;
  let ir, expect;
  try {
    ir = loadJSON(join(generatedDir, name + ".ir.json"));
    expect = loadJSON(join(generatedDir, name + ".expect.json"));
  } catch (e) {
    console.error(
      `✗ ${name}: missing generated files — run \`CONFORMANCE_UPDATE=1 go test ./test/conformance\` first (${e.message})`,
    );
    failures++;
    continue;
  }

  fx.cases.forEach((c, i) => {
    totalCases++;
    const input = {
      ...c.request,
      origin: c.origin,
      cacheStatus: c.cacheStatus,
      // D75/D76 probes: the body-transform inputs and the outage-serving inputs are
      // case-level fields the interpreter reads to produce transformedBody / outage.
      body: c.body,
      isHead: c.isHead,
      isRange: c.isRange,
      originFailed: c.originFailed,
      salvageable: c.salvageable,
      outageStatus: c.outageStatus,
    };
    let got;
    try {
      got = decide(ir, input);
    } catch (e) {
      console.error(`✗ ${name}[${i}]: interpreter threw: ${e.stack || e.message}`);
      failures++;
      return;
    }
    const gotS = stableStringify(got);
    const wantS = stableStringify(expect[i]);
    if (gotS !== wantS) {
      failures++;
      console.error(`✗ ${name}[${i}] MISMATCH`);
      console.error("  want: " + wantS);
      console.error("  got:  " + gotS);
    }
  });
}

if (failures > 0) {
  console.error(`\nFAIL: ${failures} mismatch(es) across ${totalCases} case(s) in ${fixtureFiles.length} fixture(s)`);
  process.exit(1);
}
console.log(`PASS: ${totalCases} case(s) across ${fixtureFiles.length} fixture(s) — Go and JS decide identically`);
