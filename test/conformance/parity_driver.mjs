// parity_driver.mjs — the JS half of the GENERATIVE Go==JS parity check.
//
// It is the batched sibling of conformance.test.mjs: instead of loading committed
// fixtures, it reads a single batch file written by the Go generator
// (test/conformance parity_gen_test.go), runs edge/runtime/interpreter.js decide()
// over every generated (IR, input), and compares the JS decision to the Go golden
// the generator already computed (via the SAME evalCase the committed conformance
// suite uses). One node process evaluates thousands of generated cases.
//
// The batch JSON shape (written by Go):
//   { "batches": [ { "name": "...", "ir": {…}, "cases": [ { "input": {…}, "want": {…} } ] } ] }
//
// Output (stdout, JSON): { "total": N, "mismatches": [ { name, caseIndex, wantS, gotS } ],
//                          "threw": [ { name, caseIndex, error } ] }
// Exit 0 when no mismatch and nothing threw; exit 1 otherwise. The Go side parses
// this, maps a failing `name` back to the generating config + request, and reports
// the minimized divergence.
//
// Usage:  node parity_driver.mjs <batch.json>

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { decide } from "../../edge/runtime/interpreter.js";

const here = dirname(fileURLToPath(import.meta.url));

// stableStringify — canonical JSON with sorted object keys (identical to the one in
// conformance.test.mjs), so two structurally-equal decisions compare equal regardless
// of key order or how each side happened to serialize.
function stableStringify(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(v[k])).join(",") + "}";
}

const path = process.argv[2];
if (!path) {
  console.error("usage: node parity_driver.mjs <batch.json>");
  process.exit(2);
}

const batch = JSON.parse(readFileSync(path, "utf8"));
const out = { total: 0, mismatches: [], threw: [] };

for (const b of batch.batches || []) {
  const ir = b.ir;
  (b.cases || []).forEach((c, i) => {
    out.total++;
    let got;
    try {
      got = decide(ir, c.input);
    } catch (e) {
      out.threw.push({ name: b.name, caseIndex: i, error: String(e && e.stack ? e.stack : e) });
      return;
    }
    const gotS = stableStringify(got);
    const wantS = stableStringify(c.want);
    if (gotS !== wantS) {
      out.mismatches.push({ name: b.name, caseIndex: i, wantS, gotS });
    }
  });
}

process.stdout.write(JSON.stringify(out));
process.exit(out.mismatches.length === 0 && out.threw.length === 0 ? 0 : 1);
