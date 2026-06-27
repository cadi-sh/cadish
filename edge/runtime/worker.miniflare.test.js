// worker.miniflare.test.js — runs the edge runtime inside the REAL Cloudflare
// Workers runtime (workerd) via @cloudflare/vitest-pool-workers, exercising the
// genuine Cache API (caches.default) and a real KV namespace binding (CADISH_KV).
// This is the binding-fidelity complement to the dependency-free runtime.test.mjs.
//
// Run: npm install && npm run test:miniflare   (in edge/runtime/)
import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import { handle } from "./entry.js";

// Minimal storefront-ish IR: cache_key = url, default ttl 60s/grace 1h, a
// +cache_status X-Cache header. edge default "local" (L1 only).
const IR_LOCAL = {
  irVersion: 5,
  site: { hosts: ["example.com"] },
  upstream: {},
  matchers: {},
  recv: {},
  key: { tokens: [{ kind: "url" }] },
  response: {
    ttl: [{ selKind: "default", ttl: "60s", grace: "1h0m0s" }],
    headerResp: [{ scope: { always: true }, ops: [{ op: "cache_status", name: "X-Cache" }] }],
  },
  deliver: { cacheStatusHeader: "X-Cache" },
  edge: { default: "local" },
};

// Same, but default tier "distribute" so cacheable objects also land in L2 (KV).
const IR_DISTRIBUTE = { ...IR_LOCAL, edge: { default: "distribute" } };

function req(path) {
  return new Request("https://example.com" + path);
}

function originStub(status, headers, body = "BODY") {
  let calls = 0;
  const fn = async () => {
    calls++;
    return new Response(body, { status, headers });
  };
  Object.defineProperty(fn, "calls", { get: () => calls });
  return fn;
}

async function run(ir, path, fetchImpl) {
  const ctx = createExecutionContext();
  const res = await handle(req(path), env, ctx, { ir, fetchImpl, originBase: "https://origin.test" });
  await waitOnExecutionContext(ctx); // drains waitUntil (deferred cache writes)
  return res;
}

describe("Cadish Edge runtime on workerd (real Cache API + KV)", () => {
  it("MISS then HIT via the real Cache API", async () => {
    const origin = originStub(200, { "Content-Type": "text/html" });
    const r1 = await run(IR_LOCAL, "/cache-api-a", origin);
    expect(r1.headers.get("X-Cache")).toBe("MISS");
    const r2 = await run(IR_LOCAL, "/cache-api-a", origin);
    expect(r2.headers.get("X-Cache")).toBe("HIT");
    expect(origin.calls).toBe(1);
  });

  it("distribute writes to the real KV namespace (L2)", async () => {
    const origin = originStub(200, { "Content-Type": "text/html" });
    const r1 = await run(IR_DISTRIBUTE, "/kv-b", origin);
    expect(r1.headers.get("X-Cache")).toBe("MISS");
    // The cache key for `url` on /kv-b is "/kv-b"; cache-tiers stores it under that key.
    const stored = await env.CADISH_KV.get("/kv-b", { type: "arrayBuffer" });
    expect(stored).not.toBeNull();
    const r2 = await run(IR_DISTRIBUTE, "/kv-b", origin);
    expect(r2.headers.get("X-Cache")).toBe("HIT");
  });

  it("security invariant: a Set-Cookie response is never cached", async () => {
    const origin = originStub(200, { "Content-Type": "text/html", "Set-Cookie": "sid=x; Path=/" });
    await run(IR_LOCAL, "/setcookie-c", origin);
    const r2 = await run(IR_LOCAL, "/setcookie-c", origin);
    expect(r2.headers.get("X-Cache")).toBe("MISS");
    expect(origin.calls).toBe(2);
  });
});
