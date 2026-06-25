// vitest config for the Cadish Edge runtime's miniflare tests. These run inside
// the real Cloudflare Workers runtime (workerd) via @cloudflare/vitest-pool-workers,
// so the Cache API (caches.default) and a KV namespace binding (CADISH_KV) behave
// like production — the fidelity the plain-Node runtime.test.mjs cannot give.
//
// Run with `npm run test:miniflare` (needs `npm install` first; the dependency-free
// conformance.test.mjs + runtime.test.mjs are the offline CI gate).
import { defineWorkersConfig } from "@cloudflare/vitest-pool-workers/config";

export default defineWorkersConfig({
  test: {
    include: ["**/*.miniflare.test.js"],
    poolOptions: {
      workers: {
        miniflare: {
          compatibilityDate: "2024-09-23",
          kvNamespaces: ["CADISH_KV"],
        },
      },
    },
  },
});
