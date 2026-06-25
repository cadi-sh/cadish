# cadish documentation

cadish is a single-binary HTTP cache server — **one binary: HTTP caching, TLS/ACME,
load balancing, and Kubernetes ingress.** This is the documentation index; start at
[Getting started](getting-started.md).

## Start here

- **[Getting started](getting-started.md)** — install, the command surface, your
  first Cadishfile, and the 60-second "cache an HTTP origin behind HTTPS"
  walkthrough.
- **[Cookbook](cookbook.md)** — copy-pasteable recipes for real scenarios (asset
  CDN, API cache, multi-origin failover, video edge, sticky sessions,
  device-varied cache, behind-an-LB), each with a runnable `examples/` config.
- **[Migrating from Varnish](migrating-from-varnish.md)** — the VCL → Cadishfile
  idiom map and `cadish adapt`, the converter that does the mechanical 80%.

## The Cadishfile

- **[Cadishfile reference](cadishfile-reference.md)** — every matcher and
  directive, by lifecycle phase, with syntax and examples.
- **[Cadishfile grammar](cadishfile-grammar.md)** — the lexical grammar (tokens,
  quoting, line continuations, comments, `{$ENV}` placeholders).
- **[`cadish check`](check.md)** — the config *complexity report* (regex/request,
  dead rules, cost) and how to read it.
- **[`cadish logs`](logs.md)** — live debug logging: `cadish logs` is the
  NCSA-style access tail (`logs -f`, filters, NCSA format); the
  per-request decision trace is a separate facility, enabled with
  `cadish run -trace`.
- **[`cadish edge`](edge.md)** — Cadish Edge (Cloudflare Workers): run the same
  Cadishfile as an additive caching tier at the edge. `cadish edge build` projects
  the config to the versioned edge IR; `deploy`/`enable`/`disable` manage the
  Worker. Runnable end-to-end.

## Operating cadish

- **[Deployment](deployment.md)** — systemd, the Docker image, ports &
  capabilities, persistent volumes, `cadish check` in CI, tuning.
- **[Ingress controller](ingress-controller.md)** — run cadish in-cluster as a
  Kubernetes Ingress controller (`cadish ingress`): Ingress objects as source of
  truth, `cadi.sh/policy` ConfigMaps, TLS, HA/leader election.
- **[Releasing](releasing.md)** — how releases are cut (goreleaser + the tag
  workflow), versioning, and the container image.

## Subsystems (how it works inside)

- **[Pipeline](pipeline.md)** — the per-request matcher/directive evaluation
  engine and the request lifecycle.
- **[Cache](cache.md)** — the two-tier RAM+NVMe store, coalescing, grace/SWR.
- **[Origin](origin.md)** — HTTP/S3 origins, the streaming tee contract,
  `origin chain` fallback, and CloudFront re-signing.
- **[Load balancing](load-balancing.md)** — upstreams, health checks, sticky and
  sharded backends, dynamic `dns://`/`k8s://` resolution.
- **[TLS & ACME](tls.md)** — automatic HTTPS, HostPolicy, the `:80` challenge +
  redirect, hardening, and the live-ACME pebble test.
- **[Server](server.md)** — how the handler wires pipeline + cache + origin + TLS
  into the caching reverse proxy.

## Performance

- **[Benchmarks](benchmarks.md)** — the hot-path benchmark suite and baseline.

## Releases

- **[CHANGELOG](../CHANGELOG.md)** — what shipped in each release.

## Contributing

- **[CONTRIBUTING](../CONTRIBUTING.md)** — ground rules, the build bar, and how to
  propose changes.
- **[Security policy](../SECURITY.md)** — how to report a vulnerability
  (privately, to security@cadi.sh).
