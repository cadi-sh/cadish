# Getting started

cadish is a single-binary HTTP cache server: **one binary: HTTP caching, TLS/ACME,
load balancing, and Kubernetes ingress.** It terminates TLS (with automatic Let's Encrypt certificates),
caches your origin in a two-tier RAM+NVMe cache, load-balances upstreams, and is
configured by a flat, readable `Cadishfile` — no proxy in front, no VCL.

## Install

cadish is a Go program (module `github.com/cadi-sh/cadish`, Go 1.26+).

```sh
# Build the binary from a checkout:
go build -o cadish ./cmd/cadish

# …or install it onto your PATH:
go install github.com/cadi-sh/cadish/cmd/cadish@latest

cadish version
```

A container image is provided too — see [deployment.md](deployment.md).

## The commands

```
cadish run    [-config Cadishfile]   start the server
cadish check  [-config Cadishfile]   validate config + print a complexity report
cadish fmt    [-w] [Cadishfile...]   format Cadishfile(s)
cadish adapt  [-o FILE] <file.vcl>   convert a Varnish VCL to a Cadishfile skeleton
cadish version                       print version information
cadish help                          show help
```

`reload`, `logs`, `edge`, `ingress`, and `gateway` round out the set (see
`cadish help`) — hot-reload a running server, tail the access log, build the
Cloudflare Workers edge tier, and run as a Kubernetes Ingress or Gateway API
controller.

Migrating from Varnish? Start with `cadish adapt your.vcl -o Cadishfile` — it
converts the mechanical idioms and flags the rest with `# TODO(adapt)`. See
[migrating-from-varnish.md](migrating-from-varnish.md).

## Your first Cadishfile

A `Cadishfile` is a list of **sites**. Each site is a set of host addresses
followed by a `{ … }` block of **directives**. Here is the smallest useful
config — terminate HTTPS for one host and cache an HTTP origin:

```
example.com {
    tls {
        acme you@example.com        # automatic Let's Encrypt cert for example.com
    }

    cache {
        ram 2GiB                    # hot objects in memory
    }

    upstream backend {
        to https://origin.internal:8080
    }

    # Bypass the cache for the admin area and writes.
    @dynamic path /admin/* /api/*
    pass @dynamic
    pass method POST

    cache_ttl default ttl 5m grace 1h   # cache everything else for 5 min
    header +cache_status X-Cache         # add an X-Cache: HIT/MISS header
}
```

## The 60-second walkthrough: cache an HTTP origin behind HTTPS

1. **Write `Cadishfile`** (above), pointing `to` at your real origin and using a
   hostname whose DNS already points at this machine (ACME validates over the
   public internet on ports 80/443).

2. **Check it** before starting — cadish reports how expensive your config is:

   ```sh
   cadish check -config Cadishfile
   ```

   ```
   cadish check — Cadishfile

   Site: example.com
     Matchers:               1
     Directives:             7
     Regex evals / request:  0   (path_regex/host_regex/regex-valued header on the hot path)
     Directives by phase:    SETUP 3  RECV 2  KEY 0  ORIGIN 1  DELIVER 1
     Est. per-request cost:  3   (1 exact×1 + 1 glob×2 + 0 regex×10)
     Findings:
       warning Cadishfile:19:5: this site caches responses (cache_ttl) but defines no cache_key, so the default key is `method host path` — it OMITS the query string, so e.g. /api?id=1 and /api?id=2 share ONE cache entry (collide). Varnish hashes the query by default: if responses vary by query add `cache_key method host path query` (or `query_allow …` to key only some params, `query_strip …` to drop tracking params); if they do not vary by query, this is safe to ignore  [default-key-omits-query]

   Summary: 1 site, 0 errors, 1 warning
   ```

   A non-zero exit means a real error (printed as `file:line:col: message`). See
   [check.md](check.md) for what the report means.

3. **Run it.** Binding :80/:443 needs privileges (or
   `CAP_NET_BIND_SERVICE` — see [deployment.md](deployment.md)):

   ```sh
   sudo ./cadish run -config Cadishfile
   ```

   cadish binds **:443** (HTTPS, the cached site) and **:80** (the ACME HTTP-01
   challenge, and a 301 redirect to HTTPS for everything else). On the first
   request for `example.com` it obtains a certificate automatically and caches it
   on disk so restarts don't re-issue.

4. **Verify the cache.** Request the same URL twice and watch the `X-Cache`
   header flip from `MISS` to `HIT`:

   ```sh
   curl -sI https://example.com/ | grep -i x-cache   # X-Cache: MISS
   curl -sI https://example.com/ | grep -i x-cache   # X-Cache: HIT
   ```

### No public DNS yet? Run plain HTTP

For local testing without certificates, set `tls off` and cadish serves plain
HTTP on `-addr` (default `:80`):

```
localhost {
    tls off
    cache { ram 256MiB }
    upstream backend { to http://127.0.0.1:9000 }
    cache_ttl default ttl 1m
    header +cache_status X-Cache
}
```

```sh
./cadish run -config Cadishfile -addr :8080
curl -sI http://localhost:8080/   # served by cadish, cached
```

## `run` flags

| Flag | Default | Purpose |
|---|---|---|
| `-config` | `Cadishfile` | path to the config |
| `-addr` | `:80` | HTTP listen address (ACME challenge + HTTPS redirect when TLS is on; the plain-HTTP listener when every site is `tls off`) |
| `-https-addr` | `:443` | HTTPS listen address (used when any site declares `tls`) |
| `-idle-timeout` | `60s` | abort an origin response that stalls mid-stream this long (0 disables) |
| `-acme-cache` | (auto) | directory for cached ACME certificates (empty = default resolution; see [tls.md](tls.md)) |

This is the common subset. See [server.md](server.md) for the full flag list —
`-access-log`, `-log-socket`, `-trace`, `-security-audit-log`, `-max-request-body`,
`-proxy-protocol[-trust]`, `-pidfile`, `-kubeconfig`.

cadish shuts down gracefully on SIGINT/SIGTERM.

## Formatting

`cadish fmt` canonicalizes spacing/indentation (like `gofmt`):

```sh
cadish fmt -w Cadishfile        # rewrite in place
cadish fmt Cadishfile           # print formatted result to stdout
```

## Where to go next

- **[cookbook.md](cookbook.md)** — copy-pasteable recipes for real scenarios
  (asset CDN, API cache, failover, video edge, sticky sessions, device-varied
  cache, behind-an-LB), each with a runnable `examples/` config.
- **[cadishfile-reference.md](cadishfile-reference.md)** — every matcher and
  directive, with syntax and examples.
- **[migrating-from-varnish.md](migrating-from-varnish.md)** — translate a real
  VCL to a Cadishfile.
- **[deployment.md](deployment.md)** — systemd, Docker, tuning, CI.
- **[check.md](check.md)** — reading the complexity report.
- **[tls.md](tls.md)**, **[load-balancing.md](load-balancing.md)**,
  **[cache.md](cache.md)** — subsystem deep-dives.
