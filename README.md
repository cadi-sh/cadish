# cadish

> **One binary: HTTP caching, TLS/ACME, load balancing, and Kubernetes ingress.**

cadish is a single-binary HTTP cache server written in Go. It replaces the
reverse-proxy + cache + load-balancer + ingress stack you normally chain together
with one process and one config file:

- **Cache** — two-tier RAM + NVMe, request coalescing, grace / stale-while-revalidate.
- **TLS** — built-in termination with automatic ACME certificates. No proxy in front.
- **Load balancing** — upstreams, health checks, sticky / sharded backends.
- **Config** — a flat, declarative `Cadishfile`. No VCL.
- **`cadish check`** — a config *complexity report*: regex-per-request, dead
  rules, estimated cost per request. Nothing else in the ecosystem has this.

> 🚧 **Status: BETA — ships v1 plus the full v2 directive set.** A single-binary
> HTTPS caching reverse proxy that serves a full production config end-to-end, plus
> the v2 normalizers (`{device}`/`{geo}`/`normalize`), multi-tenant `{tenant}` +
> `group` inheritance, and `replace` body transforms. See [`CHANGELOG.md`](CHANGELOG.md)
> for what shipped in each release.

## Why cadish

Most stacks assemble the edge from separate tools: one for TLS, one for load
balancing, one for caching, one for ingress. Each is excellent on its own, but
running them together means several processes, several config languages, and glue
code in between.

cadish does those jobs in one binary, driven by one declarative config: TLS
termination with ACME, load balancing, HTTP caching (RAM and NVMe, local and at
the edge), and Kubernetes ingress. The config language stays small and covers
real-world use cases first. New ones are welcome as long as they don't cost
performance, because speed is a hard constraint, not an afterthought.

## Example `Cadishfile`

```
example.com, *.example.com {
    tls { acme you@example.com }

    cache { ram 10GiB; disk /var/cache/cadish 2TiB }

    upstream web {
        to      https://origin.example.com
        sticky  by cookie PHPSESSID else client_ip
        health  GET / expect 301 interval 5s
    }

    @nocache path /panel/* /private/* /checkout/*
    pass     @nocache
    pass     method POST

    cache_ttl status 404 410   ttl 60s grace 1h
    cache_ttl default          ttl 2s  grace 24h
}
```

## Install

**Download a release binary** (linux/darwin, amd64/arm64) from the
[releases page](https://github.com/cadi-sh/cadish/releases):

```bash
# pick the asset for your OS/arch, then:
tar xzf cadish_*_linux_amd64.tar.gz
./cadish version
```

**Go install** (needs Go 1.26+):

```bash
go install github.com/cadi-sh/cadish/cmd/cadish@latest
```

**Container image** (multi-arch, from GHCR):

```bash
docker run --rm -p 80:80 -p 443:443 \
  -v "$PWD/Cadishfile:/etc/cadish/Cadishfile:ro" \
  ghcr.io/cadi-sh/cadish:latest
```

See [docs/getting-started.md](docs/getting-started.md) for the first-run
walkthrough and [docs/deployment.md](docs/deployment.md) / the
[Helm chart](deploy/helm/cadish) for production.

## Documentation

The full docs are in **[`docs/`](docs/README.md)** — getting started, the
[cookbook](docs/cookbook.md), the [Cadishfile reference](docs/cadishfile-reference.md),
[migrating from Varnish](docs/migrating-from-varnish.md), and deployment. New
contributors: see [CONTRIBUTING](CONTRIBUTING.md).

## Build & test

```bash
make build     # go build -> ./build/cadish
make test      # go test ./...
make race      # go test ./... -race
make check     # go vet ./... && go test ./...
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
