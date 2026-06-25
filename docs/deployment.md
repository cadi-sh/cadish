# Deployment

Running cadish in production: process management, the container image, ports and
capabilities, persistent volumes, CI validation, and tuning.

## Ports and capabilities

cadish binds two ports:

- **:443** — HTTPS (the cached sites) and, during the TLS handshake, the
  TLS-ALPN-01 ACME challenge.
- **:80** — the ACME HTTP-01 challenge and a 301 redirect to HTTPS for everything
  else. (When every site is `tls off`, :80 is just the plain-HTTP listener.)

Both are privileged ports. Don't run cadish as root — grant the binary
`CAP_NET_BIND_SERVICE` instead (systemd `AmbientCapabilities`, a container
`securityContext`, or `setcap`). Override the addresses with `-addr` /
`-https-addr` if you terminate elsewhere or run behind an L4 LB.

## Persistent state — two volumes

cadish writes two things that **must** survive restarts:

| Path (default) | What | Why it must persist |
|---|---|---|
| `/var/lib/cadish/acme` | cached ACME certificates | Losing it re-issues every cert on restart and risks Let's Encrypt **rate limits**. |
| `/var/cache/cadish` (your `cache { disk … }` path) | the NVMe cache tier | A cold cache after every restart hammers your origin. |

The ACME cache directory resolves in this order (see [tls.md](tls.md)):
`$CADISH_ACME_CACHE` → `/var/lib/cadish/acme` (when writable) →
`$XDG_DATA_HOME/cadish/acme` → `~/.local/share/cadish/acme`. The `-acme-cache`
flag overrides it. The disk cache directory is whatever you put in
`cache { disk PATH SIZE }`.

## systemd

Run as a dedicated unprivileged user with the bind capability and managed state
directories:

```ini
# /etc/systemd/system/cadish.service
[Unit]
Description=cadish HTTP cache server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/cadish run -config /etc/cadish/Cadishfile -pidfile /run/cadish/cadish.pid
ExecReload=/bin/kill -HUP $MAINPID
PIDFile=/run/cadish/cadish.pid
RuntimeDirectory=cadish
Restart=on-failure
RestartSec=2s

# Unprivileged, but allowed to bind :80/:443.
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Managed, persistent volumes:
#   StateDirectory  -> /var/lib/cadish   (ACME cert cache)
#   CacheDirectory  -> /var/cache/cadish (NVMe cache tier)
StateDirectory=cadish
CacheDirectory=cadish

# Tuning (see below).
Environment=GOMEMLIMIT=12GiB

# Hardening.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Point your `cache { disk … }` at `/var/cache/cadish` and leave the ACME cache at
its default so it lands in `/var/lib/cadish/acme`. Reload + start:

```sh
systemctl daemon-reload
systemctl enable --now cadish
journalctl -u cadish -f          # cadish logs one access line per request to stderr
```

cadish handles SIGINT/SIGTERM with a graceful drain, so `systemctl restart` won't
drop in-flight requests.

### Hot config reload (SIGHUP)

To apply a Cadishfile change **without a restart or a cold cache**, send SIGHUP:

```sh
systemctl reload cadish        # via the ExecReload above
# or directly:
cadish reload -pidfile /run/cadish/cadish.pid
kill -HUP "$(cat /run/cadish/cadish.pid)"
```

The server re-reads + recompiles **the same Cadishfile path it was started with** —
there is no `cadish reload -config NEW.Cadishfile`. To change the config, overwrite
that file in place, then signal the reload. It **atomically swaps** the routing
in place, preserving the warm RAM+NVMe cache, the freshness index, lb state,
and all in-flight requests. lb pools are **diffed**: an upstream whose config is
unchanged keeps its running health/resolve workers and warm health state across the
reload (steady backends are not re-probed); only added/changed pools start and removed
ones stop. **Adding or removing a TLS hostname (ACME or static keypair) is now a hot
reload too** — the `:443` listener is never reopened (D58). A **bad new config is
rejected and the old one keeps serving** (the error is logged to the journal) — a
reload never drops the listener or crashes the process. Validate first with
`cadish check -config … -strict` to see the error before signalling. *First-time*
enabling of TLS/ACME on a server started without it still needs a restart (see
[`server.md`](server.md#hot-reload-sighup-zero-downtime)).

## Docker

A multi-stage [`deploy/Dockerfile`](../deploy/Dockerfile) produces a small
`distroless` image:

```sh
docker build -f deploy/Dockerfile -t cadish:dev .

docker run --rm \
  --cap-add NET_BIND_SERVICE \
  -p 80:80 -p 443:443 \
  -v "$PWD/Cadishfile:/etc/cadish/Cadishfile:ro" \
  -v cadish-acme:/var/lib/cadish \
  -v cadish-cache:/var/cache/cadish \
  cadish:dev
```

The image runs as `nonroot`, exposes 80/443, declares the two volumes, and
defaults to `run -config /etc/cadish/Cadishfile`. On Kubernetes, grant
`CAP_NET_BIND_SERVICE` in the container `securityContext` (or bind high ports +
front with a Service) and back the two volumes with PVCs.

## Kubernetes Ingress controller (`cadish ingress`)

cadish can also run **in-cluster as a drop-in Ingress controller**: instead of a
static Cadishfile, the cluster's `Ingress` objects become the source of truth. The
controller watches `Ingress` / `IngressClass` / `Secret` / `ConfigMap`, translates them
into the same compiled routing cadish builds from a Cadishfile, and hot-swaps the live
config through the same atomic routing swap used by SIGHUP reload. A base Cadishfile
still supplies globals only; sites come from the Ingresses.

See the dedicated guide: **[ingress-controller.md](ingress-controller.md)** (install via
manifests/Helm, the `cadi.sh/policy` ConfigMap pattern, TLS, HA/leader-election,
multiple controllers). Manifests live in
[`deploy/k8s/ingress-controller.yaml`](../deploy/k8s/ingress-controller.yaml) +
[`deploy/k8s/rbac-controller.yaml`](../deploy/k8s/rbac-controller.yaml).

## Validate in CI

`cadish check` is a fast, dependency-free gate — run it on every config change so
a typo or an expensive rule never reaches production:

```yaml
# CI step
- run: go build -o cadish ./cmd/cadish
- run: ./cadish fmt Cadishfile | diff - Cadishfile   # enforce canonical format
- run: ./cadish check -config Cadishfile             # non-zero exit fails the build
```

`cadish check` exits non-zero on errors (parse failures, dead rules under
`-strict`, etc.). Add `-strict` to make warnings fail too, and `-json` to gate on
specific numbers (e.g. fail if `regex_evals_per_request` regresses). See
[check.md](check.md).

## Tuning

cadish is mostly bound by kernel network/IO, not user code, so tuning is about
memory limits and the cache tiers (background in [benchmarks.md](benchmarks.md)).

- **`GOMEMLIMIT`** — set a soft memory ceiling so the Go runtime collects before
  the OOM killer fires. Set it below the container/host limit, accounting for the
  RAM cache budget (`cache { ram … }`) **plus** headroom for connections and the
  runtime. e.g. a 16 GiB box with `ram 8GiB` → `GOMEMLIMIT=12GiB`.
- **RAM vs NVMe tiers** — size `cache { ram … }` for your hot set (latency-
  sensitive small objects) and `disk … ` for the long tail / large media. Large
  objects are served from disk with `sendfile`/page cache, off the Go heap.
- **`-idle-timeout`** — caps how long a stalled origin body ties up a connection
  (default 60s; 0 disables).
- **Upstream limits** — `max_conns`, `timeout connect/first_byte/between_bytes`
  per `upstream` bound origin pressure ([load-balancing.md](load-balancing.md)).

A good starting point: `GOMEMLIMIT` ≈ 75% of the box, `cache { ram }` ≈ 50–60%,
the rest of disk to NVMe, and `cadish check` wired into CI.
