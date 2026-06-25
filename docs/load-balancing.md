# Load balancing (`internal/lb`)

`internal/lb` is cadish's load-balancing layer: an **`Upstream`** is a named pool
of backends that picks one backend per request according to a **policy**, keeps
the eligible set healthy with **active probes** and **passive ejection**, and
tracks pod/IP churn behind **`dns://` / `k8s://` targets** with no reload. It is
pure-stdlib (`net`, `crypto/md5`, `hash/*`, `time`) — no external dependencies.

An `Upstream` **is an `origin.Origin`** (`Fetch(ctx, *Request) (*Response,
error)`), so the server treats a load-balanced pool exactly like any other
origin. A `route @x -> web` makes the `web` upstream the origin for matching
requests; it can sit anywhere a plain origin can, including inside an
`origin chain`. The streaming/ownership contract from `internal/origin` is
honored verbatim — the per-backend fetch is delegated to an httporigin client and
the `origin.Response` is returned essentially unchanged (see *Connection
accounting* below).

## Config (the `upstream` / `cluster` directives)

```
upstream web {
    to        k8s://cadish-upstream:8080   # repeatable; ≥1 required
    to        http://10.0.0.7:8080
    sticky    by cookie PHPSESSID else client_ip
    health    GET / expect 301 interval 5s window 6 threshold 3
    timeout   connect 5s first_byte 600s between_bytes 30s
    max_conns 800
}

cluster peers {
    to        k8s://cadish-peers:6081
    shard_by  url
}
```

`ParseUpstream(*cadishfile.Directive) (Config, error)` and
`ParseCluster(...)` turn those blocks into a `Config`. Both accept the same inner
directives; validation produces **positioned** `*cadishfile.ParseError`s
(`file:line:col: message`). Inner directives:

| Directive | Meaning |
|-----------|---------|
| `to URL...` | One or more backend targets (repeatable). At least one required. |
| `policy round_robin\|least_conn\|sticky\|shard` (alias `lb`) | Explicit policy. |
| `sticky by cookie NAME [else SRC]` / `sticky by client_ip` | Sets `sticky` policy + records how the **server** should derive the routing key. |
| `shard_by url\|key` | Sets `shard` policy; hash the URL or the routing key. |
| `health METHOD PATH expect CODE interval D window N threshold T` | Active probe spec. |
| `timeout [connect D] [first_byte D] [between_bytes D]` | Per-backend transport timeouts. |
| `max_conns N` | Per-backend concurrent in-flight cap (0 = unlimited). |
| `host_header preserve\|origin\|VALUE` | Host sent upstream (default `preserve`). See [cadishfile-reference](cadishfile-reference.md#host_header--which-host-the-origin-sees). |
| `sni <server-name>` | TLS ClientHello server name for HTTPS backends (explicit-only). See [cadishfile-reference](cadishfile-reference.md#sni--http_reuse--tls-server-name--connection-reuse). |
| `http_reuse never` | Disable backend connection reuse (`DisableKeepAlives`); only `never` is supported. |
| `replicas N` | Consistent-hash virtual-node count (advanced/tests). |

Policy is inferred when not explicit: a `sticky` line ⇒ `sticky`, a `shard_by`
line ⇒ `shard`, otherwise `round_robin`. `sticky` and `shard_by` are mutually
exclusive.

## Policies

All selection considers only **eligible** backends: healthy (per active health),
not passively ejected, and under `max_conns`.

- **`round_robin`** (default) — even rotation over eligible backends.
- **`least_conn`** — the eligible backend with the fewest in-flight requests.
- **`sticky`** — consistent-hash the **routing key** (a cookie value or client
  IP, supplied by the server) onto a ring so a key pins to one backend. If that
  backend is ineligible the key **rehashes to the next eligible backend**
  clockwise; every other key stays put.
- **`shard`** — consistent-hash the **shard key** (the request URL for
  `shard_by url`, or the routing key for `shard_by key`). This is the
  peer-cache-sharding case (the old `X-Shard` VCL).

### Consistent-hash ring

`sticky` and `shard` use a Ketama-style ring (`ring.go`): each backend is placed
at `replicas` (default 160) virtual nodes derived 4-at-a-time from MD5 digests; a
key is owned by the first backend clockwise from the key's hash. **Adding or
removing a backend reshuffles only ≈ 1/N of keys** — the keys in that backend's
arcs — never the whole keyspace. Health-driven skips are done by *walking* the
ring past ineligible nodes at lookup time (not by rebuilding it), so a flapping
backend's keys rehash to its neighbour while all other keys are unaffected.

## Active health checking

`health METHOD PATH expect CODE interval D window N threshold T` runs an active
prober per backend. The state machine (`healthFSM`) keeps a sliding window of the
last **N** outcomes: a backend goes **UP** after **T** successes in the window
and **DOWN** after **T** failures. A "success" is *response status == CODE*; any
transport error or other status is a failure.

- With a health spec, backends start **DOWN** until they earn `T` successes — so
  traffic is gated until a backend is proven. (Without a health spec, backends
  are always eligible.)
- The prober is injectable (`Doer` interface, `WithProbeDoer`) so tests never
  touch the network.

**Passive ejection** complements active checks: consecutive connection/5xx
failures on real `Fetch`es increment a per-backend streak; at the threshold
(default 5) the backend is ejected for a cooldown (default 30s, `WithPassiveEjection`).
Any success — or a definitive 404/4xx, which means the backend answered fine —
resets the streak.

## Dynamic resolution

A backend `to` target is one of:

| Syntax | Behaviour |
|--------|-----------|
| `http://host:port` / `https://host:port` | **Static**: one endpoint; DNS resolved by the HTTP client per request. |
| `dns://host:port` | **Dynamic**: `host` is re-resolved (A/AAAA) every `resolve` interval (default 30s); each address becomes an endpoint. |
| `k8s://service[.namespace]:port` | **Dynamic, Kubernetes-native**: resolved through an injected `EndpointResolver` (an informer + warm cache, `internal/k8s`) to the service's current **ready pod endpoints** (named ports → numbers), re-resolved on the periodic timer **and** poked sub-second on pod churn via `Watch`. Absent a wired resolver the pool simply has no endpoints. |

Re-resolution updates the backend set **with no reload**: endpoints that persist
keep their existing health/in-flight/ejection state (same backend object), new
addresses get fresh backends, vanished addresses are dropped, and a fresh ring is
built. A target whose resolution **fails** retains its current backends (a
transient DNS blip never blackholes a working pool). The DNS resolver is injectable
(`Resolver` interface, `WithResolver`); the Kubernetes endpoint resolver is injected
with `WithEndpointResolver` (the server wires a shared one when any `k8s://` target
is present).

## Timeouts & connection accounting

`connect` and `first_byte` are wired into the per-backend HTTP client
(dial/TLS-handshake timeout and response-header timeout respectively); the body
transfer is **uncapped** and governed by the request context, per the origin
streaming contract. `between_bytes` is parsed and recorded but **not enforced
today** — enforcing it would mean wrapping the body, and the contract requires the
streaming body to pass through unchanged; it is reserved for a future body-stall
guard.

`max_conns` is a true per-backend cap on concurrent in-flight requests, held for
the **whole streaming lifetime**. To do that without buffering, `Fetch` wraps the
response body in a transparent `trackedBody` whose only behaviour is to release
the in-flight/capacity slot exactly once when the caller `Close()`s it. Reads
pass straight through (no buffering); the tee/streaming contract is preserved.

## Failover

`Upstream.Fetch` selects an eligible backend, delegates, and **fails over** to
another eligible backend on a connection error, a 5xx, or a capacity miss —
retrying until one succeeds, a definitive answer arrives (200/206/404/other 4xx),
or no eligible backend remains (`ErrNoBackend`, which the origin layer treats as a
connection-class miss). When a request ends with no eligible backend (e.g. the sole
backend is failing its health check), the client receives **`503 Service
Unavailable`** — "no upstream available right now, retry" — rather than `502 Bad
Gateway` (which means "an upstream replied, but badly"). A 404 (`origin.ErrNotFound`)
is a real answer and is surfaced immediately for the origin chain above to act on.

## The routing-key integration seam (what the server must feed)

Two policies need a per-request key the **server** computes (it already has it as
the `{sticky}` normalizer): `sticky` and `shard_by key`. Rather than widen the
backend-agnostic `origin.Request`, the key travels in the **context**:

```go
// server side (M5b): compute the sticky/shard key, then:
ctx = lb.WithRoutingKey(ctx, stickyValue)
resp, err := upstream.Fetch(ctx, req)   // Upstream reads it via lb.RoutingKey(ctx)
```

| Policy | Routing key |
|--------|-------------|
| `round_robin` / `least_conn` | ignored |
| `sticky` | **required**; absent/empty ⇒ falls back to round-robin for that request |
| `shard_by url` | ignored — the request `Key` (URL path) is hashed instead |
| `shard_by key` | **required** (same fallback as sticky) |

This is the **only** thing M5b must wire beyond constructing the `Upstream` and
calling `Start(ctx)`: compute the `{sticky}` value and attach it with
`WithRoutingKey` before `Fetch`. `origin.Request` and `origin.Origin` are
unchanged. The `StickySpec` returned in the `Config` tells the server *how* to
compute the value (which cookie, the `client_ip` fallback). The `client_ip` is the
**trusted-proxy-resolved** client address: an `X-Forwarded-For` hop is honored only
when the immediate peer is a configured `trust_proxy`, so a spoofed `XFF` from an
untrusted client cannot steer routing.

## Public API

- `Config`, `Target`, `Policy`, `ShardKey`, `StickySpec`, `HealthSpec`,
  `Timeouts` — the plain config types.
- `ParseUpstream(d) (Config, error)`, `ParseCluster(d) (Config, error)`.
- `New(cfg, ...Option) (*Upstream, error)` — validates, does an initial
  resolution, returns a ready (but not-yet-probing) pool.
- `(*Upstream).Start(ctx)` — launches background health probing + re-resolution
  (both stop when `ctx` is cancelled). Idempotent.
- `(*Upstream).Fetch(ctx, *origin.Request) (*origin.Response, error)` — the
  `origin.Origin` implementation.
- `WithRoutingKey(ctx, key)`, `RoutingKey(ctx)` — the routing-key seam.
- Options: `WithResolver`, `WithEndpointResolver`, `WithOriginFactory`,
  `WithProbeDoer`, `WithClock`, `WithResolveInterval`, `WithPassiveEjection`.
- Interfaces for injection/testing: `Resolver`, `EndpointResolver` (k8s pod
  discovery), `Doer`, `OriginFactory`. `Endpoint` is one resolved `k8s://` ip:port.
- `ErrNoBackend`.

## Testing

`internal/lb` is tested with no real network: a fake `Resolver`, a fake `Doer`, a
fake clock, in-memory `OriginFactory`s, and `httptest` backends for the
end-to-end paths. Coverage spans ring distribution + add/remove stability +
health-aware rehash, every policy, the health FSM across window/threshold,
dynamic re-resolution (incl. failure-retention), failover, sticky routing,
passive ejection, and `max_conns`. All race-clean (`go test -race`).
