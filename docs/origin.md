# Origin layer (`internal/origin`)

The origin layer is cadish's **upstream-fetch** stage. An `Origin` fetches one
object from some backend (a generic HTTP server, an S3-compatible store, …) and
returns it as a **streaming** response, so the server can tee the body into the
cache while simultaneously serving it to the client — never buffering the whole
object in memory.

Design principle (design doc §4.1): **origins are composed from config; fallback
is NOT baked into the core.** The core knows only `Origin` ("give me this
object"). Strategies that combine backends (fallback, A/B, mirror, shadow) are
**composition** at this layer — see [`chain`](#chain--composable-fallback).

## The `Origin` interface

```go
// Origin fetches a single object from one backend, streaming the body.
type Origin interface {
    Fetch(ctx context.Context, req *Request) (*Response, error)
}

type Request struct {
    Method     string      // "" => GET
    Key        string      // raw object key / URL path, e.g. "videos/clip.mp4"
    Header     http.Header // forwarded to upstream; Range here => 206 passthrough
    ClientHost string      // original client authority, forwarded as upstream Host per host_header policy; "" on bg revalidate
    RawQuery   string      // original encoded query (no "?"), forwarded to HTTP origins; s3origin ignores it
}

type Response struct {
    StatusCode    int           // 200 (full) or 206 (range)
    Header        http.Header   // Content-Type, ETag, Last-Modified, Accept-Ranges, Content-Range (206)
    ContentLength int64         // length of THIS body, or -1 if unknown (chunked)
    Body          io.ReadCloser // live, streaming body — caller MUST Close exactly once
}
```

`Fetch` returns:

| Outcome | Return | Notes |
|---|---|---|
| 200 / 206 | `(*Response, nil)` | caller **owns and MUST Close** `Response.Body` |
| 3xx redirect / 304 | `(*Response, nil)` | **passed through, not followed** — see SSRF note below |
| 404 / 410 (HTTP origin) | `(*Response, nil)` with `Response.Negative == true` | **full-body negative** (backlog #21): the real error-page body+headers stream; caller **owns and MUST Close** `Response.Body`. A chain falls through on it; the server negatively caches it when the status is cacheable. |
| object missing, no usable body | `(nil, ErrNotFound)` | S3 `NoSuchKey` / 403 for OAI buckets; no body |
| other non-success | `(nil, *StatusError)` | upstream body already drained+closed; never streamed |
| transport / ctx error (pre-headers) | `(nil, err)` | dial/TLS/header timeout or cancellation |

A failure **after** headers arrived (mid-stream) surfaces from `Body.Read`, not
from `Fetch`.

**Full-body negative responses (`Response.Negative`).** An HTTP origin returns a
`404`/`410` as a streaming `*Response` (status + headers + real error-page body)
flagged `Negative`, exactly like the `3xx` passthrough — instead of collapsing it
to the bodyless `ErrNotFound`. This lets cadish **cache the actual error page** so
a HIT serves it verbatim (with the recorded status), not a synthetic "not found".
A backend whose not-found has no usable body (S3 `NoSuchKey`) still maps to the
bodyless `ErrNotFound`. `Negative` is `false` on a positive `200`/`206`.

**Redirects are never followed (SSRF guard, security review #1).** The HTTP
client sets `CheckRedirect = http.ErrUseLastResponse`, so a `30x` from the origin is
returned as a streaming passthrough `Response` (status + `Location` intact) rather
than being chased server-side. This prevents a malicious/compromised origin from
bouncing cadish to `http://169.254.169.254/…` (cloud metadata) or an RFC1918/
loopback target. The client (browser) follows the redirect itself; the server caches
only `200`s, so a redirect is never stored. The same guard is set on the `lb`
per-backend and health-probe clients.

### Error classification

`origin.StatusOf(err)` maps an error to the HTTP status it represents, for
fall-through decisions:

- `ErrNotFound` → `404`
- `*StatusError` → its `.Status`
- anything else (connection error, context cancellation) → `0` ("no HTTP
  response was obtained")

## Streaming / tee contract (the server MUST honor this)

`Fetch` hands back a `Body` that is still connected to the upstream socket.

1. **Ownership.** On a nil error the caller owns `Body` and **MUST `Close` it
   exactly once**, even after a partial read or no read. On a non-nil error
   `Body` is nil — nothing to close (the origin drained+closed the upstream body
   itself).
2. **No buffering.** The origin never reads the body into memory. The server
   streams it and can wire `io.TeeReader(resp.Body, cacheWriter)` so the bytes
   sent to the client are written to the cache in the same pass
   (serve-and-cache). The TeeReader wiring lives in the server, not here.
3. **Partial reads / early close.** The caller may `Close` before EOF (client
   disconnected, range satisfied, cache write failed). `Close` is safe at any
   point and aborts the upstream transfer. A body the caller stopped reading is
   **not** an origin error.
4. **Errors mid-stream.** A read error after `Fetch` returned (upstream dropped,
   context cancelled) comes from `Body.Read`, not `Fetch`. The server **MUST
   treat a mid-stream read error as a truncated response and MUST NOT commit a
   truncated body to the cache.**
5. **Context.** The `ctx` passed to `Fetch` governs the **whole** response
   lifetime, including the streaming read. Cancelling it unblocks an in-flight
   `Body.Read` with a context error. Origins bound **connection-establishment**
   phases (dial, TLS, response headers) with transport timeouts but do **not**
   cap the body transfer with a timeout (large media stream for minutes) — body
   cancellation rides `ctx`.
6. **Range / 206 passthrough.** A `Range` header in `Request` is forwarded
   verbatim; a 206 upstream response is passed through unchanged (`StatusCode ==
   206`, `Content-Range` in `Response.Header`). Origins never synthesize ranges
   from a full body — they ask the upstream.
7. **No ambient proxy.** The origin HTTP(S) clients set `Transport.Proxy = nil`,
   so they ignore `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` in the environment. An
   origin fetch is always a direct connection to the configured upstream — a stray
   or attacker-influenced proxy env var cannot silently divert it.

### Server-side serve-and-cache sketch

```go
resp, err := o.Fetch(ctx, req)
if errors.Is(err, origin.ErrNotFound) { /* 404 to client */ }
if err != nil { /* StatusOf(err): 5xx/connection -> 502/504 */ }
defer resp.Body.Close() // ALWAYS, exactly once

cw := cache.NewWriter(key, resp.Header, resp.StatusCode) // cache-side sink
tee := io.TeeReader(resp.Body, cw)
_, copyErr := io.Copy(clientWriter, tee)
if copyErr != nil {
    cw.Abort() // truncated: DO NOT commit a partial body
    return
}
cw.Commit() // full body streamed cleanly -> cache it
```

## Built-in origins

### `httporigin` — generic HTTP/HTTPS upstream

The bread-and-butter origin. Given a base URL, it joins the request `Key` under
the base path, forwards request headers (incl. `Range`), and streams the body. A
pooled `http.Client` with bounded establishment phases (5s dial, 5s TLS, 30s
response-header) and an uncapped body transfer governed by `ctx`.

```go
o, err := httporigin.New("https://origin.example.com")
resp, err := o.Fetch(ctx, &origin.Request{
    Key:    "videos/clip.mp4",
    Header: http.Header{"Range": {"bytes=0-1023"}},
})
```

### `s3origin` — S3-compatible upstream

An S3-compatible upstream client using the AWS SDK for Go v2. Given an
endpoint + bucket (+ static credentials), it `GetObject`s the key, forwards
`Range` (=> 206), and streams the body. `NoSuchKey`/404 maps to `ErrNotFound`;
other non-success statuses become `*StatusError`. Most S3-compatible stores
(OVH, MinIO) need `UsePathStyle: true`. Leaving both `AccessKey` and `SecretKey`
empty (or setting `Anonymous: true`) fetches **unsigned** for a public bucket —
signing with empty credentials is rejected by S3/MinIO, so empty creds must mean
"don't sign", not "sign with an empty key".

```go
o := s3origin.New(s3origin.Config{
    Endpoint:     "https://s3.gra.io.cloud.ovh.net",
    Region:       "gra",
    Bucket:       "media",
    AccessKey:    os.Getenv("S3_ACCESS_KEY"),
    SecretKey:    os.Getenv("S3_SECRET_KEY"),
    Anonymous:    false, // true (or empty creds) => unsigned, public-bucket access
    UsePathStyle: true,
})
```

## `chain` — composable fallback

A `chain.Chain` is **itself an `Origin`** that wraps an ordered list
`[primary, fallback...]`. It tries each in order and, when one **misses**, falls
through to the next. On the first **positive success (200/206)** it returns that
streaming response and the remaining origins are not consulted. A **full-body
negative response** (`Response.Negative` — a `404`/`410` with its real body) also
counts as a miss: the chain falls through to the next origin and **Closes the
abandoned negative body**. If **every** origin misses, the chain surfaces the last
full-body negative response (so the server can negatively cache its real error
page) if one was seen; otherwise the **last error** is surfaced.

This is exactly how `origin chain s3 -> cloudfront` from the Cadishfile is
realized — fallback is composition here, never hardcoded in `s3origin` or
`httporigin` (they know nothing about each other), rather than a hardwired
S3 → CloudFront fallback.

```go
chained, err := chain.New([]origin.Origin{primary, fallback})
resp, err := chained.Fetch(ctx, req)
```

### Fall-through status set (configurable)

`chain.DefaultFallThrough` (the default) falls through on:

- a **connection / transport / context error** (`StatusOf == 0`), and
- a **404**, and
- any **5xx**.

A non-404 4xx (e.g. 401, 403) is a definitive answer and is **surfaced** — the
chain stops. Override the policy:

```go
// Fall through on exactly these statuses (plus connection errors, always):
chain.New(origins, chain.WithFallThroughStatuses(404, 403, 502, 503))

// Or supply an arbitrary predicate:
chain.New(origins, chain.WithFallThrough(func(err error) bool { ... }))
```

`WithFallThroughStatuses` always falls through on connection errors (status 0) —
an origin that could not be reached should never end the chain.

### Cadishfile mapping

```
upstream s3         { to https://s3.gra.io.cloud.ovh.net; bucket media }
upstream cloudfront {
    to   https://d123.cloudfront.net
    sign cloudfront K1K6G49ZFL99X4 key /etc/cadish/keys/cloudfront.pem ttl 5m
}

origin chain s3 -> cloudfront     # miss/4xx(=404)/5xx on s3 -> fall to cloudfront
```

`s3` → an `s3origin.Origin`, `cloudfront` → a `cfsign.Origin` (see below), and
`origin chain s3 -> cloudfront` → `chain.New([s3, cloudfront])`.

## `cfsign` — CloudFront request signing

A `sign cloudfront …` upstream wraps its backend in a `cfsign.Origin` that
**re-signs every outgoing request** with the CloudFront private key before
fetching — the "S3 miss → CloudFront fallback (re-signed)" use case. It is a
plain `origin.Origin`, so it drops straight into an `origin chain`.

```
upstream cloudfront {
    to   https://d111111abcdef8.cloudfront.net          # the distribution domain
    sign cloudfront <key-pair-id> key <private-key.pem> [ttl 5m]
}
```

| Token | Meaning |
|---|---|
| `cloudfront` | the signing provider (the only one in v1) |
| `<key-pair-id>` | the CloudFront key-pair id (e.g. `K1K6G49ZFL99X4`) |
| `key <pem>` | path to the RSA private key PEM (PKCS#1 or PKCS#8) |
| `ttl DUR` | validity window minted into each signed URL (default `5m`) |

For each request, `cfsign` builds a CloudFront **canned-policy** signed URL —
`https://<distribution><key>?Expires=…&Signature=…&Key-Pair-Id=…` — using an
RSA-SHA1 signature over the policy (the exact bytes CloudFront verifies), then
does a plain HTTPS GET of it. The signature is bound to the **distribution
domain**, so the upstream's `to` MUST be the distribution (never an alias — an
alias signature is rejected). The private key (provide it via a `{$ENV}`
placeholder or a file path) signs locally; no AWS SDK or network call is needed.

The `key`/`ttl` are read from the directive; secrets belong in a file with tight
permissions (the PEM is read once at load).
```
