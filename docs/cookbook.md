# Cadishfile cookbook

Recipes for real caching scenarios. Each complete config lives in
[`examples/`](../examples) and passes `cadish check` with **0 errors** — validate
any of them yourself:

```sh
cadish check -config examples/static-cdn.Cadishfile
```

The fenced blocks below are **illustrative excerpts** — they highlight the
directives that make each recipe work, not always a full runnable site. For the
complete, copy-pasteable config, open the linked `examples/*.Cadishfile`. For the
bare-minimum starting point, see [`minimal.Cadishfile`](../examples/minimal.Cadishfile).

New to cadish? Read [getting-started.md](getting-started.md) first, and keep the
[Cadishfile reference](cadishfile-reference.md) open for directive details.

| # | Recipe | Example |
|---|---|---|
| 1 | Static-site / asset CDN | [`static-cdn.Cadishfile`](../examples/static-cdn.Cadishfile) |
| 2 | API response cache | [`api-cache.Cadishfile`](../examples/api-cache.Cadishfile) |
| 3 | Multi-origin failover | [`failover.Cadishfile`](../examples/failover.Cadishfile) · [`s3-cdn.Cadishfile`](../examples/s3-cdn.Cadishfile) |
| 4 | HLS / video edge | [`video-edge.Cadishfile`](../examples/video-edge.Cadishfile) |
| 5 | Sticky-session app cache | [`sticky-app.Cadishfile`](../examples/sticky-app.Cadishfile) |
| 6 | Device-varied cache | [`device-cache.Cadishfile`](../examples/device-cache.Cadishfile) |
| 7 | Behind an external LB / ingress | [`behind-lb.Cadishfile`](../examples/behind-lb.Cadishfile) |

---

## 1. Static-site / asset CDN

**Scenario:** front a web origin with cached HTTPS; assets (fingerprinted CSS/JS/
images) cache for a long time, HTML refreshes quickly, and browsers cache
immutable assets locally.

```
assets.example.com {
    tls { acme ops@example.com }

    cache {
        ram  4GiB
        disk /var/cache/cadish 200GiB
    }
    upstream web { to http://origin.internal:8080 }

    @assets path_regex \.(css|js|woff2?|png|jpe?g|gif|svg|ico|webp)$
    cache_ttl @assets ttl 30d grace 365d
    cache_ttl default ttl 60s grace 1h

    header content_type text/css               Cache-Control "public, max-age=31536000, immutable"
    header content_type application/javascript Cache-Control "public, max-age=31536000, immutable"

    strip_cookies @assets
    header +cache_status X-Cache
}
```

**Why it's shaped this way:** content-hashed asset filenames are immutable, so a
long `ttl` + huge `grace` maximizes hit rate while HTML stays fresh on a 60s ttl.
`content_type` matches what the origin *actually served* (not the path), so the
long browser `Cache-Control` only lands on real CSS/JS. `strip_cookies` keeps a
stray `Set-Cookie` from making a shared asset per-user. Note: `strip_cookies`
alone does **not** make a `Set-Cookie` response cacheable — it is a delivery-time
leak guard; caching a cookie-bearing class requires `cache_unsafe`.

## 2. API response cache

**Scenario:** cache idempotent reads for a few seconds; never cache writes or
authenticated/per-user responses; protect the origin from 5xx stampedes.

```
api.example.com {
    tls { acme ops@example.com }
    cache { ram 2GiB }
    upstream api { to http://api.internal:8080 }

    pass method POST PUT PATCH DELETE
    @authed  header Authorization
    @private path /v1/account/* /v1/admin/*
    pass @authed
    pass @private

    cache_key method host url header:X-Tenant

    cache_ttl status not 200 hit_for_miss 5s
    cache_ttl default ttl 10s grace 2m

    cors *
    header +cache_status X-Cache
}
```

**Why:** mutations and credentialed requests are bypassed so the cache only holds
public reads. Two of these are now **safe-by-default** (the explicit rules are
belt-and-suspenders / documentation): a request carrying `Authorization` or `Cookie`
already bypasses the shared cache unless you key by the credential
(`cache_key … cookie:session`), and a broad `cache_ttl default` already refuses to
store a `5xx` — so the `status not 200 hit_for_miss` rule is now mainly about
coalescing a flaky origin rather than preventing an outage from being cached. The key
is scoped by a **coarse** `X-Tenant` header so tenants don't
share entries — never key on the token itself (that's a per-user key = 0% hit
rate). `cadish check -strict` flags any raw-header key token (`header:X-Tenant`) with an
`unbounded-key-token` warning (the default `check` is silent on it): keep the
value low-cardinality, or bucket it into a
`normalize` enum if a tenant header could ever explode. `cache_ttl` is first-match-wins, so the `status not 200` **hit-for-miss**
rule sits *above* `default`; a flaky 5xx is remembered as "don't cache" for 5s
instead of poisoning the key or stampeding the origin.

## 3. Multi-origin failover

**Scenario:** a primary origin with a backup; fall through automatically on
miss/4xx/5xx/unreachable.

```
upstream primary { to https://origin-a.example.net
                   health GET /healthz expect 200 interval 5s window 3 threshold 2 }
upstream backup  { to https://origin-b.example.net }

origin chain primary -> backup
```

**Why:** `origin chain` composes origins at the config layer — the chain is itself
an `origin`, so caching/TTL behave exactly as with a single backend. Fallback is
*declared*, not hand-coded. The **S3 → CloudFront (re-signed)** variant — primary
S3, falling back to a CloudFront distribution whose requests are re-signed with
`sign cloudfront` — is in [`s3-cdn.Cadishfile`](../examples/s3-cdn.Cadishfile).

## 4. HLS / video edge

**Scenario:** serve adaptive-bitrate video; the player loads segments directly,
playlists update fast, VOD media is immutable and large.

```
@segments path *.ts *.m4s
pass @segments

@manifest path_regex \.m3u8$
cache_ttl @manifest ttl 2s grace 30s

@vod path_regex \.(mp4|webm)$
cache_ttl @vod ttl 7d grace 30d
storage   @vod -> disk

cors *
```

**Why:** `.ts`/`.m4s` segments carry their own short-lived URLs (every viewer
differs) → `pass` rather than cache churn. Playlists get a tiny ttl + grace so the
live edge advances without a thundering herd (stale-while-revalidate keeps players
fed). VOD is immutable → cache hard; large files live on the NVMe `disk` tier and
serve with `sendfile`. `cors *` lets browser `<video>`/MSE players fetch
cross-origin.

## 5. Sticky-session app cache

**Scenario:** a stateful app (in-memory sessions) where users must stick to one
backend, but anonymous pages are cacheable.

```
upstream web {
    to        http://app-1.internal:8080  http://app-2.internal:8080
    sticky    by cookie PHPSESSID else client_ip
    health    GET /healthz expect 200 interval 5s window 6 threshold 3
}

pass method POST PUT PATCH DELETE
@authed header Authorization
pass @authed

cache_key host path
cache_ttl default ttl 30s grace 5m
strip_cookies path /
```

**Why:** `sticky by cookie` consistently hashes each user to one healthy backend
for their session (cookieless first hits fall back to client IP). Authenticated
requests pass; anonymous GETs are cached with a **cookie-free key** (putting the
cookie in the key would give every user their own entry). `strip_cookies` stops a
cached anonymous page from carrying one user's `Set-Cookie` to the next — but it
does **not** by itself make a `Set-Cookie` response cacheable; that requires
`cache_unsafe`.

## 6. Device-varied cache (the VARY-cardinality win)

**Scenario:** the origin renders different HTML for mobile vs desktop.

```
device_detect {
    fold tablet desktop
    fold bot    desktop
}
cache_key host path {device}
```

**Why:** varying on the raw `User-Agent` shatters the cache (millions of UA
strings → ~0% hit rate). The `{device}` normalizer reduces the UA to a small enum
and the key varies on **that**, so all desktop users share one entry. `fold`
collapses tablet/bot into desktop for a 2-way desktop/mobile split (the
lowest-cardinality option that still serves the mobile template). `cadish check`
confirms `{device}` is a bounded, hit-rate-safe key token. The same pattern
applies to **`{geo}`** (country class) — see recipe 7.

## 7. Behind an external LB / ingress

**Scenario:** an LB/ingress/CDN terminates TLS and forwards plain HTTP; cadish
trusts the front for the real client IP and country.

```
cache.example.com {
    tls off
    cache { ram 4GiB; disk /var/cache/cadish 200GiB }
    upstream app { to http://app.internal:8080 }

    geo {
        source      header CF-IPCountry
        trust_proxy 10.0.0.0/8 ::1/128   # CIDR(s) of the fronting LB/CDN
    }
    pass method POST PUT PATCH DELETE
    cache_key host path {geo}
    cache_ttl default ttl 1m grace 1h
    header +cache_status X-Cache
}
```

**Why:** `tls off` makes cadish a plain-HTTP cache behind the front (no ACME
challenge / HTTPS redirect on `:80` — run it *only* behind the LB). `geo` reads
the country header the CDN/LB injects and `trust_proxy` lists the **CIDR(s)** of
that front (it takes a CIDR list, not a hop count) so cadish honors its forwarded
`X-Forwarded-For`/country header, and `{geo}` varies the key on a bounded country
class without ever keying on the raw client IP. Use the real subnet of your
ingress/LB; `0.0.0.0/0 ::/0` trusts the immediate peer from anywhere (safe only
when cadish is reachable *exclusively* through the LB). See
[deployment.md](deployment.md) for the k8s/ingress wiring.

---

## Rough edges found while writing these

Dogfooding the config across scenarios surfaced a few real gaps (filed as
feedback):

1. **Per-cookie matcher — RESOLVED.** The `cookie NAME` matcher exists and tests a
   specific cookie inside the `Cookie` header (presence, exact value, or a
   `NAME*` name-prefix glob): `@authed cookie sessionid` + `pass @authed` makes
   session-aware bypass first-class. And credentialed requests (`Authorization`/
   `Cookie`) are now bypassed by default — see the
   [credentialed-request safe-default](cadishfile-reference.md#credentialed-requests-are-never-shared-cached-by-default).
2. **Tier placement is wired** — both the per-rule `storage <sel> -> ram|disk`
   directive (recipe 4's `storage @vod -> disk` pins VOD to NVMe) and the
   per-extension `cache { tier .ext -> ram|disk }` default are honored. (This
   rough edge is resolved.)
3. **No cardinality warning for `header:` key tokens.** `cadish check` smartly
   warns that `{device}`/`{geo}` are bounded, but a `cache_key … header:X` with a
   high-cardinality header (a token, a raw UA) gets no warning — the exact footgun
   the report exists to catch. A "this key token looks unbounded" hint would round
   it out.

None of these blocked a recipe; they're polish that would make the config even
harder to misuse.
