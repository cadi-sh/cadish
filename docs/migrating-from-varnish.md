# Migrating from Varnish (VCL → Cadishfile)

cadish replaces a multi-tool edge stack — reverse proxy, cache, load balancer and
TLS — with one binary and a flat config. This guide maps common VCL idioms to
cadish directives, using
a **real-world storefront migration** as the worked example — a ~478-line
production `storefront.vcl` (a fictional e-commerce site) translated to the
Cadishfile under
[`test/migration/storefront/`](../test/migration/storefront/) (with a golden
behavior spec in `golden_cases.md`).

Read the [Cadishfile reference](cadishfile-reference.md) alongside this; every
directive here is documented there.

## Start with `cadish adapt`

Don't translate by hand from scratch — let cadish do the mechanical 80%:

```sh
cadish adapt -o Cadishfile your.vcl
```

`cadish adapt` parses a Varnish VCL and emits a **best-effort Cadishfile
skeleton**: it converts the high-confidence idioms (backends → `upstream`, the
`vcl_recv` `return(pass)` wall → one `@nocache` + `pass`, `vcl_backend_response`
ttl/grace → `cache_ttl`, `vcl_hash` → `cache_key`, header edits, synthetic health
responses → `respond`) and leaves a clear `# TODO(adapt): …` — with the original
snippet — for everything non-mechanical (ACLs, vmods, `regsub`, device detect,
ESI, inline-C, templating). It prints a *mapped-vs-needs-review* count to stderr.

It is a **skeleton generator, not a compiler** — the output is a starting point a
human finishes. The workflow is: `adapt` → fix the TODOs and set your site
host(s) → `cadish check` → `cadish fmt`. The idiom table below is exactly what
`adapt` automates (and what it can't).

## The mental shift

VCL is imperative: you write subroutines (`vcl_recv`, `vcl_backend_response`,
`vcl_deliver`) that mutate request/response state and `return()` actions. A
Cadishfile is declarative: you write **matchers** and **directives**, and the
engine runs them in a fixed lifecycle. Most of what VCL makes you write by hand
(director glue, sticky-key math, anti-loop sharding headers) is a first-class
directive in cadish, so it disappears.

## Idiom map

This is a **conceptual mapping**, not a guarantee of what `cadish adapt` auto-emits.
`adapt` converts only the mechanical subset — literal `set`/`unset` header ops,
backends, and the no-cache wall — and flags everything else (anything with an
expression or a ternary, e.g. the `obj.hits > 0 ? "HIT" : "MISS"` row) as a
`# TODO(adapt)` for you to translate by hand.

| VCL (Varnish) | Cadishfile (cadish) | Phase |
|---|---|---|
| `sub vcl_recv { if (req.url ~ "…") return(pass); }` (a wall of them) | one `@nocache path /a/* /b/* …` matcher + `pass @nocache` | RECV |
| `if (req.method == "POST") return(pass);` | `pass method POST` | RECV |
| `if (req.http.X-Requested-With) return(pass);` | `pass header X-Requested-With` (what `adapt` emits — a header **presence** check; refine by hand to `@ajax header X-Requested-With XMLHttpRequest` + `pass @ajax` if you need the value match) | RECV |
| `sub vcl_recv { return(synth(200,"OK")); }` for a health path | `respond /health-check 200 "OK"` | RECV |
| director + `req.backend_hint` + `X-Shard` anti-loop + sticky-key hashing | `upstream web { to …; sticky by cookie PHPSESSID else client_ip; health … }` | SETUP |
| peer/self cache cluster sharded by URL | `cluster peers { to …; shard_by url }` | SETUP |
| `set req.backend_hint = images;` by host | `route @static -> images` | RECV |
| `sub vcl_hash { hash_data(req.url); hash_data(req.http.host); }` | `cache_key url host` | KEY |
| `sub vcl_backend_response { set beresp.ttl = 60s; set beresp.grace = 1h; }` by status | `cache_ttl status 404 410 ttl 60s grace 1h` | ORIGIN |
| `if (beresp.status >= 500) set beresp.uncacheable = true; ttl = 5s;` (HFM) | `cache_ttl status not 200 hit_for_miss 5s` | ORIGIN |
| `unset beresp.http.Set-Cookie;` to make a cookie-stamping origin cacheable | `strip_cookies @cacheable` (drops `Set-Cookie` **before** store+deliver — the *only* way to cache a `Set-Cookie` response; it is never cached otherwise, not even with `cache_unsafe`) | DELIVER |
| `unset req.http.Cookie;` (drop all but the cookies you keep, then cache) | `cookie_allow lang darkMode wp_logged_in_*` (keep these, strip the rest before key+bypass+origin; bare `cookie_allow` strips all). **You must KEY the cookies you keep** (`cache_key … cookie:lang cookie:darkMode`) — a kept-but-unkeyed cookie still bypasses the cache | RECV |
| `unset resp.http.Server; unset resp.http.X-Varnish;` | `header -Server -X-Varnish -Via` | DELIVER |
| `set resp.http.X-Cache = obj.hits > 0 ? "HIT" : "MISS";` | `header +cache_status X-Cache` | DELIVER |
| CORS header soup | `cors *` (or `cors ORIGIN… methods … headers …`) | DELIVER |
| token-guarded `PURGE`/`BAN` | `purge when header X-Purge-Token {$PURGE_TOKEN}` (hand-written — `adapt` emits `# TODO(adapt)` for **all** `PURGE`/`BAN` forms) | RECV |
| `include "nocache.vcl";` | `import nocache.cadish` | — |
| TLS terminated by a separate Hitch/nginx/Caddy | `tls { acme you@example.com }` (built in) | SETUP |

## Worked example: the no-cache wall

The VCL had ~50 lines like:

```vcl
sub vcl_recv {
  if (req.url ~ "^/panel")      { return(pass); }
  if (req.url ~ "^/publish")    { return(pass); }
  if (req.url ~ "^/admin-area") { return(pass); }
  # … ~50 more …
}
```

Each is a separate regex evaluated on every request. In cadish that collapses to
**one matcher** — a single trie/set lookup, not 50 regexes:

```
@nocache path \
    /panel/*  /publish/*  /admin-area/*  /private/*  /checkout/* \
    /account/*  /media/image_server.php  *sitemap*
pass @nocache
```

`cadish check` actively rewards this: it reports "regex evals / request" and will
tell you *"24 paths → one matcher, one set lookup, not 24 compares."* Run it on
your translation and drive that number down.

## Worked example: sticky sharding

The VCL's director + `X-Shard` anti-loop + sticky-key hashing was ~80 lines of
low-level glue. cadish makes sticky a directive:

```
upstream web {
    to       k8s://varnish-ingress.default:8080   # re-resolved, no reloads
    sticky   by cookie PHPSESSID else client_ip
    health   GET / expect 301 interval 5s window 6 threshold 3
    timeout  connect 5s first_byte 600s
    max_conns 800
}
```

A user pins to one backend by `PHPSESSID` (falling back to client IP); only
healthy backends are eligible; `k8s://` re-resolves so pod churn needs no reload.
The ~80 lines are gone. See [load-balancing.md](load-balancing.md).

## Worked example: per-status TTL/grace

```vcl
sub vcl_backend_response {
  if (beresp.status == 404 || beresp.status == 410) { set beresp.ttl = 60s; set beresp.grace = 1h; }
  else if (beresp.status >= 500) { set beresp.uncacheable = true; set beresp.ttl = 5s; }
  else { set beresp.ttl = 2s; set beresp.grace = 24h; }
}
```

becomes, first-match-wins:

```
cache_ttl status 404 410  ttl 60s grace 1h
cache_ttl status not 200  hit_for_miss 5s
cache_ttl default         ttl 2s grace 24h
```

## What's now wired vs. still v2-only

Most of the "real logic, not glue" parts of a big VCL are now translatable:

- **Device detection** (`req.http.User-Agent ~ "Mobile"` → desktop/mobile VARY
  normalization) — **available**: `device_detect` + the `{device}` cache-key token /
  `device` matcher.
- **Geo / whitelabel / brand** routing and **feature-flag VARY collapsing** —
  **available**: the `geo { … }` source + `{geo}`/`{geo.continent}`/`{geo.region}`
  tokens and the `normalize NAME { from …; map … }` bucketing machinery (collapse a
  high-cardinality header/cookie into a bounded cache-key token).

The one genuinely v2-only piece — leave it as `# TODO(v2)`:

- **CloudFront signed-URL _verification_** (validating inbound CloudFront signatures)
  — a future `cloudfront-auth` module. Origin re-signing the other direction already
  works: `upstream { sign cloudfront … }` re-signs each origin request URL with the
  CloudFront private key before fetching (see the reference + origin docs).

- Some behaviors that were once gaps are now wired: **negative caching** of
  404/410 (the failing response is stored and served from cache), per-rule
  **`storage` tier** placement (`storage <sel> -> ram|disk` is honored), and origin
  **3xx** handling (a redirect is passed through to the client with its real status
  and `Location`, never followed). For the remaining parsed-but-unwired items, see
  the [reference's "parsed but not yet wired"](cadishfile-reference.md#parsed-but-not-yet-wired-in-v1)
  section.

## Validate the translation

```sh
cadish check -config Cadishfile
```

Zero errors is the bar (warnings are advisory — `cadish check` explains each, and
flags dead rules, unknown names, and collapse opportunities). The storefront
target checks clean with 0 errors / 0 warnings; aim for the same, then diff
behavior against your VCL with golden request cases (see
`test/migration/storefront/golden_cases.md` for the shape).
