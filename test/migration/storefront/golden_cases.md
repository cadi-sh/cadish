# storefront — golden behavior spec

Representative requests → the decision cadish must make, each citing the VCL
behavior it mirrors. This is the contract the end-to-end test asserts against the
server. Decisions follow the directive semantics of the pipeline and are already
validated at the pipeline layer by `internal/pipeline/storefront_test.go` (cited
as **[pipe]** below).

Notation: **Pass** = bypass cache, straight to origin, never stored
(first-match-wins in RECV). **Key** = cache key. **Tier** = store tier on a miss.
**TTL/grace** = applied to the stored object by status/selector (first match
wins). `{SEP}` is the internal cache-key separator.

## RECV — pass / synthetic / purge decisions

| # | Method | Host | Path | Headers | Expected decision | Mirrors VCL |
|---|--------|------|------|---------|-------------------|-------------|
| 1 | GET | example.com | `/home` | — | **Cacheable** (no pass match) | default `lookup` path |
| 2 | GET | example.com | `/panel/settings` | — | **Pass** — `@nocache` (`/panel/*`) | `if(req.url~"/panel")return(pass)` **[pipe: panel-is-pass]** |
| 3 | GET | example.com | `/private/x` | — | **Pass** — `@nocache` (`/private/*`) | no-cache path set |
| 4 | GET | example.com | `/publish/item` | — | **Pass** — `@nocache` (`/publish/*`) | no-cache path set |
| 5 | GET | example.com | `/media/image_server.php` | — | **Pass** — `@nocache` (exact) | no-cache exact path |
| 6 | GET | example.com | `/sitemap.xml` | — | **Pass** — `@nocache` (`*sitemap*`) | `req.url~"sitemap"` |
| 7 | POST | example.com | `/home` | — | **Pass** — `method POST` | `if(req.method=="POST")return(pass)` **[pipe: post-is-pass]** |
| 8 | GET | example.com | `/home` | `X-Requested-With: XMLHttpRequest` | **Pass** — `@ajax` | `if(req.http.X-Requested-With)return(pass)` **[pipe: ajax-is-pass]** |
| 9 | GET | example.com | `/catalog/` | — | **Cacheable** — `@listings`, NOT `@nocache` | listings exception (cached) **[pipe: listing-is-cached]** |
| 10 | GET | example.com | `/electronics/phones` | — | **Cacheable** — `@listings` | listings exception |
| 11 | GET | example.com | `/health-check` | — | **Synthetic 200 `OK`** (no origin) | `vcl_recv` synthetic health **[pipe: health-check-synthetic]** |
| 12 | PURGE | example.com | `/` | `X-Purge-Token: <correct>` | **Purge authorized** | token-guarded PURGE/BAN **[pipe: purge-token-guarded]** |
| 13 | PURGE | example.com | `/` | `X-Purge-Token: wrong` | **Not authorized** (no purge) | token mismatch rejected **[pipe: purge-token-guarded]** |

## KEY — cache key composition

| # | Method | Host | Path | Query | Expected key | Mirrors VCL |
|---|--------|------|------|-------|--------------|-------------|
| 14 | GET | Example.com | `/list` | `p=2` | `/list?p=2{SEP}example.com` (host lower-cased) | `hash_data(req.url);hash_data(req.http.host)` **[pipe: cache-key-url-host]** |
| 15 | GET | example.com | `/a` | `b=1&a=2` | url-then-host (query canonicalized) | same `cache_key url host` |

## ROUTE / ORIGIN — image host routing + store tier + TTL

| # | Method | Host | Path | Expected | Mirrors VCL |
|---|--------|------|------|----------|-------------|
| 16 | GET | static.example.com | `/a.jpg` | **Upstream `images`**, Tier **disk**, TTL **24h/365d** | `host~"^static"`→images backend; long TTL **[pipe: images-to-disk-and-long-ttl]** |
| 17 | GET | static.example.com | `/logo.png` | Upstream `images`, disk, 24h/365d, **cookies stripped** | image origin + cookie hygiene |
| 18 | GET | example.com | `/page` | Tier **ram** (default storage) | non-image → RAM **[pipe: non-image-to-ram]** |

## ORIGIN — per-status TTL / grace (first match wins)

| # | Response status | Path | Expected | Mirrors VCL |
|---|-----------------|------|----------|-------------|
| 19 | 200 | `/page` | TTL **2s**, grace **24h**, Tier ram | default `beresp.ttl` **[pipe: default-ttl]** |
| 20 | 404 | `/gone` | TTL **60s**, grace **1h** | deleted content replaces stale 200 **[pipe: 404-ttl]** |
| 21 | 410 | `/gone` | TTL **60s**, grace **1h** | same 404/410 rule |
| 22 | 502 | `/x` | **hit_for_miss 5s**, not cacheable | transient 5xx must not poison key **[pipe: 5xx-hit-for-miss]** |
| 23 | 301 | `/redir` | **hit_for_miss 5s** (status≠200) | conservative: redirects not cached (see note A) |
| 24 | 200 | `/catalog/` (listing) | TTL **2s**, grace **24h**, Tier ram | listings stale-while-revalidate |
| 25 | 200 | `static.example.com/a.jpg` | TTL **24h**, grace **365d**, Tier disk | image long-cache (`@images` before `default`) |

## DELIVER — response headers + cookie stripping

| # | Request | Cache status | Expected response edits | Mirrors VCL |
|---|---------|--------------|-------------------------|-------------|
| 26 | GET `/page` | HIT | `X-Cache: HIT`; remove `Server`,`X-Powered-By`,`Via`,`X-Varnish`; add `Access-Control-Allow-Origin: *`, `Access-Control-Allow-Methods`, `X-Frame-Options: SAMEORIGIN` | debug-header unset + CORS + cache-status **[pipe: deliver-headers]** |
| 27 | GET `/style.css` | HIT | **Cookies stripped** (`path_regex \.(css\|js\|…)$`) | static cookie hygiene **[pipe: strip-cookies-css]** |
| 28 | GET `/` (home) | MISS | **Cookies stripped** (`path /`) | home cookie hygiene |
| 29 | GET `/category/sale` | MISS | **Cookies stripped** (`path /category/*`) | section cookie hygiene |
| 30 | response `Content-Type: text/css` | HIT | `Cache-Control: public, max-age=31536000` | long client-cache for css/svg |

## Cross-cutting

| # | Method | Host | Path | Expected | Note |
|---|--------|------|------|----------|------|
| 31 | GET | www.example.com | `/home` | Served by site (matches `*.example.com`), cacheable default | wildcard site address |

## Interpretation notes

- **Note A (301/redirects):** the TTL policy is `cache_ttl status not 200
  hit_for_miss 5s`, so any non-200 (incl. 301/302) gets a short hit-for-miss
  rather than being cached. This is the conservative reading of the VCL, which
  did not positively cache redirects. If prod telemetry shows cacheable 301s, add
  an explicit `cache_ttl status 301 …` rule above the catch-all.
- **First-match-wins ordering:** `@listings` is intentionally evaluated as a
  cacheable path and is NOT part of `@nocache`; placing the `pass @nocache` rule
  before the TTL policy guarantees listings are cached while admin/checkout paths
  bypass. (`internal/pipeline` evaluates `pass` in RECV and TTL/storage in ORIGIN,
  so there is no ordering hazard between them.)
- **Sticky/sharding:** requests to `upstream web` pin to a frontend by
  `PHPSESSID` (else client IP); not a per-request cache decision, so it is not in
  the table, but the end-to-end test should assert the same `PHPSESSID` value maps
  to a stable backend across requests (consistent-hash stability).
- **TODO(v2) behaviors** (device detect, whitelabel, VARY normalization, the
  CDN re-signing image fallback) are out of v1 scope and have no golden cases
  here; they get their own fixtures when the v2 machinery lands.
