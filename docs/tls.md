# TLS termination + automatic ACME (`internal/tlsacme`)

cadish terminates TLS itself — no proxy in front. A site that declares

```
example.com, *.example.com {
    tls { acme you@example.com }
    # … cache / upstream / routing directives …
}
```

gets HTTPS with automatically issued, automatically renewed Let's Encrypt
certificates. This is the "automatic-HTTPS half" of cadish.

## The `tls` directive

| Form | Meaning |
|---|---|
| `tls { acme EMAIL }` (or `tls acme EMAIL`) | Automatic ACME issuance/renewal. `EMAIL` is the ACME account contact. |
| `tls { cert FILE key FILE }` | Static keypair from disk (you terminate your own / internal CA). |
| `tls off` (or `tls { off }`) | Plain HTTP — for deployments behind a TLS-terminating load balancer. |

Optional hardening knob inside the block:

```
tls {
    acme you@example.com
    hsts max_age 31536000 includeSubdomains preload
}
```

`hsts` emits a `Strict-Transport-Security` header on HTTPS responses for the
site. It is **opt-in** (sending HSTS commits every browser to HTTPS-only for
`max-age` seconds — don't enable it until HTTPS is solid).

`http_redirect_except /path …` exempts the listed **exact** request paths from
the `:80` HTTP→HTTPS redirect — they are answered on plain `:80` by the site
pipeline instead of being `301`'d (for an L4/DNS health-check probe, webhook, or
monitoring endpoint a direct client hits over HTTP while cadish terminates TLS).
It is strictly an opt-**out** for the named paths; every other path still
redirects. Each path must start with `/`.

## How it works

- **Issuer:** `golang.org/x/crypto/acme/autocert` (battle-tested, stdlib-adjacent),
  wrapped behind a `CertSource` interface so a DNS-01 / multi-CA provider can be
  swapped in later without touching the server.
- **HostPolicy:** certificates are issued **only** for the union of hostnames
  declared across all `acme` sites (exact names and one-label `*.` wildcards).
  cadish is never an open ACME issuer — an unknown SNI is refused. The host set
  (and the static-keypair set + HSTS) lives behind an atomic pointer, so a SIGHUP
  reload **adds/removes a TLS hostname live** without a restart — the autocert
  manager and the `:443` listener are never rebuilt (D58). First-time enabling of
  ACME on a server started without it still needs a restart.
- **Wildcard ACME is on-demand (per-subdomain), and rate-limited.** cadish has no
  DNS-01 challenge, so a `*.example.com` site does **not** obtain a single wildcard
  certificate — instead each distinct subdomain that is actually requested gets its
  **own** certificate issued on demand via HTTP-01 / TLS-ALPN-01. To stop a flood of
  random `<rand>.example.com` SNI from driving unbounded ACME orders (and exhausting
  the account's order limit, e.g. Let's Encrypt's 300 new orders / 3h — which would
  break real renewals), **genuinely-new** certificate orders are bounded by a token
  bucket (burst 50, then ~20/hour); already-issued names (served from cache) and the
  in-flight challenge handshakes are exempt. When the budget is exhausted, the
  handshake fails for *that one new name* only — existing sites keep serving. **If
  your subdomain set is known, list exact hostnames** (`a.example.com b.example.com`)
  to remove the on-demand surface entirely.
- **Cache:** issued certificates are cached on disk so restarts don't re-issue
  (which would burn Let's Encrypt rate limits). Resolution order:
  `$CADISH_ACME_CACHE` → `/var/lib/cadish/acme` (when writable, i.e. a system
  service) → `$XDG_DATA_HOME/cadish/acme` → `~/.local/share/cadish/acme`.
- **Listeners:** the server binds `:80` and `:443`.
  - `:80` serves the ACME **HTTP-01 challenge** (`/.well-known/acme-challenge/…`)
    and `301`-redirects everything else to `https://`. A request that already arrived
    over HTTPS at an upstream terminator (`X-Forwarded-Proto: https`) is **not**
    redirected — it is served plain, to avoid a redirect loop behind a TLS-terminating
    LB. **The `X-Forwarded-Proto` loop guard is trust-gated** (R15): cadish honors it
    **only when the immediate socket peer is in `trust_proxy`**, so a direct client
    cannot add `X-Forwarded-Proto: https` to a plain `:80` request to be served in
    cleartext. **Behind a TLS terminator (Cloudflare / an LB), declare its network in
    `trust_proxy`** (e.g. `trust_proxy 173.245.48.0/20 …`) so the legitimate loop guard
    still suppresses the redirect; with no `trust_proxy` the header is ignored and every
    plain `:80` request is redirected. See
    [`ingress-controller.md`](ingress-controller.md) §HTTP→HTTPS redirect.
  - **Undeclared hosts are still redirected.** The `:80` redirect applies to *any*
    `Host:` — an undeclared host on `:80` still gets `301 https://<that-host>/…`.
    HostPolicy then refuses to issue a cert for it at the `:443` handshake (the
    redirect succeeds, the cert does not), so an unknown host fails at the TLS layer,
    not with a "not configured" rejection on `:80`. This is intended (no open
    issuer) but can surprise operators expecting `:80` to reject the unknown host.
  - **Dev/test gotcha — the 301 `Location` always targets the default `:443`.** The
    HTTP→HTTPS `Location` omits a non-standard HTTPS port: with `-https-addr :19052`
    the redirect still points at `https://host/path` (i.e. `:443`), so it won't
    round-trip in a high-port dev setup. This is fine in production where HTTPS is
    on `:443`.
  - `:443` serves the site over a hardened TLS config; the **TLS-ALPN-01**
    challenge (`acme-tls/1`) is handled inline during the handshake.

## TLS hardening (defaults)

- Minimum **TLS 1.2**, TLS 1.3 preferred.
- Modern AEAD cipher suites with forward secrecy only (TLS 1.2); TLS 1.3 suites
  are the Go stdlib defaults.
- ALPN advertises **HTTP/2** and HTTP/1.1 (plus `acme-tls/1` when ACME is active).
- Curve preferences X25519, P-256.
- OCSP stapling (via autocert).
- `ReadHeaderTimeout` on both listeners to blunt Slowloris.

## Mixed deployments

A single cadish instance can mix modes: some sites on ACME, some on a static
keypair, some `off`. Certificate lookup dispatches by SNI — a static host uses its
keypair, an ACME host uses autocert, and an `off` host is served over plain HTTP
only (and is never eligible for ACME issuance).

## Server integration

`internal/tlsacme` is consumed by the server (`cadish run`):

```go
// One SiteConfig per site, built from the parsed Cadishfile.
sites := []tlsacme.SiteConfig{ /* tlsacme.SiteConfigFromSite(site) … */ }

mgr, err := tlsacme.NewManager(sites, tlsacme.Options{})
if err != nil { /* bad keypair, etc. */ }

if mgr.NeedsTLS() {
    srv := mgr.BuildServers(siteHandler, tlsacme.DefaultHTTPAddr, tlsacme.DefaultHTTPSAddr)
    err = srv.ListenAndServe(ctx) // :80 challenge+redirect, :443 hardened TLS
} else {
    // every site is `tls off` → plain HTTP only
}
```

Key API:

| Symbol | Purpose |
|---|---|
| `ParseSiteTLS(d) (SiteTLS, []error)` / `SiteConfigFromSite(site)` | Interpret the `tls` directive from the AST. |
| `NewManager(sites, Options) (*Manager, error)` | Build the whole-server TLS coordinator; loads static keypairs eagerly. |
| `Manager.NeedsTLS()` | Whether to bind `:443`. |
| `Manager.TLSConfig()` | Hardened `*tls.Config` for the `:443` listener. |
| `Manager.HTTPHandler()` | `:80` handler — ACME challenge + HTTPS redirect. |
| `Manager.HSTSMiddleware(next)` / `HSTSValueFor(host)` | Per-host HSTS on HTTPS responses. |
| `Manager.HostAllowed(host)` | Whether a host is eligible for ACME issuance. |
| `Manager.BuildServers(handler, httpAddr, httpsAddr)` → `Servers.ListenAndServe(ctx)` | Turn-key `:80`+`:443` with graceful shutdown. |

## Testing

Unit tests cover directive parsing (all `tls` forms + HSTS), the HostPolicy
(serves configured hosts incl. wildcards, refuses others), the cache-dir
resolution order, the `:80` challenge/redirect split, TLS-config hardening, and a
**real TLS handshake** through the hardened config with a generated self-signed
keypair (correct cert served by SNI; a TLS 1.1 client is rejected).

## Live ACME end-to-end testing (pebble)

A guarded test, `TestPebbleEndToEnd`, drives the **full** ACME issuance flow
against [pebble](https://github.com/letsencrypt/pebble) (Let's Encrypt's small
test ACME server). It is **skipped by default** so CI stays green without Docker.

The certificate source is pluggable behind `CertSource` (the production path is a
named `autocertSource` wrapping `autocert.Manager`); `Options.ACMEDirectoryURL`
points the issuer at pebble and `Options.ACMEHTTPClient` lets the test trust
pebble's self-signed directory.

Bring up the stack and run the test:

```sh
docker compose -f test/acme/docker-compose.yml up -d

# Linux / CI (deterministic): give both services `network_mode: host`, then:
CADISH_ACME_PEBBLE=1 \
CADISH_ACME_CHALLTESTSRV=http://localhost:8055 \
CADISH_ACME_HOST_IP=127.0.0.1 \
go test ./internal/tlsacme -run TestPebbleEndToEnd -v

docker compose -f test/acme/docker-compose.yml down
```

The test answers HTTP-01 on **:5002** and TLS-ALPN-01 on **:5001** (non-privileged
— no sudo), matching `test/acme/pebble-config.json`. It seeds a DNS record via
pebble-challtestsrv so pebble resolves the challenge domain back to this process,
then triggers a handshake that drives autocert to obtain a real certificate.

**Networking:** on Linux/CI use host networking and `CADISH_ACME_HOST_IP=127.0.0.1`
(pebble dials the host directly). On **Docker Desktop** (macOS/Windows) there is no
host networking; set `CADISH_ACME_HOST_IP` to the `host.docker.internal` gateway
(e.g. `192.168.65.254`). The stack comes up and pebble runs real validation
against the test's listener there, but Docker Desktop's container→host NAT can
drop pebble's concurrent multi-perspective probes, so issuance may not complete —
use the Linux path for a deterministic pass. See `test/acme/docker-compose.yml`
for details.
