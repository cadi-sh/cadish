# cadish as a Kubernetes Ingress controller

Run cadish in-cluster as a drop-in **Ingress controller**: it watches `Ingress` /
`IngressClass` objects (plus the `Secret`s and policy `ConfigMap`s they reference),
translates them into the *same* compiled routing cadish builds from a Cadishfile, and
hot-swaps the live config with zero downtime. The cluster's Ingress objects become the
source of truth; a small **base Cadishfile** supplies only globals.

This is **Layer 2**. It builds on **Layer 1** (`k8s://service.namespace:port` upstream
resolution via EndpointSlices) — every backend becomes a `k8s://` upstream, so cadish
runs its own load balancing over the live ready pods.

## How it works

```
Ingress / IngressClass / Secret / ConfigMap          (the desired state)
        │  informers + debounce
        ▼
   translator  → Cadishfile text  → config compiler → routing
        │                                              │ Server.ApplyConfig (atomic swap)
        └──────────────── one Cadishfile, one compiler ┘
```

- **Backends** → `upstream u_… { to k8s://svc.ns:port }` (Layer 1 resolves pods).
- **`pathType`** → a cadish `path` matcher: `Exact` → `path /p` (exact); `Prefix` /
  `ImplementationSpecific` → `path /p /p/*` (matches `/p` and any `/p/…` subpath, never
  `/prefix`). A `Prefix /` becomes a catch-all route.
- **Most-specific-wins** is reproduced by cadish's first-match-wins `route` order
  (Exact before Prefix; longer prefix before shorter).
- **Unmatched paths 404 (path-scoped isolation).** A site whose paths are all explicit
  — no `Prefix /` catch-all and no `spec.defaultBackend` — emits a terminal
  `respond !@r0 !@r1 … 404`, so a request matching none of the declared paths returns
  **404** instead of silently falling back to the site's first declared upstream. A
  backend mapped to `/api` therefore does **not** also serve `/admin`.
- **`spec.defaultBackend`** → the **per-Ingress** terminal fallback, emitted last as a
  catch-all `route ->` for **only the hosts that same Ingress declares**. One Ingress's
  `defaultBackend` never bleeds into a host owned by another Ingress. When present it
  replaces the bare 404 for that host (unmatched paths hit the defaultBackend). A
  `defaultBackend` is **not** turned into a wildcard listener: cadish is host-routed
  (one site per host), and a request to an **unknown host** that matches no rule keeps
  the server's default no-site behavior (it does not fall through to any Ingress's
  `defaultBackend`) — this keeps host routing explicit and avoids one tenant's
  `defaultBackend` silently catching another's (or an attacker's) unknown-host traffic.
- **Multiple Ingresses on one host** are merged **oldest-wins** (by `creationTimestamp`);
  a duplicate `(host, path, pathType)` from a newer Ingress is rejected with an Event.
- **A bad Ingress never takes serving down**: it is skipped with a Kubernetes warning
  Event and the last good routing keeps serving.

## 5-minute Quickstart

The minimal path from a fresh cluster to cadish serving an Ingress. Every command is
copy-pasteable.

> The shipped manifests pull `ghcr.io/cadi-sh/cadish` — if your pods land in
> `ImagePullBackOff`, the package is private; see
> [Troubleshooting → image pull fails](#a-imagepullbackoff--errimagepull).

**1. Install the controller** (IngressClass + RBAC + base ConfigMap + Deployment + LB
Service). The controller is **not** part of `kubectl apply -k deploy/k8s` (that deploys
the standalone server), so apply its three manifests explicitly:

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac-controller.yaml
kubectl apply -f deploy/k8s/ingress-controller.yaml
kubectl rollout status deploy/cadish-ingress -n cadish
```

(or via Helm: `helm install cadish deploy/helm/cadish --namespace cadish
--create-namespace --set controller.enabled=true --set
controller.publishService=cadish/cadish-ingress`.)

**2. Create a tiny backend** — a `whoami` Deployment + Service in its own namespace:

```bash
kubectl create namespace demo
kubectl create deployment whoami --image=traefik/whoami:v1.10 -n demo
kubectl expose deployment whoami --port=80 -n demo
```

**3. Create an Ingress** with `ingressClassName: cadish`:

```bash
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: whoami
  namespace: demo
spec:
  ingressClassName: cadish
  rules:
    - host: whoami.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: { service: { name: whoami, port: { number: 80 } } }
EOF
```

**4. Curl it through the LoadBalancer** with a `Host` header (no DNS needed):

```bash
# The external address (.ip for most clouds; .hostname for AWS ELBs):
LB=$(kubectl get svc cadish-ingress -n cadish \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}{.status.loadBalancer.ingress[0].hostname}')
curl -H 'Host: whoami.example.com' "http://${LB}/"
```

You should get the `whoami` pod's request dump. The Ingress `ADDRESS` column
(`kubectl get ingress -n demo`) is populated by the leader once `--publish-service`
resolves. No `tls:` block was set, so the host is served over plain HTTP — add one (and
a Secret, or let cadish ACME-issue) per the [TLS](#tls--from-ingress-spectls-secrets-if-present-else-acme)
section.

## Install

### Manifests

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac-controller.yaml
kubectl apply -f deploy/k8s/ingress-controller.yaml
```

This creates the `cadish` `IngressClass`, the controller `Deployment` (2 replicas), a
`LoadBalancer` `Service`, and the base-config `ConfigMap`.

### Helm

```bash
helm install cadish deploy/helm/cadish \
  --namespace cadish --create-namespace \
  --set controller.enabled=true \
  --set controller.publishService=cadish/cadish-ingress
```

`controller.enabled=true` switches the chart from the plain `run` Deployment to the
Ingress-controller stack (IngressClass + RBAC + base ConfigMap + Deployment + Service).

## Using it

Create Ingress objects with `ingressClassName: cadish` (cadish also honors the legacy
`kubernetes.io/ingress.class: cadish` annotation, and — if you mark its IngressClass
default via `ingressclass.kubernetes.io/is-default-class: "true"` — classless Ingresses):

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: shop
  namespace: prod
spec:
  ingressClassName: cadish
  tls:                            # honored: if shop-tls exists it terminates that cert;
    - hosts: ["shop.example.com"] # if it is absent, cadish ACME-issues the host instead
      secretName: shop-tls        # (see "TLS" below). Both take effect on reconcile.
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend: { service: { name: api, port: { number: 8080 } } }
          - path: /
            pathType: Prefix
            backend: { service: { name: web, port: { number: 80 } } }
```

### Per-host cache / policy — the `cadi.sh/policy` ConfigMap

cadish's `cache { … }`, `cache_ttl`, matchers etc. are **per-site**, so they cannot live
in the (global-only) base. Attach them per host with a `cadi.sh/policy` annotation
pointing at a ConfigMap (`ns/name`) whose `cadishfile` key holds a Cadishfile fragment:

```yaml
metadata:
  annotations:
    cadi.sh/policy: prod/shop-policy
---
apiVersion: v1
kind: ConfigMap
metadata: { name: shop-policy, namespace: prod }
data:
  cadishfile: |
    cache { ram 512MiB }
    @static path *.css *.js *.png
    cache_ttl @static ttl 1h
    cache_ttl default ttl 1m grace 1h
```

The fragment is validated in isolation before it is layered in. An **invalid fragment is
skipped** (a warning Event) and the routes still apply.

> **Cache size/path changes need a pod restart.** Editing a `cache { ram … }` budget or
> disk path in a live fragment is applied to routing immediately, but the running cache
> store keeps its original size/path until the pod restarts (a `WARN cadish reload: cache
> budget/path change is ignored until restart` is logged — it is not silent). Roll the
> Deployment (`kubectl rollout restart deploy/cadish-ingress -n cadish`) to pick up a new
> cache budget. TTLs, matchers and other policy hot-reload normally.

A policy fragment is **policy-only** and is compiled in a restricted mode (see
[Security model](#security-model)): it may carry cache / header / CORS / security /
rate-limit-style policy, but it **may not**

- reference the controller pod's environment — `{$VAR}` env placeholders are **rejected**
  (otherwise a fragment could exfiltrate the admin token or any process secret), nor
- define a backend, route, or credential — `upstream`, `cluster`, `origin`, `route`, `to`,
  and `sign` are **rejected** (otherwise a tenant's ConfigMap could proxy an arbitrary
  host — cloud metadata / SSRF — or a Service in another namespace, bypassing the
  namespace-locked Ingress path). `import` and `geo` are **rejected** too — both resolve a
  pod-local filesystem path, which would leak controller-pod file contents into the Ingress
  status.

A fragment that hits either restriction is skipped with a warning Event; the host's routes
still serve.

### TLS — from Ingress `spec.tls` (Secrets-if-present-else-ACME)

cadish honors `spec.tls[]` directly (D55 §19, D61). `cadish ingress` always starts
TLS-capable: it binds `:80` (ACME HTTP-01 + HTTPS redirect) and `:443` at startup with a
live, initially-empty host policy, so TLS hosts can be added, removed or rotated **on
reconcile with no restart**. For each `spec.tls[]` host:

- **the referenced `kubernetes.io/tls` Secret exists** → cadish serves that BYO /
  cert-manager certificate. The controller reads `tls.crt` / `tls.key` from the Secret and
  hot-swaps it into the live listener; **rotating the Secret re-loads the cert live**.
- **the Secret is absent (or not a usable TLS Secret)** → cadish **ACME-issues** the host
  automatically. The generated site carries a `tls acme` directive, and the ACME
  `HostPolicy` is bounded to the **union of watched Ingress hosts** — never an open issuer.

A Secret that is **present but contains an unparseable keypair** is treated as **unusable**:
the host **falls back to ACME issuance** (so it is never left dark), a `BadTLSSecret` warning
Event names the corrupt Secret, and routing still applies. Pass `--acme-email` to set the
ACME account contact for auto-issued hosts; `--acme-cache` is the on-disk cache for issued
certs.

> The controller RBAC already grants `secrets` `get`/`list`/`watch`
> (`deploy/k8s/rbac-controller.yaml`), which is all BYO-Secret TLS needs.

A global `tls { … }` / per-site `tls` in the **base Cadishfile** is still served normally
and composes with `spec.tls` (the base supplies globals; per-host TLS comes from Ingress).

### HTTP→HTTPS redirect (TLS-gated)

In Ingress mode the `:80` handler redirects `HTTP→HTTPS` **only for hosts that have TLS**
(a host in some `spec.tls`, served by a BYO Secret or ACME). A host with **no** TLS is
served over plain HTTP — it is never 301'd to a TLS endpoint it has no certificate for
(matching ingress-nginx / Traefik). To force the redirect on a non-TLS host — e.g. when
TLS is terminated upstream at an LB / Cloudflare — set the annotation on its Ingress:

```yaml
metadata:
  annotations:
    cadi.sh/ssl-redirect: "true"
```

> **Avoiding a redirect loop.** When TLS is terminated upstream, the LB forwards plain
> HTTP to cadish `:80`; an unconditional 301→HTTPS would bounce the client back to the
> terminator, which forwards plain HTTP again — an infinite loop. cadish breaks it by
> **not redirecting a request that already arrived over HTTPS**, detected via
> `X-Forwarded-Proto: https`. This loop guard is **trust-gated** (R15): cadish honors
> `X-Forwarded-Proto` **only from a socket peer in `trust_proxy`**, so a direct client
> cannot forge the header to be served in cleartext. **Declare the terminator's network
> in `trust_proxy`** (e.g. Cloudflare's IP ranges) so the legitimate loop guard applies;
> the LB must also still set `X-Forwarded-Proto` to the client's scheme and strip any
> client-supplied value. With no `trust_proxy` the header is ignored and every plain
> `:80` request is redirected (so a `cadi.sh/ssl-redirect` host behind an untrusted-by-
> cadish terminator would loop — declare the trust_proxy).

(Standalone `cadish run` is unaffected: it keeps automatic-HTTPS, redirecting
every host.)

## Security model

The Ingress controller assumes an **operator-curated, single-trust-domain cluster**:
**cluster RBAC is the tenant boundary** — whoever can create an `Ingress`/`ConfigMap`/
`Secret` in a namespace is trusted with what that grants, exactly like the default posture
of nginx-ingress and Traefik. Within that model the controller still enforces the
guarantees below, which are correct in **any** trust model.

**What IS enforced**

- **Policy fragments are policy-only.** A `cadi.sh/policy` ConfigMap fragment is compiled
  in a restricted mode: **no environment substitution** (`{$VAR}` is rejected, so a fragment
  cannot read the controller pod's env / admin token) and a **directive allow-list** that
  rejects backend/route/credential directives (`upstream`, `cluster`, `origin`, `route`,
  `to`, `sign`, plus `import`/`geo` whose filesystem-path reads would leak pod-local files).
  A fragment cannot define an upstream, re-wire routing, or mint credentials.
- **A policy ref is confined to its own namespace.** `cadi.sh/policy: ns/name` must name a
  ConfigMap in the **Ingress's own namespace**; a cross-namespace ref is rejected and the
  controller never reads the foreign ConfigMap.
- **Routing host ownership across namespaces (first-claim lock).** A host's routing is owned
  by the **oldest** Ingress that declares a rule for it (first-claim / oldest-wins). An
  Ingress in a **different namespace** that contributes rules (or a `spec.defaultBackend`)
  for that host is **rejected** for that host (per-Ingress Event) and its rules are **never
  merged** — a hostile tenant cannot claim or parasitize another namespace's hostname's
  routing (e.g. add a `/` catch-all or a conflicting path to `victim.com`). Ingresses in the
  **same** namespace still merge (a namespace owns its own host). This is the same owner per
  host that TLS ownership uses, so routing and TLS ownership always agree.
- **TLS host ownership is aligned to routing.** A host's routing is owned by the **oldest**
  Ingress that declares a rule for it (first-claim / oldest-wins). A `spec.tls` BYO cert (or
  ACME host) may only come from **that owning namespace** — a different namespace cannot
  register a certificate for a host another namespace routes (confused-deputy / cert
  hijack). Cross-namespace TLS entries are rejected with an Event.
- **Per-namespace ACME domain allow-list (optional, off by default).** ACME issuance is
  always bounded to the watched-host union (never an open issuer). Additionally, an
  operator may configure `--acme-domain-policy` to map each namespace to the domain
  suffixes it is permitted to auto-issue for. When set, an ACME host whose **owning
  namespace** is not permitted that domain is **excluded** from the ACME issuer HostPolicy
  (no `tls acme` directive is rendered for it) and surfaced as a warning Event. When unset
  (the default), every watched host is eligible — the single-trust-domain behaviour is
  unchanged. Format: `ns=suffix[,suffix];ns2=suffix` (a suffix matches the apex and any
  subdomain; a leading `*.` is accepted and normalised away). The owner namespace is the
  same first-claim owner routing/TLS use.
- **Per-namespace resource caps (optional, off by default).** An operator may bound a
  noisy/hostile tenant's footprint with `--max-sites-per-namespace`,
  `--max-routes-per-namespace`, and `--max-fragment-bytes`. When a namespace exceeds a cap,
  the **excess is rejected deterministically** — oldest-Ingress-first, so the namespace's
  earlier sites/routes keep rendering and only the newest over-the-line ones are dropped,
  each with a per-Ingress warning Event. An over-size `cadi.sh/policy` fragment is rejected
  **before** it is validated/compiled. **Other namespaces are never affected.** Every cap
  defaults to `0` = unlimited = unchanged behaviour.
- **SSRF literal guard.** A `to` backend target whose host is a **link-local / cloud-metadata
  IP literal** (`169.254.0.0/16`, incl. `169.254.169.254`; IPv6 `fe80::/10`) is rejected.
  Private / RFC1918 ranges stay allowed (pod IPs and private origins are legitimate).
- **One bad tenant can't freeze the cluster.** A site that fails to compile in the combined
  config is **dropped alone** (with a per-Ingress Event); every other site still applies.
  Malformed rule hosts are rejected in the translator rather than trusted from the API
  server. Render/apply failure keeps the last-good config live.

- **Label-scoped Secret/ConfigMap reads (C1).** By default the controller watches Secrets
  and ConfigMaps **cluster-wide** (so a compromise could read every Secret). Set a label
  selector to bound the blast radius: `-secret-label-selector` / `-configmap-label-selector`
  (or `-watch-label-selector` for both), e.g. `cadi.sh/managed=true`. Only objects matching
  the selector ever enter the controller's informer cache. **Off by default** (empty = watch
  all = unchanged). When you set a selector you **must label** your BYO/cert-manager TLS
  Secrets and your `cadi.sh/policy` ConfigMaps with the same label, or the controller will
  not see them — a TLS host then falls through to ACME and a policy fragment resolves to
  empty. See [RBAC & least privilege](#rbac--least-privilege) for the matching RBAC tightening.

> **Recommended for production / multi-tenant clusters:** prefer the scoped posture —
> apply `deploy/k8s/rbac-controller-scoped.yaml` (or Helm `--set controller.rbac.scoped=true`
> with `controller.namespaces=…`) **and** a `-watch-label-selector` — so the controller
> never holds cluster-wide `secrets` read. The cluster-wide default exists only for the
> simplest single-trust-domain case.

> With slices A–C (cross-namespace host-ownership + per-namespace ACME allow-list, per-tenant
> resource caps + removed-pool drain, and now label-scoped Secret/ConfigMap reads) the
> previously-deferred hostile-multi-tenant fronts are closed. Hardening remains operator-
> curated and **off by default** — a single-trust-domain cluster keeps the original behaviour.

## Multi-tenant runbook

The default posture is **single-trust-domain** ([Security model](#security-model)):
cluster RBAC is the tenant boundary. To run cadish ingress across **untrusted
namespaces**, layer the controls below — all are **off by default** and a
single-trust-domain cluster keeps its original behaviour. The invariants in
[Security model](#security-model) (policy-fragment confinement, first-claim host/TLS
ownership, SSRF guard, one-bad-tenant-can't-freeze-serving) apply in any trust model;
this runbook adds the operator-curated bounds on top.

1. **Scope the namespaces you serve.** Run with `-namespace ns1,ns2` (Helm
   `controller.namespaces=ns1,ns2`) so the controller only reconciles Ingresses in the
   tenant namespaces you opt in. Reconcile filters by namespace in code even though the
   informers list cluster-wide.

2. **Scope the Secret/ConfigMap blast radius (C1).** By default the controller caches
   **every** Secret and ConfigMap cluster-wide. Bound it two ways, combined:
   - **Label-scope the cached reads** — `-watch-label-selector cadi.sh/managed=true`
     (or `-secret-label-selector` / `-configmap-label-selector` for one each). Only
     labelled objects ever enter the informer cache, so a compromise reads only what you
     labelled. You **must** then label your BYO/cert-manager TLS Secrets and your
     `cadi.sh/policy` ConfigMaps, or a TLS host falls through to ACME and a fragment
     resolves to empty.
   - **Scope the granted RBAC** — apply
     [`deploy/k8s/rbac-controller-scoped.yaml`](../deploy/k8s/rbac-controller-scoped.yaml)
     instead of `rbac-controller.yaml` (or Helm `controller.rbac.scoped=true` with
     `controller.namespaces`). This drops the cluster-wide `secrets`/`configmaps` read
     rule and grants those reads via per-namespace `Role`s. Core k8s RBAC cannot filter
     by label, so the selector bounds **which objects** are cached and the per-namespace
     Roles bound **which namespaces** are readable — use both. (EndpointSlice/Ingress
     reads stay cluster-wide.) See [RBAC & least privilege](#rbac--least-privilege).

3. **Cap each tenant's footprint.** A noisy or hostile namespace can't starve the others:
   `-max-sites-per-namespace N`, `-max-routes-per-namespace N`, and `-max-fragment-bytes N`
   reject the excess **oldest-Ingress-first** (the namespace's earlier sites/routes keep
   serving; only the newest over-the-line ones are dropped, each with a per-Ingress
   warning Event). An over-size `cadi.sh/policy` fragment is rejected before it is
   compiled. Every cap is `0` = unlimited; other namespaces are never affected.

4. **Restrict ACME to permitted domains.** ACME issuance is always bounded to the
   watched-host union, but with untrusted tenants also set `-acme-domain-policy
   'team-a=a.example.com;team-b=b.example.com'` so a namespace can only auto-issue for
   its own domain suffixes (the apex and any subdomain; a leading `*.` is normalised
   away). A host whose **owning** namespace is not permitted its domain is excluded from
   the issuer HostPolicy (no `tls acme` rendered) and surfaced as a warning Event.

5. **Rely on first-claim host ownership.** A host's routing **and** TLS are owned by the
   **oldest** Ingress that declared a rule for it; an Ingress in a *different* namespace
   that tries to contribute rules, a `spec.defaultBackend`, or a `spec.tls` cert for that
   host is **rejected for that host** (per-Ingress Event) and never merged — a tenant
   cannot claim, parasitize, or hijack the cert of another namespace's hostname. Same
   namespace still merges. No flag needed; this is always on. (See
   [Security model](#security-model) for the full statement.)

Recommended baseline for an untrusted-multi-tenant cluster: `rbac-controller-scoped.yaml`
**+** `-watch-label-selector` **+** `-namespace` **+** the per-namespace caps **+**
`-acme-domain-policy`.

## HA & leader election

Every replica **serves traffic** with no coordination — run 2+ for HA. A `client-go`
leader-elected `Lease` (`coordination.k8s.io/v1`) gates **only** the writer that stamps
`status.loadBalancer` on Ingresses (the address comes from `--publish-service`). Serving
is *never* gated by leadership.

## Multiple controllers

Run several controllers side by side by giving each its own class:
`cadish ingress --ingress-class cadish-internal` vs the default `cadish`. Each only owns
Ingresses whose class matches.

## Observability

- **Kubernetes Events** on every accept/reject (e.g. duplicate-path conflicts, bad
  policy fragments, render/apply failures) — `kubectl describe ingress …` /
  `kubectl get events`.
- The controller exposes a reconcile snapshot (watched-Ingress count, last-applied
  config hash, per-reconcile rejects, last error, leader status) via `Controller.Stats()`.
  When the base Cadishfile declares an `admin` block, `cadish ingress` renders it as a
  **Kubernetes Ingress** panel on the admin dashboard, refreshed once a second over the
  existing live feed (`/api/ingress` + the SSE stream). Plain `cadish run` has no
  controller, so the panel never appears.

## Warm-readiness probe (`/.cadish/readyz`)

cadish serves a reserved `/.cadish/readyz` endpoint that reports **`503 Service
Unavailable` until the controller's first reconcile builds the routing table** from synced
listers, then **`200 OK`**. The controller's `startupProbe` and `readinessProbe` use it
(`httpGet: /.cadish/readyz`), so Kubernetes does **not** route traffic to a pod whose
routing table is not yet built — closing the rollout window where a freshly-started pod
would otherwise return transient **502s** (a TCP probe passes the instant the listener
binds, *before* `WaitForCacheSync` + the first reconcile). The endpoint is Host-agnostic,
answers any method, is never cached or logged as traffic, and never reaches an origin. The
`livenessProbe` deliberately stays **TCP** — liveness must check process-alive, not warm,
or it would kill a pod that is merely between configs.

The probe targets the plain **`:80`** listener (`port: http`, scheme HTTP). Even when the
controller terminates TLS, `/.cadish/readyz` is **exempt from the HTTP→HTTPS redirect** on
`:80`: it is served straight through to the data plane and returns the real `200`/`503`,
never a `301`. This matters because a Kubernetes `httpGet` probe treats **both 2xx and 3xx
as success** — if the probe were redirected it would pass regardless of warm state,
silently defeating the gate. Keep the probe on the HTTP scheme/`:80` port for this reason.

## Troubleshooting

Quick diagnoses for the failures you are most likely to hit. Each has a symptom, the
command to confirm it, and the fix.

### (a) `ImagePullBackOff` / `ErrImagePull`

**Symptom.** Controller pods never start; `kubectl get pods -n cadish` shows
`ImagePullBackOff`.

**Diagnose.**

```bash
kubectl describe pod -n cadish -l app.kubernetes.io/name=cadish-ingress | grep -A3 -i pull
```

A `denied`/`unauthorized`/`manifest unknown` on `ghcr.io/cadi-sh/cadish` means the
image is private to the node's pull credentials.

**Fix** — pick one:

- **Make the GHCR package public** (simplest): on github.com/cadi-sh, open the `cadish`
  package → *Package settings* → *Change visibility* → Public.
- **Use an imagePullSecret.** Create a docker-registry Secret in the `cadish` namespace
  and reference it: with Helm set `imagePullSecrets: [{name: ghcr}]`; with the raw
  manifest add `imagePullSecrets` under the Deployment pod `spec`.

  ```bash
  kubectl create secret docker-registry ghcr -n cadish \
    --docker-server=ghcr.io --docker-username=<user> --docker-password=<token>
  ```

- **Sideload the image** (air-gapped / k3s): pull elsewhere, `docker save`, copy, then on
  each node `sudo k3s ctr images import cadish.tar` and set `image.pullPolicy=IfNotPresent`.

### (b) Ingress `ADDRESS` stays empty

**Symptom.** `kubectl get ingress -n <ns>` shows no `ADDRESS`, even though traffic works.

**Diagnose.**

```bash
kubectl get svc cadish-ingress -n cadish                     # does the LB have an EXTERNAL-IP?
kubectl logs -n cadish -l app.kubernetes.io/name=cadish-ingress | grep -i 'publish\|leader\|status'
```

The status writer is **leader-only** and reads the publish Service's address.

**Fix.**

- Confirm the LoadBalancer Service actually got an external address (a bare cluster with
  no cloud LB / MetalLB leaves it `<pending>` — there is then no address to publish).
- Confirm `-publish-service cadish/cadish-ingress` is set (it is in the shipped manifest;
  Helm needs `controller.publishService=cadish/cadish-ingress`). Empty disables status
  writing.
- The ClusterRole must grant `get` on `services` (the leader does a direct GET of the
  publish Service) — see error (d). Without it the address resolves to `""`.

### (c) 404 / 502 / no route

**Symptom.** The request returns 404, a `502 no site configured for host`, or the wrong
backend instead of yours.

**Diagnose.**

```bash
kubectl get ingress -n <ns> <name> -o jsonpath='{.spec.ingressClassName}{"\n"}'  # must be 'cadish'
kubectl describe ingress -n <ns> <name>                                          # Events: conflicts/rejects
kubectl get endpointslices -n <ns> -l kubernetes.io/service-name=<svc>           # any READY endpoints?
```

**Fix.**

- **Class mismatch** — `ingressClassName` must be `cadish` (or the legacy
  `kubernetes.io/ingress.class: cadish` annotation, or mark the IngressClass default).
  An Ingress with another class is simply not served by cadish.
- **Host mismatch** — cadish is host-routed; the request `Host` must equal a `rules[].host`.
  Test with `curl -H 'Host: <host>'`. With two or more sites, an unknown host gets a
  **`502` with body `no site configured for host`** — it is never silently sent to another
  Ingress's `defaultBackend`. (Special case: with exactly **one** site configured, cadish
  serves that lone site for *every* host, so a wrong host still returns `200` from the
  single backend; add a second host and the match becomes strict.)
- **No ready backends** — if the Service has no ready EndpointSlices (pods not ready /
  scaled to zero / wrong `port`) the upstream is empty and returns 503/closes. Check the
  pods are `Ready` and the Service `port` matches.
- **Path-scoped 404** — a site with only explicit paths and no `Prefix /` catch-all (and
  no `spec.defaultBackend`) returns 404 for any unmatched path by design.

### (d) RBAC `forbidden` in controller logs

**Symptom.** Logs show `... is forbidden: User "system:serviceaccount:cadish:cadish-ingress"
cannot list/get/watch resource ...`.

**Diagnose.**

```bash
kubectl logs -n cadish -l app.kubernetes.io/name=cadish-ingress | grep -i forbidden
kubectl auth can-i list secrets --as=system:serviceaccount:cadish:cadish-ingress
```

**Fix.** Apply (or re-apply) `deploy/k8s/rbac-controller.yaml` — it grants exactly the
needed verbs: `get/list/watch` on `endpointslices`, `ingresses`, `ingressclasses`,
`secrets`, `configmaps`; `get` on `services`; `update/patch` on `ingresses/status`;
`create/patch` on `events`; and the leader `leases` Role. A `forbidden` on `secrets`
after switching to the **scoped** RBAC usually means a TLS Secret lives in a namespace
not listed in `controller.namespaces` (its per-namespace `Role` was never created).

### (e) TLS not terminating

**Symptom.** HTTPS fails (cert error, or the host falls back to plain HTTP / a self-signed
cert).

**Diagnose.**

```bash
kubectl get secret -n <ns> <secretName> -o jsonpath='{.type}{"\n"}'   # must be kubernetes.io/tls
kubectl describe ingress -n <ns> <name> | grep -i 'BadTLSSecret\|tls\|acme'
```

**Fix.**

- **BYO cert** — the Secret named in `spec.tls[].secretName` must exist in the Ingress's
  namespace, be type `kubernetes.io/tls`, and carry a parseable `tls.crt`/`tls.key`. An
  unparseable keypair falls back to ACME with a `BadTLSSecret` Event.
- **Label selector** — if you set `-watch-label-selector`, the TLS Secret must carry that
  label or the controller never sees it (the host falls through to ACME).
- **ACME issuance** — for an auto-issued host the LB must be reachable on `:80` for HTTP-01,
  and (if set) the owning namespace must be permitted the domain by `-acme-domain-policy`,
  else the host is excluded from the issuer HostPolicy (warning Event). Set `--acme-email`
  and a persistent `--acme-cache` to avoid re-issuing on restart (Let's Encrypt rate limits).

## CLI flags

```
cadish ingress \
  -config /etc/cadish/base.cadish   # base Cadishfile (globals only)
  -ingress-class cadish             # the IngressClass to serve
  -namespace ns1,ns2                # restrict watched namespaces (default: all)
  -publish-service ns/name          # Service whose address is written to Ingress status
  -leader-elect                     # leader-elect the status writer (default true)
  -addr :80  -https-addr :443       # listen addresses
  -acme-email you@example.com       # ACME account contact for auto-issued spec.tls hosts
  -acme-cache PATH                  # on-disk cache for ACME-issued certs
  -acme-domain-policy SPEC          # per-namespace ACME domain allow-list (off by default)
                                    #   SPEC: 'ns=suffix[,suffix];ns2=suffix'
  -max-sites-per-namespace N        # cap distinct hosts per namespace (0 = unlimited)
  -max-routes-per-namespace N       # cap routes (paths) per namespace (0 = unlimited)
  -max-fragment-bytes N             # cap cadi.sh/policy fragment size in bytes (0 = unlimited)
  -watch-label-selector SEL         # scope BOTH Secret + ConfigMap reads to SEL (off by default)
  -secret-label-selector SEL        # scope Secret reads only (overrides watch; off by default)
  -configmap-label-selector SEL     # scope ConfigMap reads only (overrides watch; off by default)
  -kubeconfig PATH                  # out-of-cluster (default: in-cluster)
```

This is the subset the prose above relies on; run `cadish ingress -h` for the full set
(including `-identity`, `-leader-name`/`-leader-namespace`, `-idle-timeout`, and
`-resync-debounce`).

`SIGHUP` re-reads the base Cadishfile and re-reconciles.

## RBAC & least privilege

The controller's informers watch **cluster-wide** by default and reconcile filters by
namespace in code, so its **reads** (`endpointslices`, `ingresses`, `ingressclasses`,
`secrets`, `configmaps`) are granted cluster-wide via a `ClusterRole` — a namespace-scoped
`LIST`/`WATCH` would be denied at the API server and break the informer cache. Its
**writes**, however, only ever touch the namespaces it serves (`ingresses/status` patches
on owned Ingresses; `events` in the involved object's namespace).

When you restrict namespaces, prefer the Helm chart and set `controller.namespaces`: the
chart then **drops the write verbs from the `ClusterRole`** and grants `ingresses/status`
and `events` via **per-namespace `Role`/`RoleBinding`s** (one per served namespace, plus
the controller's own namespace for IngressClass/Secret Events), so the controller cannot
write status or Events cluster-wide. With no namespace restriction (the default) the writes
remain cluster-wide. The static manifest (`deploy/k8s/rbac-controller.yaml`) is cluster-wide
by default and documents the namespaced split inline.

> **Security — RBAC blast radius.** The cluster-wide `get`/`list`/`watch` on `secrets`
> means that a **compromised controller pod can read every `Secret` in the cluster**,
> including TLS private keys for every workload. This is the same posture as
> ingress-nginx and Traefik — it is inherent to the role of a TLS-terminating ingress
> controller — but operators should account for it:
>
> - **Isolate the controller pod** from untrusted workloads. An attacker with code
>   execution in any pod on the same node can reach the controller's service-account
>   token. Use node taints/tolerations or dedicated nodes to prevent co-scheduling.
> - **Restrict who can create `Ingress` objects and `Secrets`** in served namespaces —
>   the controller's read access is broad, so controlling what enters the cluster limits
>   what it can be directed to expose.
> - **Use namespace restriction** (`-namespace ns1,ns2` / `controller.namespaces` Helm
>   value) when you don't need cluster-wide Ingress serving; this also narrows the
>   write scope automatically.
> - **Label-scope the reads (C1).** Set `-secret-label-selector` / `-configmap-label-selector`
>   (or `-watch-label-selector`), e.g. `cadi.sh/managed=true`. The informer list/watch then
>   carries that selector, so the controller's cache **only ever contains matching objects** —
>   a compromise can read only the Secrets/ConfigMaps you explicitly labelled for cadish, not
>   the whole cluster. You **must** label your TLS Secrets + policy ConfigMaps accordingly.
> - **Namespace-scope the reads via RBAC.** Core k8s RBAC **cannot filter by label**, so the
>   selector above bounds what is *cached/read* but the `ClusterRole` still *grants* cluster-wide
>   read. To also tighten the grant, run with `-namespace ns1,ns2` and either:
>   - **Helm:** set `controller.rbac.scoped=true` (with `controller.namespaces`) — the chart
>     drops the cluster-wide `secrets`/`configmaps` rule and grants those reads via
>     **per-namespace `Role`s** in the served namespaces (plus the controller's own, for the
>     base ConfigMap); or
>   - **Static manifest:** apply [`deploy/k8s/rbac-controller-scoped.yaml`](../deploy/k8s/rbac-controller-scoped.yaml)
>     instead of `rbac-controller.yaml` (enumerate one read `Role`/`RoleBinding` per namespace).
>
>   Combine both: the **label selector bounds which objects** are cached, the **per-namespace
>   Roles bound which namespaces** are readable. (EndpointSlice/Ingress reads stay cluster-wide.)
>
> See [SECURITY.md](../SECURITY.md#kubernetes-controller-rbac-blast-radius) for the
> full blast-radius analysis and mitigations.
