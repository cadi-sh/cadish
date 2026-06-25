# cadish as a Kubernetes Gateway API controller

Run cadish in-cluster as a **Gateway API controller**: it watches `GatewayClass` /
`Gateway` / `HTTPRoute` objects, translates the HTTP routing they describe into the *same*
compiled routing cadish builds from a Cadishfile, and hot-swaps the live config with zero
downtime — the **same atomic swap** the [Ingress controller](ingress-controller.md) uses.
The cluster's Gateway API objects become the source of truth; a small **base Cadishfile**
supplies only globals.

It runs **alongside** the Ingress controller (a separate Deployment, a distinct
controllerName), not instead of it. Pick whichever API your platform standardises on — or
run both.

This is **Layer 2**, built on **Layer 1** (`k8s://service.namespace:port` upstream
resolution via EndpointSlices): every `backendRef` Service becomes a `k8s://` upstream, so
cadish runs its own load balancing over the live ready pods, exactly as the Ingress
controller does.

> **Status.** Gateway API support is complete for the common HTTP(S) path: GatewayClass
> acceptance, HTTP **and HTTPS (TLS Terminate) listeners with `certificateRefs`**, HTTPRoute
> host + path routing with **advanced matchers** (`headers` / `queryParams` / `method`),
> **cross-namespace refs gated by `ReferenceGrant`**, **weighted backend pools**, and status
> conditions. See [What's not (yet) supported](#whats-not-yet-supported) for the remainder
> (ACME for a Gateway listener, exotic HTTPRoute filters, `GRPCRoute`/`TCPRoute`/`TLSRoute`).

## How it works

```
GatewayClass / Gateway / HTTPRoute               (the desired state)
        │  informers + debounce
        ▼
   translator  → Cadishfile text  → config compiler → routing
        │                                              │ Server.ApplyConfig (atomic swap)
        └──────────────── one Cadishfile, one compiler ┘
```

- **GatewayClass acceptance.** A `GatewayClass` whose `spec.controllerName` is
  `cadi.sh/gateway-controller` is **owned** by cadish; cadish sets its `Accepted`
  condition. A GatewayClass naming any other controller is ignored entirely (no status is
  written for it).
- **Gateway listeners (HTTP + HTTPS).** For each `Gateway` using an accepted GatewayClass,
  every `protocol: HTTP` listener becomes an attachment point (with an optional `hostname`
  constraint). A `protocol: HTTPS` listener with `tls.mode: Terminate` and a
  `certificateRefs` entry pointing at a `kubernetes.io/tls` Secret **terminates TLS** for its
  hostname using that BYO cert — see [HTTPS / TLS termination](#https--tls-termination).
  cadish sets the Gateway's `Accepted` + `Programmed` conditions and a per-listener status
  (including `attachedRoutes`).
- **HTTPRoute → routing.** An `HTTPRoute` attaches to a Gateway via `parentRefs`. Its
  `spec.hostnames` (intersected with the listener's hostname) become **sites**; each
  `rules[].matches[]` becomes a route condition (path **plus** any `headers` / `queryParams`
  / `method` — see [Advanced matchers](#advanced-matchers)), routed to the rule's Service
  `backendRef`(s) as `upstream u_… { to k8s://svc.ns:port }`. cadish sets the route's
  `Accepted` + `ResolvedRefs` conditions per parent.
- **Path semantics — identical to the Ingress translator.**
  - `Exact /p` → `path /p` (matches only `/p`).
  - `PathPrefix /p` → `path /p /p/*` (matches `/p` and any `/p/…` subpath, **never**
    `/prefix`). This is the element-wise Kubernetes prefix, the same as Ingress `Prefix`.
- **Most-specific-wins** is reproduced by cadish's first-match-wins `route` order (Exact
  before PathPrefix; longer path before shorter).
- **Unmatched paths 404 (path-scoped isolation).** A site whose paths are all explicit
  (no `PathPrefix /` catch-all) emits a terminal `respond !@r0 !@r1 … 404`, so a request
  matching none of the declared paths returns **404** instead of silently falling back to
  the site's first declared upstream. A backend mapped to `/api` does **not** also serve
  `/admin`. This is the same F7 fix the Ingress controller enforces.
- **Unmatched host 404.** A request whose `Host` matches no Gateway listener / HTTPRoute
  hostname returns **404 Not Found** (the Gateway data plane's not-found posture), rather
  than the standalone server's 502 — there is simply no route for that authority.
- **Graceful degradation.** A single bad HTTPRoute (e.g. a backendRef that does not
  resolve) never freezes all routing: its site is dropped alone, the rest keep serving,
  and its status reflects the problem. The last good config stays live on any compile or
  apply failure.

The translator is **pure**: identical inputs render byte-identical Cadishfile text, so the
controller skips no-op swaps. It reuses the Ingress translator's rendering (upstream
dedup, specificity ordering, the element-wise PathPrefix matcher, the terminal 404), so
the two controllers emit the *same* routing model.

## Install

Prerequisite: the Gateway API CRDs are **not** bundled with Kubernetes. Install them:

```sh
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.1/standard-install.yaml
```

Then apply the controller:

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac-gateway.yaml
kubectl apply -f deploy/k8s/gateway-controller.yaml
```

`deploy/k8s/gateway-controller.yaml` ships a `GatewayClass` named `cadish` with
`controllerName: cadi.sh/gateway-controller`, a globals-only base ConfigMap, a 2-replica
Deployment binding `:80` and `:443`, and a LoadBalancer Service.

> **Single-IP clusters — don't run two LoadBalancer host-port controllers at once.**
> The ingress controller and the Gateway controller each ship as a `LoadBalancer`
> Service binding host `:80`/`:443`. On a single-node / single-IP cluster (e.g. k3s)
> the two collide on the same host ports. Run only one of them, or expose them via
> `NodePort` / separate IPs.

## Using it

Create a Gateway with an HTTP listener and an HTTPRoute attaching to it:

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: web
  namespace: prod
spec:
  gatewayClassName: cadish
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      # hostname: shop.example.com   # optional listener hostname constraint
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: shop
  namespace: prod
spec:
  parentRefs:
    - name: web            # attaches to the Gateway above (same namespace)
  hostnames:
    - shop.example.com
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api
      backendRefs:
        - name: api-svc    # a core Service in the same namespace
          port: 8080
```

This renders (and atomically applies) the equivalent of:

```
shop.example.com {
    upstream u_prod_api_svc_8080 { to k8s://api-svc.prod:8080 }
    @r0 path /api /api/*
    route @r0 -> u_prod_api_svc_8080
    respond !@r0 404
}
```

`/api` and `/api/v1/...` route to `api-svc`; `/apiother` and any other unmatched path
return **404**.

## HTTPS / TLS termination

An `HTTPS` listener with `tls.mode: Terminate` (the default) and a `certificateRefs` entry
referencing a `kubernetes.io/tls` Secret terminates TLS for the listener's hostname using
that **bring-your-own** certificate (e.g. a cert-manager-issued Secret). This reuses the
**exact same dynamic-cert mechanism** the Ingress controller uses (`Server.SetDynamicCerts`,
one TLS manager keyed by SNI host), including the **SAN-coverage gate**: cadish registers a
cert for a hostname **only** if the certificate's SANs actually cover it — a mismatch is
refused (the listener is `Programmed=False` with a SAN-mismatch reason) rather than serving
the wrong cert. Multiple HTTPS listeners on one Gateway (different hostnames / certs) all
program independently.

```yaml
spec:
  gatewayClassName: cadish
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      hostname: secure.example.com
      tls:
        mode: Terminate
        certificateRefs:
          - kind: Secret
            name: secure-example-tls   # a kubernetes.io/tls Secret covering secure.example.com
```

The controller binds `:443` and injects the BYO cert on reconcile (a Secret rotation
hot-swaps the served cert with no restart). A listener whose cert is missing, unusable, or
does **not** cover the hostname is acknowledged but not programmed (a clear status reason);
any HTTP listener on the same Gateway keeps serving (graceful degradation).

> **ACME for a Gateway listener is deferred.** A terminating listener must reference a BYO
> `kubernetes.io/tls` Secret. (The Ingress controller's ACME path is unchanged.)

## Advanced matchers

A `rules[].matches[]` entry may combine a `path` with `headers`, `queryParams`, and a
`method`. Within one match all conditions are **AND**ed; multiple matches in a rule are
**OR**ed (any one routes). These map onto cadish's matcher primitives:

| Gateway match | cadish matcher |
|---|---|
| `headers` `type: Exact` | `header NAME VALUE` |
| `headers` `type: RegularExpression` | `header_regex NAME RE` |
| `queryParams` `type: Exact` | `query NAME VALUE` |
| `method` | `method VERB` |
| `path` `Exact` / `PathPrefix` | `path /p` / `path /p /p/*` |

A multi-criteria match renders one composite `all` matcher (an AND of the path + condition
matchers), so the route is a single `route @rN -> u` and the terminal no-match **404** stays
correct (a request matching the path but failing a header/method condition 404s, it does not
fall through). `queryParams` `type: RegularExpression` is not supported and is surfaced as
`UnsupportedValue` (the rest of the match still applies).

## Cross-namespace references (`ReferenceGrant`)

A `backendRef` (or an HTTPS listener `certificateRef`) to **another namespace** is allowed
**only** when a `ReferenceGrant` in the *target* namespace permits it, per the Gateway API
trust model. Without a permitting grant the reference is refused and the route's
`ResolvedRefs` is `False` (`RefNotPermitted`).

```yaml
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-team-a-routes
  namespace: team-b            # the TARGET namespace (where the Service lives)
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      namespace: team-a        # the route's namespace
  to:
    - group: ""
      kind: Service            # (omit `name` to allow all Services of this kind)
```

## Weighted backends

A rule with multiple `backendRefs` builds a **load-balanced pool** over all of them
(`upstream u_… { to k8s://a.ns:p k8s://b.ns:p }`), and cadish runs its own LB over the live
ready pods. A `backendRef` with `weight: 0` is excluded. **Note:** cadish has no per-backend
weight knob, so proportional `weight`s are **approximated** as an even split across the
listed backends (surfaced once as a status note); equal weights are exact. See the ADR for
the rationale.

### Inspecting status

```sh
kubectl get gatewayclass cadish -o jsonpath='{.status.conditions}'
kubectl get gateway web -n prod -o jsonpath='{.status}'
kubectl get httproute shop -n prod -o jsonpath='{.status.parents}'
```

You should see `Accepted=True` on the GatewayClass; `Accepted=True` + `Programmed=True`
plus per-listener status on the Gateway (an HTTPS listener whose cert is registered is
`Programmed=True`; a missing/mismatched cert is `Programmed=False` with the reason); and
`Accepted=True` + `ResolvedRefs=True` per parent on the HTTPRoute. A backendRef that does
not resolve shows `ResolvedRefs=False` (`BackendNotFound`); a cross-namespace ref without a
`ReferenceGrant` shows `ResolvedRefs=False` (`RefNotPermitted`); a route that attaches to no
listener shows `Accepted=False` (`NoMatchingParent`).

## HA & leader election

Every replica **serves traffic** (no coordination). A leader-elected `coordination.k8s.io`
Lease (`cadish-gateway-leader`) gates **only** the status writer — exactly like the Ingress
controller. Serving is never gated by leadership. Run >= 2 replicas. Disable with
`-leader-elect=false` for a single replica.

## CLI

```
cadish gateway [-config base.cadish] [flags]

  -config string             base Cadishfile (globals only)              (default cadishfile)
  -namespace string          comma-separated namespaces to watch (empty = all)
  -addr string               HTTP listen address                         (default ":80")
  -https-addr string         HTTPS listen address (BYO-cert termination) (default ":443")
  -kubeconfig string         kubeconfig path (else in-cluster / KUBECONFIG)
  -resync-debounce duration  quiet window before a reconcile             (default 250ms)
  -leader-elect              leader-elect the status writer              (default true)
  -leader-namespace string   namespace for the leader-election Lease
  -leader-name string        Lease name                                  (default cadish-gateway-leader)
  -identity string           leader-election identity (default POD_NAME / hostname)
```

## RBAC & least privilege

`deploy/k8s/rbac-gateway.yaml` grants exactly:

- `gatewayclasses` / `gateways` / `httproutes` / `referencegrants` — `get,list,watch`
  (build routing + authorize cross-namespace refs);
- the route/gateway/class `/status` subresources — `update,patch` (the leader-elected status writer);
- `endpointslices` — `get,list,watch` (Layer-1 `k8s://` resolution);
- `services` — `get,list,watch` (backendRef resolution);
- `secrets` — `get,list,watch` (BYO TLS certs for HTTPS listener `certificateRefs`);
- `leases` in the controller's namespace — leader election.

Reads are cluster-wide because the informers watch cluster-wide. The label-scoping and
namespaced-Role hardening the Ingress controller offers (its C1 / `rbac-controller-scoped`
variants) is a planned follow-up for the Gateway controller's hostile-multi-tenant story.

## What's not (yet) supported

The following are recognised but not programmed; each is surfaced with a clear status
reason (never silently dropped), and a bad element never breaks the others:

- **ACME for a Gateway listener.** A terminating HTTPS listener must reference a BYO
  `kubernetes.io/tls` Secret; cadish does not auto-issue a Gateway listener cert via ACME.
- **`queryParams` `type: RegularExpression`** — surfaced as `UnsupportedValue` (the rest of
  the match still applies). `headers` RegularExpression **is** supported.
- **`HTTPRoute` filters** (`RequestHeaderModifier`, `RequestRedirect`, `URLRewrite`,
  `RequestMirror`, …) — surfaced as `UnsupportedValue`; the rule still serves its backend.
- **Per-backend weights are approximated** as an even split (cadish has no per-backend
  weight knob); `weight: 0` excludes a backend exactly.
- **`TLS` (passthrough) listeners**, **`GRPCRoute` / `TCPRoute` / `TLSRoute`**, and Gateway
  `addresses` publishing.
- **Gateway-native cache policy.** There is no HTTPRoute/Gateway-attached cache-policy
  resource in v1. Caching is configured only through the **base Cadishfile globals** (the
  controller's base ConfigMap) and applies to all routed traffic; you cannot scope cache
  behavior per-HTTPRoute via a Gateway API object.

These are deliberate v1 scoping decisions; see
[ingress-controller.md](ingress-controller.md) for the controller model they build on.
