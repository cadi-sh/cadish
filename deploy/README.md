# Deploying cadish

This directory has everything to run cadish in production:

- [`Dockerfile`](Dockerfile) — the multi-stage build (distroless, non-root).
- [`helm/cadish`](helm/cadish) — the Helm chart (recommended).
- [`k8s/`](k8s) — plain, editable manifests (kustomize) for the same thing.

cadish needs three things from its environment regardless of how you deploy it:

1. **Two persistent volumes** — `/var/lib/cadish` (ACME cert cache; losing it
   re-issues every cert and risks Let's Encrypt rate limits) and
   `/var/cache/cadish` (the NVMe cache tier; persisting avoids a cold-cache origin
   stampede on restart). Both must be **writable by uid 65532** (see below).
2. **The ability to bind its ports** — `:80` and `:443` by default (via
   `CAP_NET_BIND_SERVICE`), or any high ports if you'd rather run cap-less.
3. **Its config** — a `Cadishfile` (mounted at `/etc/cadish/Cadishfile`). Validate
   it with `cadish check` (wire it into CI; see [../docs/check.md](../docs/check.md)).

## Volume ownership (the non-root uid)

The image runs **non-root as uid 65532** (distroless). A **fresh** persistent or
named volume is created **root-owned**, so cadish can't create
`/var/cache/cadish/blobs` (or the ACME dir) and crash-loops on
`mkdir /var/cache/cadish/blobs: permission denied`. Make the volumes writable by
65532 — **don't** run cadish as root (that defeats the security posture below):

- **Kubernetes (Helm / k8s manifests):** the pod `securityContext` sets
  **`fsGroup: 65532`**, so most CSI drivers chown the mounted volume to that group
  on attach — nothing else to do. Some volume types (`hostPath`, many `local`/NFS
  provisioners) **ignore `fsGroup`**; for those, enable the chown initContainer:
  Helm `--set volumePermissions.enabled=true`, or uncomment the `initContainers:`
  block in [`k8s/deployment.yaml`](k8s/deployment.yaml). It runs once as root and
  chowns the cache (and ACME) mounts to 65532 before cadish starts.
- **`docker run` / Docker Compose:** named volumes aren't chowned for you. Run this
  one-liner **once per volume** before (or after) first start:

  ```sh
  docker run --rm -v <volume>:/data busybox chown -R 65532:65532 /data
  ```

  (e.g. `docker run --rm -v cadish_cache:/data busybox chown -R 65532:65532 /data`,
  and the same for the ACME volume.) A bind-mounted host directory works too —
  `chown -R 65532:65532 ./cache` on the host. If you skip this, cadish now prints an
  actionable error naming the uid and this fix instead of a bare `permission denied`.

## TLS: two deployment shapes

cadish behaves differently on `:80`/`:443` depending on whether **it** terminates
TLS — and that changes how you health-check it:

| | `tls { acme … }` (cadish terminates TLS) | `tls off` (behind an Ingress/LB) |
|---|---|---|
| `:443` | serves the site (and the TLS-ALPN-01 challenge) | not used |
| `:80` | ACME HTTP-01 challenge + **301 redirect** to HTTPS | serves the site directly |
| Health probe | **TCP** on `:443` (the `:80` redirect isn't a 200, and `:443` needs a cert) | **httpGet** `/healthz` on `:80` (a `respond /healthz 200` synthetic) |
| Service | `LoadBalancer` (needs a stable public IP for ACME validation) | `ClusterIP` behind your Ingress |

The chart picks the right probe + ports automatically from `tls.mode`.

> **Health path:** cadish has no built-in `/health` — it's whatever your Cadishfile
> defines with `respond`. For HTTP probes, keep a `respond /healthz 200 "OK"` line
> (the default config does). TCP probes need no such line.

## Helm (recommended)

```sh
# 1. Put your real Cadishfile into values (or use --set-file).
helm install cadish ./deploy/helm/cadish \
  --namespace cadish --create-namespace \
  --set-file config=./my-Cadishfile

# behind-an-ingress variant (plain HTTP, ClusterIP, httpGet probes):
helm install cadish ./deploy/helm/cadish \
  --namespace cadish --create-namespace \
  --set tls.mode=off --set service.type=ClusterIP \
  --set-file config=./my-Cadishfile
```

Then, for `tls.mode=acme`, point each site's DNS A/AAAA record at the Service's
external IP (`kubectl get svc cadish -n cadish -o wide`); cadish issues a
certificate on the first HTTPS request.

Key values (see [`values.yaml`](helm/cadish/values.yaml) for all):

| Value | Default | Notes |
|---|---|---|
| `config` / `existingConfigMap` | sample | your Cadishfile |
| `tls.mode` | `acme` | `acme` or `off` |
| `image.repository` / `image.tag` | `…/cadish` / appVersion | |
| `containerPorts.http/https` | `80` / `443` | high ports ⇒ no `NET_BIND_SERVICE` |
| `service.type` | `LoadBalancer` | `ClusterIP` behind an Ingress |
| `persistence.acme.*` / `persistence.cache.*` | enabled | PVC size/class/mode |
| `podSecurityContext.fsGroup` | `65532` | makes fresh volumes writable by the non-root uid |
| `volumePermissions.enabled` | `false` | chown initContainer for volumes that ignore `fsGroup` |
| `gomemlimit` | "" | soft Go memory ceiling |
| `resources` | 250m/512Mi … 2Gi | size RAM cache below the limit |
| `networkPolicy.enabled` | `false` | restrict ingress/egress |
| `podDisruptionBudget.enabled` | `false` | keep pods up on node drains (enable for HA) |
| `hostPort.enabled` | `false` | also bind ports on the node (bare-metal/edge) |
| `replicaCount` | `1` | see HA note below |

Validate the rendered output before applying:

```sh
helm lint ./deploy/helm/cadish
helm template cadish ./deploy/helm/cadish | less
```

## Plain manifests (kustomize)

[`k8s/`](k8s) is the same deployment as editable YAML (ACME mode). Edit
`k8s/configmap.yaml` with your Cadishfile, then:

```sh
kubectl apply -k deploy/k8s
```

## Security posture

Both paths run cadish **non-root** (uid 65532, distroless), with a **read-only
root filesystem** (only the two PVCs and an `emptyDir` `/tmp` — for RAM-cache temp
dirs — are writable), `allowPrivilegeEscalation: false`, **all capabilities
dropped** except `NET_BIND_SERVICE` (only when binding privileged ports),
`seccompProfile: RuntimeDefault`, and the service-account token unmounted. An
optional `NetworkPolicy` restricts ingress to `:80`/`:443` and egress to DNS +
your origins + ACME.

## High availability

The defaults use `ReadWriteOnce` PVCs and a `Recreate` strategy (a single pod;
RWO volumes can't be co-mounted during a rolling update). For multi-replica HA:

- use `ReadWriteMany` volumes (or disable `persistence` and accept a per-pod cold
  cache), **and**
- give the ACME store a shared (RWX) volume so replicas share one cert cache —
  otherwise each pod issues its own certificates and you'll hit rate limits, **or**
  front cadish with externally-managed certs (`tls { cert … key … }`).

Then raise `replicaCount` and switch `strategy.type` to `RollingUpdate`, and
enable the PodDisruptionBudget (`podDisruptionBudget.enabled=true`, or
`kubectl apply -f deploy/k8s/pdb.yaml`) so node drains keep a pod serving. (A PDB
with a single replica would *block* drains, so it's off by default.)

**Sticky / sharded LB across replicas.** A `sticky` upstream pins a user to a
backend by consistent hash on the cookie/IP — that hashing is per-pod and
deterministic, so it stays stable across replicas (every cadish pod maps a given
key to the same backend). The peer **`cluster … shard_by url`** case is the same:
all pods agree on which peer owns a URL. No shared state is needed for routing;
only the cache *contents* differ per pod (each pod has its own RAM/NVMe tier), so
more replicas trade cache hit-rate for capacity — front with a peer `cluster` if
you want pods to share cache.

## Clustered single-location cache (3 nodes, shared cache)

To run N cadish nodes in one location as **one sharded cache** — each object stored
**once** across the cluster instead of N times — use a `cluster { … }` membership
block in `mode owner`. A request landing on any node is reverse-proxied to the node
that owns that key on a consistent-hash ring; only the owner caches it. A `pass`
route goes straight to origin (no detour). Nodes health-check each other and a failed
node is dropped from the ring (its keys redistribute to a neighbor; they return when
it recovers). Full semantics: the `cluster { … }` section in
[`docs/cadishfile-reference.md`](../docs/cadishfile-reference.md).

**Per-node config** (identical on all three — change only `self`):

```
cache.example.com {
    cache { ram 4GiB disk /var/cache/cadish 50GiB }
    upstream backend { to https://origin.internal }

    # REQUIRED for clustering: trust + isolate the peer network (see below).
    trust_proxy 10.0.0.0/24

    cluster {
        self     http://10.0.0.11:8080          # this node; the only line that differs
        peers    http://10.0.0.11:8080 http://10.0.0.12:8080 http://10.0.0.13:8080
        region   madrid
        mode     owner
        fallback degraded
        health   GET /.cadish/readyz expect 200 interval 1s window 3 threshold 2
    }
    cache_ttl default ttl 60s
}
```

**Entry layer — what lands a client on a node (cadish does not).** cadish routes
*between* nodes but does not distribute the initial request; put one of these in
front:

- **DNS round-robin with health checks (recommended, provider-agnostic).** One
  hostname (`cache.example.com`) with an A/AAAA record per node; the DNS provider
  (Route 53 health checks, NS1, Cloudflare LB, …) probes each node's
  **`/.cadish/readyz`** and withdraws a dead node's record. Because any live node
  forwards a cacheable key to its owner, the entry layer only needs **liveness**, not
  sharding awareness. Caveat: DNS reacts at TTL granularity — keep a **low record
  TTL** so a dead node drains quickly.
- **BGP/anycast or an L4 VIP** (MetalLB+BGP, keepalived) reacts in sub-second time
  with no TTL lag, but couples you to the network/provider — a more advanced option,
  not required.

**Two independent health layers** (don't conflate them):
1. **Entry health** — the DNS/L4 checker → `/.cadish/readyz`: does this node receive
   client traffic at all.
2. **Peer health** — the `cluster { health … }` block: peers probe each other to
   decide ring ownership and ejection.

**Trust + isolation (load-bearing).** The peer subnet **must** be in `trust_proxy`
*and* reachable only by cadish nodes (firewall / security group / NetworkPolicy).
The hop guard and the owner's client-IP/cache-key derivation both depend on the
peers being trusted; isolation is what makes trusting them safe (no untrusted client
can forge headers from the peer network). See the security notes in the
`cluster { … }` reference section.

## Kubernetes-native upstreams (`k8s://` EndpointSlice resolution)

Point `upstream`/`cluster` `to` at a **`k8s://service.namespace:port`** target and
cadish resolves it against the Kubernetes API — watching the service's
**EndpointSlices** and load-balancing directly over the live set of **ready pod
`IP:port`** addresses. It **bypasses kube-proxy/`ClusterIP`**, so cadish's own
policies (`sticky`, `shard_by url`, `least_conn`, per-pod health) act on real pods,
and scaling/rollout churn needs no cadish reload or restart:

```
upstream app {
    to     k8s://my-app.default:8080     # service.namespace (namespace mandatory)
    health GET /healthz expect 200 interval 5s window 3 threshold 2
}
```

The port may be numeric (`:8080`) or a named service port (`:http`). Only ready
endpoints become backends; a scaled-to-zero service returns 503; a transient API
error retains the last-known set. See
[../docs/cadishfile-reference.md](../docs/cadishfile-reference.md) for the full
semantics. This is the in-cluster equivalent of the dynamic director the original
production VCL needed a vmod for.

### RBAC (least privilege)

cadish needs only `get/list/watch` on `discovery.k8s.io/endpointslices` — never
write, never secrets, never pods, never services (named ports are read from the
EndpointSlices' own port list). Apply the ready-made manifest (creates the
`cadish-resolver` ServiceAccount + a read-only ClusterRole/binding in the `cadish`
namespace):

```
kubectl apply -f deploy/k8s/rbac-resolver.yaml
```

In-cluster, set `serviceAccountName: cadish-resolver` on the cadish Deployment;
its mounted token is used automatically (no `--kubeconfig` needed).

### Out-of-cluster kubeconfig recipe

To run cadish OUTSIDE the cluster (e.g. on a VM) against `k8s://` upstreams, give
it a **least-privilege** kubeconfig — never an admin one. Mint a short-lived token
for the read-only ServiceAccount above and assemble a kubeconfig from it:

```sh
# 1. Apply the read-only RBAC (once).
kubectl apply -f deploy/k8s/rbac-resolver.yaml

# 2. Mint a bounded token for the resolver ServiceAccount.
TOKEN=$(kubectl -n cadish create token cadish-resolver --duration=8760h)

# 3. Pull the API server URL and cluster CA from your current context.
APISERVER=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
kubectl config view --raw --minify \
    -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
    | base64 -d > /etc/cadish/k8s-ca.crt

# 4. Assemble a minimal kubeconfig pointing at that SA token.
cat > /etc/cadish/kubeconfig <<EOF
apiVersion: v1
kind: Config
clusters:
- name: c
  cluster:
    server: ${APISERVER}
    certificate-authority: /etc/cadish/k8s-ca.crt
users:
- name: cadish-resolver
  user:
    token: ${TOKEN}
contexts:
- name: c
  context: { cluster: c, user: cadish-resolver }
current-context: c
EOF

# 5. Point cadish at it.
cadish run --kubeconfig /etc/cadish/kubeconfig
```

Precedence is `--kubeconfig` > `KUBECONFIG` > in-cluster > `~/.kube/config`. The
token only grants `get/list/watch` on endpointslices, so a leaked kubeconfig
cannot mutate the cluster or read secrets.

## Ingress-controller mode (`cadish ingress`)

cadish can also run **in-cluster as a Kubernetes Ingress controller** (Layer 2):
it watches `Ingress`/
`IngressClass` (+ referenced `Secret`s and policy `ConfigMap`s) and hot-swaps the live
routing — the cluster's Ingress objects are the source of truth; a base Cadishfile
supplies only globals. Backends become `k8s://` upstreams (the resolution above).

```sh
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac-controller.yaml      # extends the resolver RBAC
kubectl apply -f deploy/k8s/ingress-controller.yaml   # IngressClass + Deployment + LB Service
```

Helm: `--set controller.enabled=true --set controller.publishService=cadish/cadish-ingress`.
Set `controller.defaultClass=true` to make this the cluster's default IngressClass, and
`controller.namespaces=ns1,ns2` to restrict the watch (which also switches the chart to
per-namespace `Role`/`RoleBinding`s).

**Bound the Secret blast radius (C1).** By default the controller reads `Secret`s and
`ConfigMap`s **cluster-wide** — a compromise could read every Secret. To narrow it:

- **Label-scope the cached reads** (off by default): `--set controller.labelSelector.watch=cadi.sh/managed=true`
  (or the `cadish ingress -watch-label-selector` / `-secret-label-selector` /
  `-configmap-label-selector` flags). Only labelled objects enter the informer cache — you
  **must** then label your TLS Secrets + `cadi.sh/policy` ConfigMaps, or they are invisible
  (TLS hosts fall through to ACME; fragments resolve to empty).
- **Namespace-scope the granted RBAC** for a known namespace set: `--set controller.rbac.scoped=true`
  (with `controller.namespaces=ns1,ns2`) drops the cluster-wide `secrets`/`configmaps` rule
  and grants those reads via per-namespace `Role`s. For the static manifests, apply
  `deploy/k8s/rbac-controller-scoped.yaml` instead of `rbac-controller.yaml`.

Core k8s RBAC can't filter by label, so combine both: the selector bounds **which objects**
are cached, the per-namespace Roles bound **which namespaces** are readable.

> **Recommended for production / multi-tenant clusters:** apply
> `deploy/k8s/rbac-controller-scoped.yaml` instead of `rbac-controller.yaml` (or Helm
> `--set controller.rbac.scoped=true`) **and** set a `-watch-label-selector`, so the
> controller never holds cluster-wide `secrets` read. The cluster-wide `rbac-controller.yaml`
> is the convenience default for a single-trust-domain cluster only.

Every replica serves; a leader-elected `Lease` gates ONLY the `status.loadBalancer`
writer. Full guide: [../docs/ingress-controller.md](../docs/ingress-controller.md).

## Tuning

See [../docs/deployment.md](../docs/deployment.md) for `GOMEMLIMIT`, RAM/NVMe tier
sizing, and `cadish check` in CI.
