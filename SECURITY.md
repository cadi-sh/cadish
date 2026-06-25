# Security Policy

cadish terminates TLS and sits on the public edge, so we take security seriously.

## Supported versions

Pre-1.0: only the latest released tag (currently **0.2.0**) receives security
fixes. There is no back-porting to older tags while the API is still stabilizing.

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Instead email
**security@cadi.sh** (or, until that mailbox exists, open a GitHub *security
advisory* on the repository). Include:

- affected version / commit,
- a description and, ideally, a minimal reproduction,
- the impact you foresee.

We aim to acknowledge within 72 hours and to ship a fix or mitigation as fast as
the severity warrants. We'll credit reporters who want it.

## Scope & hardening posture

cadish is built defensively from day one:

- **Never an open ACME issuer** — certificates are only requested for hosts
  explicitly configured in the Cadishfile (host-allowlist policy).
- **No private keys on the edge by design for signed-URL verification** — only
  public keys are needed.
- **TLS hardening defaults** — min TLS 1.2 (1.3 preferred), AEAD/forward-secret
  cipher allow-list, modern curves.
- **Tiny, auditable supply chain** — stdlib-first; the only external deps are the
  AWS SDK (S3 origin) and `golang.org/x/crypto` (ACME). No CLI frameworks.
- **Fuzzed config parser**, race-tested concurrency, and a `cadish check` that
  surfaces footguns before deploy.

Areas we actively review: cache-key poisoning, request smuggling, SSRF via origin
targets, ReDoS in user-supplied regex matchers, disk-cache path traversal, and
resource exhaustion. Findings and mitigations are tracked in `docs/`.

## Trust-boundary assumptions

### Cluster / peer network must be isolated

When cadish is deployed in **clustered mode** (`cluster { peers … }` block), the
peer read-through (#7) and owner-routing (#8) traffic travels over the **same
public listener port** as client traffic. There is **no mutual authentication**
between peers — no shared secret, no token, no mTLS. The only mechanism that
distinguishes a genuine peer hop from an ordinary client request is the
`X-Cadish-Peer` loop-guard header, which carries the cluster region name.

**Deployment requirement: peer nodes must be network-isolated.** The listener
port of each cadish node must be reachable by the other cadish nodes in the
cluster and by legitimate upstream clients, but **must not** be reachable by
untrusted external parties over the peer path. This is the same hard requirement
as Varnish, HAProxy, and every other clustered cache: the peer/backend network
is a trust domain, not a public endpoint. Enforce it with firewalling, a VPC
security group, or a network policy — whichever is appropriate for your platform.

**What an attacker who can reach a node's port can do without network isolation:**

- **Read cached objects by key** — peer read-through fetches a key from the
  peer's cache over HTTP; anyone reaching the port can issue the same request
  and receive cached content.
- **Poison the regional cache** — because a peer hit is teed into the local
  cache (same contract as an origin fetch), a response from a forged peer can
  inject arbitrary content into the cache of every node that reads through to
  it.

**Mitigations already in place (verified in code):**

- The **security gate runs before cluster routing** (lines 135–196 of
  `internal/server/handler.go`, cluster seam at line 277): an enforced `deny`
  terminates the request before any peer path is consulted. An attacker who
  reaches the port but is blocked by an `ip` ACL is still blocked; the cluster
  path is never reached.
- **Peer targets come only from config** — the `peers` directive in the
  Cadishfile is the sole source of peer URLs; the `X-Cadish-Peer` header
  carries only the region string and cannot redirect traffic. There is no SSRF
  vector through the cluster path.
- **A spoofed `X-Cadish-Peer` header fails safe** — a client that sends
  `X-Cadish-Peer: <region>` causes the node to serve the request locally
  (no owner-routing, no read-through). It lowers the cluster hit rate but
  cannot cause a loop, a redirect, or an SSRF. See the callout in
  [`docs/cadishfile-reference.md`](docs/cadishfile-reference.md#cluster---region-local-peer-cache-clustering).

**`trust_proxy` interaction.** If the peer subnet is also listed in
`trust_proxy`, then any client reachable from that subnet can forge
`X-Forwarded-For` headers and potentially bypass `ip` ACLs or dilute rate
limits. **Do not include the peer/backend subnet in `trust_proxy` unless it
is also a legitimate trusted proxy** (a CDN or LB that forwards the real
client IP). Keep the peer network and the trusted-proxy set disjoint.

**Future hardening.** Mutual peer authentication (mTLS between nodes, or a
shared-secret `Authorization` header on the peer path) is a recognized
improvement but is **not currently implemented**. Until it is, network
isolation is the required control.

### Kubernetes controller RBAC blast radius

When cadish runs as a Kubernetes Ingress controller (`cadish ingress`), its
`ServiceAccount` holds a `ClusterRole` that **by default** grants cluster-wide
`get`/`list`/`watch` on `secrets` and `configmaps` (see
[`deploy/k8s/rbac-controller.yaml`](deploy/k8s/rbac-controller.yaml) and
[`deploy/helm/cadish/templates/controller.yaml`](deploy/helm/cadish/templates/controller.yaml)).
By default the controller's informers watch cluster-wide and filter by namespace
in code; a namespace-scoped `LIST`/`WATCH` would otherwise be denied by the API
server and break the informer cache. Both the cached reads and the granted RBAC
can be **narrowed** — see the mitigations below.

**Blast radius.** A compromised controller pod can read every `Secret` in the
cluster, including TLS private keys for every workload that stores them as
Kubernetes Secrets. This is the **same posture as ingress-nginx and Traefik** —
it is inherent to the role of a TLS-terminating ingress controller, not a
cadish-specific weakness — but it is worth stating explicitly.

**Mitigations already in place (verified in YAML):**

- The RBAC grants only `get`/`list`/`watch` on Secrets — no write access.
- **Write verbs are narrowed when namespaces are restricted.** When
  `controller.namespaces` is set (Helm) or manually configured, the
  `ingresses/status` and `events` write verbs are **dropped from the
  `ClusterRole`** and granted only via per-namespace `Role`/`RoleBinding`s,
  so the controller cannot write status or Events cluster-wide. The static
  manifest documents this split inline.
- Leader election uses a namespaced `Role` (only the `cadish` namespace) for
  the `Lease` resource — not a `ClusterRole`.

**Recommended mitigations:**

- **Don't co-schedule untrusted workloads** with the controller pod. An
  attacker who gains code execution in any pod on the same node can reach
  the controller's service-account token via `/var/run/secrets` or the
  node's kubelet. Isolate the controller onto dedicated nodes or use node
  taints/tolerations.
- **Restrict who can create `Ingress` objects and `Secrets`** in served
  namespaces. The controller's read access is broad; controlling what enters
  the cluster limits what it can be directed to expose.
- **Use namespace restriction** (`-namespace ns1,ns2` / `controller.namespaces`
  Helm value) if you do not need cluster-wide Ingress serving. This narrows
  write scope automatically (via the Helm chart's scoped-writes logic).
- **Label-scope the cached reads (C1).** Set `-secret-label-selector` /
  `-configmap-label-selector` (or `-watch-label-selector` for both), e.g.
  `cadi.sh/managed=true`. The informer list/watch then carries that selector, so
  the controller's cache **only ever contains matching objects** — a compromise
  can read only the Secrets/ConfigMaps you explicitly labelled for cadish, not the
  whole cluster. Off by default; when set you must label your TLS Secrets and
  `cadi.sh/policy` ConfigMaps accordingly.
- **Namespace-scope the granted RBAC (C1).** Core Kubernetes RBAC cannot filter by
  label, so the selector above bounds what is *cached* while the `ClusterRole`
  still *grants* cluster-wide read. For a known set of served namespaces, run with
  `-namespace ns1,ns2` and either set `controller.rbac.scoped=true` (Helm — drops
  the cluster-wide `secrets`/`configmaps` rule and grants them via per-namespace
  `Role`s) or apply
  [`deploy/k8s/rbac-controller-scoped.yaml`](deploy/k8s/rbac-controller-scoped.yaml)
  instead of the default manifest. Combine with the label selector for the tightest
  posture: the selector bounds **which objects** are cached, the per-namespace Roles
  bound **which namespaces** are readable.

For more detail see the [RBAC & least privilege](docs/ingress-controller.md#rbac--least-privilege)
and [Security model](docs/ingress-controller.md#security-model) sections of
the Ingress controller guide.
