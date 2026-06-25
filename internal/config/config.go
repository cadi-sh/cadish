// Package config loads a Cadishfile from disk and turns each site block into a
// runtime *Site that the server can execute: a compiled *pipeline.Pipeline, a
// *cache.Store built from the site's `cache { … }` block, and the site's
// origin.Origin composed from its `upstream`/`origin chain` directives.
//
// It is the bridge between the semantics-free AST (internal/cadishfile), the pure
// evaluation engine (internal/pipeline), the cache store (internal/cache) and the
// origin layer (internal/origin). The server (internal/server) consumes the
// resulting *Config and never touches the raw AST.
//
// Load performs the import splice + env substitution + Compile sequence once, at
// startup, and surfaces every error with its source position (file:line:col) so a
// bad config fails fast and legibly.
package config

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"github.com/cadi-sh/cadish/internal/cache"
	"github.com/cadi-sh/cadish/internal/cadishfile"
	"github.com/cadi-sh/cadish/internal/classify"
	"github.com/cadi-sh/cadish/internal/cluster"
	"github.com/cadi-sh/cadish/internal/geo"
	"github.com/cadi-sh/cadish/internal/k8s"
	"github.com/cadi-sh/cadish/internal/lb"
	"github.com/cadi-sh/cadish/internal/origin"
	"github.com/cadi-sh/cadish/internal/pipeline"
	"github.com/cadi-sh/cadish/internal/tlsacme"
)

// Config is a loaded, ready-to-serve configuration: one runtime Site per site
// block in the Cadishfile, plus any temp directories created for RAM-only caches
// (removed by Close).
type Config struct {
	// Sites are the runtime sites in source order.
	Sites []*Site

	// TLS is the per-site TLS configuration (hostnames + tls directive), in site
	// order, for building the server's tlsacme.Manager. The server decides whether
	// to bind :443 from these.
	TLS []tlsacme.SiteConfig

	// Admin is the parsed `admin { … }` global block, or NIL when no admin block
	// is present (the common case). When set, cadish starts the opt-in
	// observability/dashboard server on its own listener (internal/admin) and
	// threads a metrics seam through the datapath; when nil, none of that exists
	// and the datapath pays nothing. The Cadishfile path is recorded so the admin
	// `cadish check`-style config view can re-read it.
	Admin      *AdminConfig
	ConfigPath string

	// Security is the parsed global `security { … }` block (WAF v1c, D52), or NIL
	// when absent (the common case). It carries cross-cutting security observability
	// for v1 — the audit-log target — which is OFF by default. The native security
	// primitives (allow/deny/rate_limit) are site-level and not gated by this block.
	Security *SecurityConfig

	// StrictHost is the global `strict_host` option: when true the server rejects a
	// request whose Host matches no declared site address with 421 Misdirected
	// Request, instead of the lenient single-site fallback (serve ANY Host from the
	// only configured site). Default false = lenient (backward-compatible). It hardens
	// a single-site deployment against cache-poisoning / Host-confusion by an
	// undeclared Host. The server reads it once at routing-build time.
	StrictHost bool

	// AccessLogOff is the global `access_log off` option: when true the server's
	// in-memory access-log fan-out hub (D44) is disabled, so even an attached
	// `cadish logs` consumer receives nothing and the hot path's only cost is the
	// idle atomic check. Default false = hub on (but idle-free until a consumer
	// attaches). The `-access-log off` run flag is OR'd with this.
	AccessLogOff bool

	// ProxyProtocol is the parsed global `proxy_protocol { … }` block (the opt-in
	// PROXY-protocol listener), or NIL when absent (the common case). When set, the
	// server wraps its inbound listener(s) so each accepted connection's PROXY v1/v2
	// header recovers the real client IP (honored ONLY from a trusted peer). When nil,
	// no wrapper is installed and the accept path is unchanged (zero cost). It can also
	// be supplied by the `-proxy-protocol` + `-proxy-protocol-trust` run flags, which
	// the run command merges into this field before constructing the server.
	ProxyProtocol *ProxyProtocolConfig

	// tempDirs are scratch directories created to back the disk tier of RAM-only
	// caches (the disk tier always needs a directory even when its budget is 0).
	// Close removes them.
	tempDirs []string

	// pools are every lb.Upstream across all sites; Start launches their background
	// health probing + dynamic re-resolution.
	pools []*lb.Upstream

	// clusters are every cluster.Membership across all sites; Start launches their
	// peer health probing + dynamic peer discovery. Empty when no site is clustered.
	clusters []*cluster.Membership

	// k8s is the shared Kubernetes client, built lazily ONLY when a k8s:// upstream
	// target exists (zero-cost otherwise). Its informers start in Start(ctx) and stop
	// in Close. One client serves every k8s:// pool across all sites.
	k8s k8sClient

	// kubeconfig is the optional explicit kubeconfig path (from LoadOptions / the
	// --kubeconfig flag) used when lazily building the k8s client. Empty ⇒ in-cluster
	// then KUBECONFIG then ~/.kube/config.
	kubeconfig string

	// injectedResolver, when non-nil, supplies the k8s:// EndpointResolver instead of
	// building (and owning) a shared k8s.Client. The ingress controller passes Layer
	// 1's already-built client's resolver so the translated config reuses ONE client
	// (no second informer set); the externally-owned client is started/stopped by the
	// controller, so this config's Start/Close never touch it. Tests inject a fake so a
	// k8s:// config compiles offline.
	injectedResolver lb.EndpointResolver
}

// k8sClient is the subset of *k8s.Client that config depends on (lets tests inject
// a fake via k8sClientFactory).
type k8sClient interface {
	Resolver() lb.EndpointResolver
	Start(ctx context.Context) error
	Close()
}

// k8sClientFactory builds the shared K8s client; overridable in tests.
var k8sClientFactory = func(opts k8s.Options) (k8sClient, error) { return k8s.NewClient(opts) }

// ensureK8sResolver builds the shared K8s client on first use (lazy) and returns
// its lb.EndpointResolver. One client serves every k8s:// pool.
func (c *Config) ensureK8sResolver() (lb.EndpointResolver, error) {
	if c.injectedResolver != nil {
		return c.injectedResolver, nil // externally-owned client (ingress controller / tests)
	}
	if c.k8s == nil {
		cl, err := k8sClientFactory(k8s.Options{Kubeconfig: c.kubeconfig})
		if err != nil {
			return nil, fmt.Errorf("kubernetes: %w", err)
		}
		c.k8s = cl
	}
	return c.k8s.Resolver(), nil
}

// siteHasK8sTarget reports whether any upstream/cluster block in site declares a
// k8s:// backend (so the shared client is built only when actually needed).
func siteHasK8sTarget(site *cadishfile.Site) bool {
	for _, n := range site.Body {
		d, ok := n.(*cadishfile.Directive)
		if !ok || (d.Name != "upstream" && d.Name != "cluster") {
			continue
		}
		if directiveHasK8sBackend(d) {
			return true
		}
	}
	return false
}

// directiveHasK8sBackend reports whether an upstream/cluster directive has any
// k8s:// `to` target.
func directiveHasK8sBackend(d *cadishfile.Directive) bool {
	for _, bn := range d.Block {
		bd, ok := bn.(*cadishfile.Directive)
		if !ok || bd.Name != "to" {
			continue
		}
		for _, a := range bd.Args {
			if t, err := lb.ParseTarget(a.Raw, bd.Pos); err == nil && t.Scheme == lb.SchemeK8s {
				return true
			}
		}
	}
	return false
}

// Site is one runtime site: its host addresses, compiled pipeline, cache store and
// origin. It is immutable after Load and safe for concurrent use by the server.
type Site struct {
	// Addresses are the site header tokens (e.g. "example.com", "*.cdn.example.com"),
	// used for Host-based site selection.
	Addresses []string

	// Name is a short identifier for logs (the first address).
	Name string

	// Pipeline is the compiled request-evaluation engine for this site.
	Pipeline *pipeline.Pipeline

	// Store is the two-tier cache for this site.
	Store *cache.Store

	// Origin is the default upstream origin (a single httporigin/s3origin, or a
	// chain when `origin chain …` is configured). Used when no `route` matched or
	// the routed upstream is unknown.
	Origin origin.Origin

	// Origins maps each declared upstream name to its origin, so a `route @m ->
	// NAME` decision can select the matching backend. A chain's member upstreams
	// also appear here.
	Origins map[string]origin.Origin

	// DefaultUpstreamName is the name of the default origin's upstream ("" when the
	// default is an `origin chain`). The server resolves a request's effective
	// upstream name as routedUpstream-or-DefaultUpstreamName to look up its sticky
	// spec for the lb routing-key seam.
	DefaultUpstreamName string

	// StickySpecs maps a sticky upstream's name to the spec telling the server how
	// to derive the {sticky} routing key (which cookie / client_ip fallback) to
	// attach via lb.WithRoutingKey before Fetch.
	StickySpecs map[string]*lb.StickySpec

	// Device is the site's User-Agent → device-class classifier for the {device}
	// cache-key normalizer (built from `device_detect { … }`, or the built-in
	// default ruleset when absent). Never nil. The server consults it (gated by
	// Pipeline.UsesDeviceToken) to set Request.Device before EvalRequest.
	Device *classify.Classifier

	// Geo is the site's client-IP/header → country-class source for the {geo}
	// cache-key normalizer (built from `geo { … }`). It is NIL when the site
	// configures no geo source — the geo tokens then render "". The server consults
	// it (gated by Pipeline.UsesGeoToken) to set Request.Geo before EvalRequest, and
	// derives Request.GeoContinent from the country via an in-tree table.
	Geo geo.Source

	// GeoRegion is the site's upstream region/subdivision-header source for the
	// {geo.region} token / `geo region …` matcher (from `geo { region_header NAME }`).
	// It is NIL when no region_header is configured — {geo.region} then renders "".
	// Region needs an upstream geo header because a US state can't come from a raw IP
	// without a GeoIP DB (D11: no bundled GeoIP database). Set into Request.GeoRegion
	// in the same gated geo pre-pass.
	GeoRegion geo.Source

	// TrustedProxies are the CIDRs whose X-Forwarded-For is trusted when resolving
	// the real client IP. It is the SINGLE SOURCE OF TRUTH for trusted-proxy
	// resolution, read by BOTH {geo} (the geo pre-pass) and the security gate's `ip`
	// ACL. It is the UNION of the standalone site-level `trust_proxy …` directive and
	// the `geo { trust_proxy … }` block, so a pure-security site (an `ip` ACL with no
	// geo block) can still declare its proxies.
	TrustedProxies []netip.Prefix

	// geoDBs are the memory-mapped MaxMind readers opened for this site's
	// `geo { source maxmind … }` line(s) (D56). They are owned by the site for
	// lifecycle: closed on config teardown (CloseExcept) and reloaded on SIGHUP via the
	// whole-config reload (each reload opens fresh readers; the old ones are closed when
	// the old config is torn down). Nil when the site uses no maxmind source.
	geoDBs []*geo.MaxMindDB

	// Cluster is the region-local peer-cache membership built from a `cluster { … }`
	// block, or NIL when the site declares no cluster (the zero-cost default: a
	// non-clustered cadish behaves exactly as before). When non-nil it drives peer
	// read-through (#7) and ownership routing (#8); the server consults it in one
	// well-named seam (clusterRoute) and the read-through PeerOrigin is already
	// composed before the real origin in this site's Origin chain.
	Cluster *cluster.Membership
}

// LoadOptions tunes Load behavior with knobs that come from run-time flags rather
// than the Cadishfile itself.
type LoadOptions struct {
	// Kubeconfig is the explicit kubeconfig path used to resolve k8s:// upstreams
	// out-of-cluster (the --kubeconfig flag). Empty ⇒ in-cluster, then KUBECONFIG,
	// then ~/.kube/config. It is only consulted when the config has a k8s:// target.
	Kubeconfig string

	// EndpointResolver, when non-nil, supplies the k8s:// EndpointResolver directly
	// instead of building a shared k8s.Client. The ingress controller passes Layer 1's
	// already-built client's resolver (so the translated config reuses one client);
	// tests inject a fake so a k8s:// config compiles offline. When set, this config's
	// Start/Close do NOT manage the resolver's client — its owner does.
	EndpointResolver lb.EndpointResolver

	// AllowNoSites permits a config that defines ZERO sites. The ingress controller uses
	// it: its base Cadishfile holds only globals (sites come from Ingress objects), and a
	// reconcile with no matched Ingresses renders a site-less config that must still load
	// (the server then serves nothing until Ingresses appear). For a normal `cadish run`
	// it stays false, so a site-less Cadishfile is the usual fail-fast error.
	AllowNoSites bool
}

// Load reads, validates and compiles the Cadishfile at path. Every error carries a
// source position where possible. The returned *Config owns cache stores that the
// caller MUST Close (via Config.Close) at shutdown. It is LoadWithOptions with the
// zero options (in-cluster/KUBECONFIG/~/.kube/config for any k8s:// target).
func Load(path string) (*Config, error) {
	return LoadWithOptions(path, LoadOptions{})
}

// LoadWithOptions is Load with explicit run-time options (e.g. the --kubeconfig path
// for out-of-cluster k8s:// resolution).
func LoadWithOptions(path string, opts LoadOptions) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Imports and geo file references in a disk Cadishfile resolve relative to the
	// Cadishfile's own directory.
	return loadFromSource(path, string(data), filepath.Dir(path), opts)
}

// LoadString compiles a Cadishfile held in memory (no file read), through the exact
// same parse + env-substitute + compile path as Load. name is used for file:line
// diagnostics (e.g. "<ingress>"). It is the seam the ingress controller renders into:
// the translator emits Cadishfile text and LoadString turns it into a ready *Config.
// Imports/geo file references resolve relative to the process working directory.
func LoadString(name, src string) (*Config, error) {
	return LoadStringWithOptions(name, src, LoadOptions{})
}

// LoadStringWithOptions is LoadString with explicit run-time options (e.g. the
// --kubeconfig path so a generated k8s:// upstream resolves out-of-cluster).
func LoadStringWithOptions(name, src string, opts LoadOptions) (*Config, error) {
	return loadFromSource(name, src, ".", opts)
}

// loadFromSource is the shared compile path behind Load (read file → here) and
// LoadString (in-memory → here). name is the diagnostic source name; baseDir is the
// directory imports/geo file paths resolve against; opts carries run-time knobs.
func loadFromSource(name, src, baseDir string, opts LoadOptions) (*Config, error) {
	file, err := cadishfile.Parse(name, []byte(src))
	if err != nil {
		return nil, err
	}
	// Resolve {$ENV} placeholders against the process environment before compiling.
	cadishfile.SubstituteEnv(file, os.LookupEnv)

	// Parse the optional `admin { … }` global block (the opt-in dashboard surface).
	admin, err := adminFromFile(file)
	if err != nil {
		return nil, err
	}

	// Parse the optional global `access_log off` option (D44): disable the in-memory
	// access-log fan-out hub entirely.
	accessLogOff, err := accessLogOffFromFile(file)
	if err != nil {
		return nil, err
	}

	// Parse the optional global `strict_host` option: reject an undeclared Host with
	// 421 instead of the lenient single-site fallback. OFF by default (lenient).
	strictHost, err := strictHostFromFile(file)
	if err != nil {
		return nil, err
	}

	// Parse the optional global `security { … }` block (WAF v1c, D52): the audit-log
	// target (OFF by default — zero cost when absent).
	security, err := securityFromFile(file)
	if err != nil {
		return nil, err
	}

	// Parse the optional global `proxy_protocol { trust … }` block: the opt-in
	// PROXY-protocol listener. OFF by default (nil) — zero cost when absent.
	proxyProto, err := proxyProtocolFromFile(file)
	if err != nil {
		return nil, err
	}

	// Expand any `group { … }` site-groups into one site per tenant (V2d).
	sites, err := cadishfile.ExpandGroups(file.Sites)
	if err != nil {
		return nil, err
	}

	cfg := &Config{Admin: admin, Security: security, AccessLogOff: accessLogOff, StrictHost: strictHost, ProxyProtocol: proxyProto, ConfigPath: name, kubeconfig: opts.Kubeconfig, injectedResolver: opts.EndpointResolver}
	for _, site := range sites {
		rs, tlsCfg, err := cfg.buildSite(site, baseDir)
		if err != nil {
			cfg.Close() // tear down any stores already opened
			return nil, err
		}
		cfg.Sites = append(cfg.Sites, rs)
		cfg.TLS = append(cfg.TLS, tlsCfg)
	}
	if len(cfg.Sites) == 0 && !opts.AllowNoSites {
		return nil, fmt.Errorf("%s: config defines no sites", name)
	}
	return cfg, nil
}

// buildSite turns one AST site into a runtime Site, returning the site plus its
// TLS configuration (for the server's tlsacme.Manager).
func (c *Config) buildSite(site *cadishfile.Site, baseDir string) (*Site, tlsacme.SiteConfig, error) {
	// Splice imports BEFORE compiling (a leftover import is a compile error).
	spliced, err := pipeline.SpliceImports(site, pipeline.FileImportResolver(baseDir))
	if err != nil {
		return nil, tlsacme.SiteConfig{}, err
	}
	p, err := pipeline.Compile(spliced)
	if err != nil {
		return nil, tlsacme.SiteConfig{}, err
	}

	store, err := c.buildStore(spliced)
	if err != nil {
		return nil, tlsacme.SiteConfig{}, err
	}

	// Build the shared K8s endpoint resolver lazily, only if this site declares a
	// k8s:// backend. One client is shared across all sites (zero cost when absent).
	var epRes lb.EndpointResolver
	if siteHasK8sTarget(spliced) {
		r, err := c.ensureK8sResolver()
		if err != nil {
			_ = store.Close()
			return nil, tlsacme.SiteConfig{}, err
		}
		epRes = r
	}

	so, err := buildOrigins(spliced, epRes)
	if err != nil {
		_ = store.Close()
		return nil, tlsacme.SiteConfig{}, err
	}
	c.pools = append(c.pools, so.pools...)

	// Cluster membership (#7/#8): build the peer-cache layer when the site declares
	// a `cluster { peers … }` block. When present in read-through or owner mode it
	// composes the peer read-through origin BEFORE the site's default origin, so a
	// local miss tries the owning peer before origin. NIL membership (no block) is
	// the zero-cost default.
	membership, defOrigin, err := buildCluster(spliced, so.def)
	if err != nil {
		_ = store.Close()
		return nil, tlsacme.SiteConfig{}, err
	}
	so.def = defOrigin
	if membership != nil {
		c.clusters = append(c.clusters, membership)
	}

	// The device classifier is compiled ONCE by the pipeline (single source of truth,
	// so the Go server and the edge worker — which projects the same ruleset, D70 —
	// classify a User-Agent identically). Read it back here for the server pre-pass.
	classifier := p.DeviceClassifier()

	geoSrc, geoRegionSrc, geoTrusted, geoDBs, err := buildGeo(spliced, baseDir, true)
	if err != nil {
		_ = store.Close()
		return nil, tlsacme.SiteConfig{}, err
	}
	// Standalone site-level `trust_proxy …` (independent of any geo block) UNIONs with
	// the geo block's trust_proxy. This decouples the trusted-proxy set from geo so a
	// pure-security deployment (an `ip` ACL with no geo block) still resolves the REAL
	// client behind a CDN/LB instead of silently ACLing the proxy. Single source of
	// truth downstream: both {geo} and the `ip` gate read Site.TrustedProxies.
	siteTrusted, err := buildSiteTrustProxies(spliced)
	if err != nil {
		_ = store.Close()
		return nil, tlsacme.SiteConfig{}, err
	}
	trustedProxies := unionPrefixes(geoTrusted, siteTrusted)

	// TLS config from the site's `tls` directive (soft warnings are ignored here;
	// `cadish check` surfaces them).
	tlsCfg, _ := tlsacme.SiteConfigFromSite(spliced)

	name := ""
	if len(spliced.Addresses) > 0 {
		name = spliced.Addresses[0]
	}
	return &Site{
		Addresses:           spliced.Addresses,
		Name:                name,
		Pipeline:            p,
		Store:               store,
		Origin:              so.def,
		Origins:             so.origins,
		DefaultUpstreamName: so.defName,
		StickySpecs:         so.sticky,
		Device:              classifier,
		Geo:                 geoSrc,
		GeoRegion:           geoRegionSrc,
		geoDBs:              geoDBs,
		TrustedProxies:      trustedProxies,
		Cluster:             membership,
	}, tlsCfg, nil
}

// Start launches background workers for every lb.Upstream (active health probing
// and dynamic DNS re-resolution). They run until ctx is cancelled. Idempotent per
// pool. Safe to call on a config with no lb pools (a no-op).
//
// When a k8s:// target exists it FIRST starts the shared K8s client and blocks on
// its informer cache sync, returning that error (fail-fast: a config that can't
// reach the API or lacks RBAC must not start serving with empty k8s pools). Pools
// and clusters only start after the client is healthy.
func (c *Config) Start(ctx context.Context) error {
	if err := c.StartShared(ctx); err != nil {
		return err
	}
	for _, p := range c.pools {
		p.Start(ctx)
	}
	return nil
}

// StartShared starts the config's NON-pool background workers: the shared K8s client
// (blocking on its informer cache sync, fail-fast) and every cluster membership. It
// is the part of Start that is NOT diffed across a reload — pools are started
// separately, per-pool, by the server so steady upstreams survive a reload (see
// TransplantPoolsFrom). K8s is started before clusters; clusters never error.
//
// Start = StartShared + start every pool under ctx; the server uses StartShared plus
// per-pool contexts instead, so a transplanted pool keeps running when the config
// that originally started it is torn down.
func (c *Config) StartShared(ctx context.Context) error {
	if c.k8s != nil {
		if err := c.k8s.Start(ctx); err != nil {
			return err
		}
	}
	for _, m := range c.clusters {
		m.Start(ctx)
	}
	return nil
}

// Pools returns every lb.Upstream load-balancer pool across all sites, for
// observability (the admin dashboard reads each pool's HealthSnapshot). The slice
// is the live backing slice; callers must treat it as read-only.
func (c *Config) Pools() []*lb.Upstream { return c.pools }

// TotalRAMCacheBytes is the sum of every site's configured RAM-tier cache budget.
// It is the dominant component of cadish's live heap, so the run path uses it to size
// the GOMEMLIMIT soft limit (D45). Sites without a store contribute nothing. The sum
// saturates at math.MaxInt64 rather than overflowing.
func (c *Config) TotalRAMCacheBytes() int64 {
	var total int64
	for _, s := range c.Sites {
		if s.Store == nil {
			continue
		}
		b := s.Store.Stats().RAMMaxBytes
		if b <= 0 {
			continue
		}
		if total > math.MaxInt64-b {
			return math.MaxInt64
		}
		total += b
	}
	return total
}

// primaryHost is a site's stable identity for matching across a reload: the
// lower-cased, trimmed first address token. Old and new configs run through the
// same function, so the match is consistent (site tokens are hostnames/wildcards,
// not host:port, so no port stripping is needed here).
func primaryHost(s *Site) string {
	if len(s.Addresses) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(s.Addresses[0]))
}

// TransplantStoresFrom moves the WARM cache store from each of old's sites onto the
// matching site in c (matched by primary host), for zero-downtime reload: c is the
// freshly loaded config and old is the one currently serving. For every carried-over
// site, the cold store config.Load just opened for c is closed and its scratch temp
// dir (if any) removed, and old's warm store + freshness keep serving through
// the handler swap. Sites only in old (removed) or only in c (added) are untouched.
//
// It mutates c.Sites' Store fields and c.tempDirs (dropping orphaned scratch dirs).
// Call it BEFORE the handler routing swap so the new routing points at warm stores.
func (c *Config) TransplantStoresFrom(old *Config) {
	oldByHost := make(map[string]*Site, len(old.Sites))
	for _, s := range old.Sites {
		oldByHost[primaryHost(s)] = s
	}
	orphanedDirs := map[string]bool{}
	for _, s := range c.Sites {
		prev := oldByHost[primaryHost(s)]
		if prev == nil || prev.Store == nil || s.Store == nil || prev.Store == s.Store {
			continue
		}
		cold := s.Store
		s.Store = prev.Store // serve from the warm store; preserve the hit ratio
		if d := cold.DiskDir(); d != "" {
			orphanedDirs[d] = true
		}
		_ = cold.Close()
	}
	if len(orphanedDirs) == 0 {
		return
	}
	kept := c.tempDirs[:0]
	for _, d := range c.tempDirs {
		if orphanedDirs[d] {
			_ = os.RemoveAll(d) // scratch dir for a discarded cold store
			continue
		}
		kept = append(kept, d)
	}
	c.tempDirs = kept
}

// TransplantPoolsFrom moves UNCHANGED lb pools from old onto c (the freshly loaded
// config), so a reload does not re-probe steady backends. A pool in c is "unchanged"
// iff old has a pool with the SAME name AND the SAME content fingerprint
// (lb.Upstream.Fingerprint — name, target set, policy/shard/replicas, health,
// host-header, max_conns, timeouts). For every such survivor the live old
// *lb.Upstream instance — with its warm health FSM, ejection windows, inflight
// accounting, consistent-hash ring and already-running goroutines — replaces the
// cold instance config.Load just built, BOTH in c.pools and everywhere the origin
// graph references it (each site's Origins map and default Origin, descending into
// origin chains). Genuinely-new pools (new name, or same name with a changed
// fingerprint) are left in c.pools as the cold instances the server then Starts.
//
// It mutates ONLY c (it reads old purely to match): the survivor instances are
// shared between old and c during the swap window, which is safe because an
// *lb.Upstream is concurrency-safe and the server never cancels a survivor's
// goroutines (only genuinely-removed pools are stopped, after the swap). Call it
// BEFORE starting c's pools so the server starts only the added ones.
func (c *Config) TransplantPoolsFrom(old *Config) {
	if len(old.pools) == 0 || len(c.pools) == 0 {
		return
	}
	oldByName := make(map[string]*lb.Upstream, len(old.pools))
	for _, p := range old.pools {
		oldByName[p.Name()] = p
	}
	// A CONFIG-OWNED k8s client (old.k8s != nil) is closed when the old config is torn
	// down after the swap. A transplanted k8s:// pool keeps the OLD lb.Upstream, whose
	// EndpointResolver is wired to that dying client — once its informer stops, endpoint
	// resolution silently freezes (routes to dead pods, never learns new ones), and
	// meanwhile next's freshly-started client is left unreferenced. So when old owns its
	// client we do NOT transplant k8s:// pools: they are rebuilt to bind next's live,
	// started client. (When the resolver is INJECTED/shared — old.k8s == nil, the Ingress
	// controller path — the client is long-lived, so transplanting is safe and preserves
	// the no-reprobe benefit. DNS/static pools never use the shared client and always
	// transplant.)
	rebuildK8sPools := old.k8s != nil
	// repl maps a cold NEW pool (as an origin.Origin) to the warm OLD survivor it is
	// replaced by, for rewriting the origin graph.
	repl := make(map[origin.Origin]origin.Origin)
	newPools := make([]*lb.Upstream, 0, len(c.pools))
	for _, np := range c.pools {
		op := oldByName[np.Name()]
		if op == nil || op.Fingerprint() != np.Fingerprint() {
			newPools = append(newPools, np) // genuinely new/changed — server will Start it
			continue
		}
		if rebuildK8sPools && np.HasK8sBackend() {
			newPools = append(newPools, np) // rebuild so it binds next's live k8s client
			continue
		}
		repl[np] = op
		newPools = append(newPools, op) // transplant the live instance
	}
	c.pools = newPools
	if len(repl) == 0 {
		return
	}
	for _, s := range c.Sites {
		for name, o := range s.Origins {
			s.Origins[name] = rewriteOrigin(o, repl)
		}
		s.Origin = rewriteOrigin(s.Origin, repl)
	}
}

// rewriteOrigin returns the replacement for o if it is a transplanted survivor,
// otherwise descends into any composite origin (an origin chain) to rewrite its
// members, then returns o unchanged. Only *lb.Upstream leaves appear as keys in repl;
// s3/cfsign/httporigin leaves are pass-through.
func rewriteOrigin(o origin.Origin, repl map[origin.Origin]origin.Origin) origin.Origin {
	if r, ok := repl[o]; ok {
		return r
	}
	if rw, ok := o.(interface {
		ReplaceOrigins(func(origin.Origin) origin.Origin)
	}); ok {
		rw.ReplaceOrigins(func(member origin.Origin) origin.Origin {
			return rewriteOrigin(member, repl)
		})
	}
	return o
}

// Close releases every site's cache store and removes temp directories. Safe to
// call once; errors are joined into the first non-nil.
func (c *Config) Close() error {
	return c.CloseExcept(nil)
}

// CloseExcept releases this config's cache stores and temp directories, SKIPPING any
// store present in keep. It exists for zero-downtime reload: when a site survives a
// reload its warm cache.Store is transplanted onto the new config, so the old config
// must be torn down WITHOUT closing that preserved store (closing it would cold the
// cache, defeating the reload). A store that was transplanted out is in keep and is
// left open; its temp dir (if any) is likewise still in use, so removal of temp dirs
// is governed by the same keep set (a temp dir whose store is preserved is kept).
//
// keep may be nil (close everything — the plain shutdown path). Errors are joined
// into the first non-nil.
func (c *Config) CloseExcept(keep map[*cache.Store]bool) error {
	if c.k8s != nil {
		c.k8s.Close()
	}
	var firstErr error
	preservedDir := map[string]bool{}
	for _, s := range c.Sites {
		// Close this site's MaxMind readers (D56). They are never transplanted across a
		// reload (each reload opens fresh readers), so the old config's readers are always
		// released here, independent of the cache-store keep set.
		for _, db := range s.geoDBs {
			if err := db.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if s.Store == nil {
			continue
		}
		if keep[s.Store] {
			if d := s.Store.DiskDir(); d != "" {
				preservedDir[d] = true
			}
			continue // preserved by the new config; do NOT close
		}
		if err := s.Store.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, d := range c.tempDirs {
		if preservedDir[d] {
			continue // backing a preserved store; leave it on disk
		}
		_ = os.RemoveAll(d)
	}
	return firstErr
}
