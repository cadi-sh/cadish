package lb

import (
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/cadi-sh/cadish/internal/cadishfile"
)

// Policy is a backend-selection strategy.
type Policy int

const (
	// RoundRobin rotates evenly over the healthy backends (the default).
	RoundRobin Policy = iota
	// LeastConn picks the healthy backend with the fewest in-flight requests.
	LeastConn
	// Sticky pins a routing key (cookie value / client IP, supplied by the
	// caller via WithRoutingKey) to one backend via a consistent-hash ring; if
	// that backend is unhealthy the key rehashes to the next healthy backend.
	Sticky
	// Shard consistent-hashes the shard key (the request URL for ShardURL, or
	// the routing key for ShardKey) so a key maps to one backend — the
	// peer-cache-sharding case.
	Shard
)

// String renders the policy keyword.
func (p Policy) String() string {
	switch p {
	case RoundRobin:
		return "round_robin"
	case LeastConn:
		return "least_conn"
	case Sticky:
		return "sticky"
	case Shard:
		return "shard"
	default:
		return "unknown"
	}
}

// ShardKey selects what Shard policy hashes.
type ShardKey int

const (
	// ShardNone means no shard key was configured (not a Shard policy).
	ShardNone ShardKey = iota
	// ShardURL hashes the request Key (the URL path) — `shard_by url`.
	ShardURL
	// ShardKeyVal hashes the caller-supplied routing key — `shard_by key`.
	ShardKeyVal
)

// String renders the shard key keyword.
func (s ShardKey) String() string {
	switch s {
	case ShardURL:
		return "url"
	case ShardKeyVal:
		return "key"
	default:
		return "none"
	}
}

// TargetScheme classifies a backend target by how its endpoints are discovered.
type TargetScheme int

const (
	// SchemeStatic is an http://host:port / https://host:port target: a single
	// endpoint whose DNS is resolved by the HTTP client per request.
	SchemeStatic TargetScheme = iota
	// SchemeDNS is a dns://host:port target: the host is re-resolved (A/AAAA)
	// periodically and each address becomes an endpoint.
	SchemeDNS
	// SchemeK8s is a k8s://service.namespace:port target: resolved against the
	// Kubernetes API (EndpointSlices) to the live ready pod IP:port set, over which
	// the pool runs its own LB. Resolution is supplied by an injected
	// EndpointResolver (internal/k8s); absent one, the pool has no endpoints.
	SchemeK8s
)

// String renders the scheme keyword.
func (s TargetScheme) String() string {
	switch s {
	case SchemeStatic:
		return "static"
	case SchemeDNS:
		return "dns"
	case SchemeK8s:
		return "k8s"
	default:
		return "unknown"
	}
}

// dynamic reports whether the target's endpoints are discovered by periodic
// re-resolution (dns/k8s) rather than being a fixed address (static).
func (s TargetScheme) dynamic() bool { return s == SchemeDNS || s == SchemeK8s }

// Target is one `to` backend address. A static target is a single endpoint; a
// dns/k8s target expands into one endpoint per resolved address.
type Target struct {
	// Raw is the original token, e.g. "http://h:80", "dns://svc:8080".
	Raw string
	// Scheme is how endpoints are discovered.
	Scheme TargetScheme
	// ConnScheme is the wire scheme used to reach an endpoint ("http"/"https").
	// For static targets it is the URL's scheme; for dns/k8s it defaults to
	// "http".
	ConnScheme string
	// Host is the hostname (static: the URL host; dns/k8s: the name to resolve).
	Host string
	// Port is the port string (may be empty for static, where the URL governs).
	Port string
	// Path is an optional base path for static targets (preserved and prefixed
	// onto request keys by httporigin).
	Path string
	// Service and Namespace are the parsed parts of a k8s:// target's
	// `service.namespace` host (populated only when Scheme == SchemeK8s). Meaning
	// lives here in lb, not in the semantics-free cadishfile AST.
	Service   string
	Namespace string
	Pos       cadishfile.Pos
}

// StickySpec records how the SERVER should derive the routing key for a Sticky
// upstream. The lb package does not read cookies or client IPs itself — the key
// arrives via WithRoutingKey — but parsing and exposing the spec lets the server
// (and `cadish check`) know what to compute for `{sticky}`.
type StickySpec struct {
	// Source is "cookie" or "client_ip".
	Source string
	// Cookie is the cookie name when Source == "cookie".
	Cookie string
	// Fallback is the else-source ("client_ip" or "cookie"); empty if none.
	Fallback string
	// FallbackCookie is the cookie name when Fallback == "cookie".
	FallbackCookie string
}

// HealthSpec configures the active health prober:
// `health METHOD PATH expect CODE… interval D window N threshold T`.
//
// `expect` accepts one or more acceptances: an exact status (`expect 301`), a
// list (`expect 200 301`), or a class form (`expect 2xx`, `expect 2xx 3xx`). A
// probe counts as a success when the response status matches ANY acceptance.
type HealthSpec struct {
	Method string // GET, HEAD, …
	Path   string // request path, e.g. "/"
	// ExpectCode is the single accepted status for the single-int back-compat
	// form (`expect 301`); 0 when the list/class form is used. Kept for callers
	// and the config fingerprint; Matches is the source of truth.
	ExpectCode int
	// ExpectCodes are exact accepted statuses (`expect 200 301`).
	ExpectCodes []int
	// ExpectClasses are accepted status classes by leading digit (e.g. 2 for 2xx,
	// 3 for 3xx) from the class form (`expect 2xx 3xx`).
	ExpectClasses []int
	Interval      time.Duration // time between probes
	Window        int           // sliding window size (probes considered)
	Threshold     int           // successes→up / failures→down within the window
}

// Matches reports whether an HTTP status code counts as a healthy probe under
// this spec: it matches the single back-compat code, any listed exact code, or
// any accepted status class (2xx/3xx/…).
func (h *HealthSpec) Matches(code int) bool {
	if h.ExpectCode != 0 && code == h.ExpectCode {
		return true
	}
	for _, c := range h.ExpectCodes {
		if code == c {
			return true
		}
	}
	for _, cls := range h.ExpectClasses {
		if code/100 == cls {
			return true
		}
	}
	return false
}

// hasExpect reports whether any acceptance was configured (used by the parser to
// enforce that `expect` is present).
func (h *HealthSpec) hasExpect() bool {
	return h.ExpectCode != 0 || len(h.ExpectCodes) > 0 || len(h.ExpectClasses) > 0
}

// Timeouts are per-backend transport timeouts.
type Timeouts struct {
	// Connect bounds dial+TLS establishment.
	Connect time.Duration
	// FirstByte bounds the wait for response headers after the request is sent.
	FirstByte time.Duration
	// BetweenBytes is the body-stall budget: the maximum gap between
	// progress-making reads of the origin response body. It IS enforced — the
	// server stamps it onto the Response and the idle-timeout reader aborts a
	// stream that stalls longer than this (taking the stricter of this and the
	// global -idle-timeout). See internal/server handler.go / idlereader.go.
	BetweenBytes time.Duration
}

// Config is a plain, fully-described upstream pool. Build it with ParseUpstream
// / ParseCluster from a Cadishfile directive, or by hand in tests.
type Config struct {
	// Name is the upstream/cluster name (the directive's first arg).
	Name string
	// Kind is "upstream" or "cluster" (informational).
	Kind string
	// Backends are the `to` targets, in source order. At least one is required.
	Backends []Target
	// Policy is the balancing policy (default RoundRobin).
	Policy Policy
	// Sticky is the sticky spec (non-nil only for Policy == Sticky).
	Sticky *StickySpec
	// Shard selects what Shard policy hashes (ShardNone unless Policy == Shard).
	Shard ShardKey
	// Health is the active-probe spec; nil disables active health checking (all
	// backends are then always eligible).
	Health *HealthSpec
	// Timeouts are per-backend transport timeouts (zero ⇒ library defaults).
	Timeouts Timeouts
	// HostHeader is the upstream Host-header policy applied to every backend's
	// httporigin (backlog #11). The zero value is httporigin.HostPreserve (forward
	// the client Host) — the default. The config layer fills it from the
	// `host_header` directive; the default origin factory passes it to
	// httporigin.WithHostPolicy.
	HostHeader HostHeaderPolicy
	// SNI is the TLS ClientHello server name advertised to every HTTPS backend's
	// httporigin (gap H6, `sni <server-name>`). Empty ⇒ Go's default (the dialed
	// host) — the zero value leaves the datapath unchanged. The config layer fills
	// it from the `sni` directive; the default origin factory passes it to
	// httporigin.WithSNI.
	SNI string
	// DisableReuse disables backend connection reuse for every backend's httporigin
	// (gap H6, `http_reuse never`). False ⇒ keep-alive on (the default, datapath
	// unchanged). The config layer fills it from `http_reuse never`; the default
	// origin factory passes it to httporigin.WithDisableKeepAlives.
	DisableReuse bool
	// MaxConns caps concurrent in-flight requests per backend (0 = unlimited).
	MaxConns int
	// Replicas is the consistent-hash virtual-node count per backend (0 ⇒
	// defaultReplicas). Exposed mainly for tests.
	Replicas int
	// Pos is the directive's source position.
	Pos cadishfile.Pos
}

// Validate checks a Config for internal consistency, returning a positioned
// error on the first problem. New calls it; ParseUpstream/ParseCluster produce
// already-valid configs.
func (c *Config) Validate() error {
	if len(c.Backends) == 0 {
		return posErrf(c.Pos, "upstream %q: no backends (need at least one `to`)", c.Name)
	}
	switch c.Policy {
	case Shard:
		if c.Shard == ShardNone {
			return posErrf(c.Pos, "upstream %q: shard policy requires `shard_by url|key`", c.Name)
		}
	case Sticky:
		// A sticky upstream with no sticky spec is allowed (the caller may still
		// pass a routing key); we only validate the spec when present.
	}
	if c.Health != nil {
		h := c.Health
		if h.Window <= 0 || h.Threshold <= 0 || h.Threshold > h.Window {
			return posErrf(c.Pos, "upstream %q: health window/threshold invalid (need 0 < threshold <= window)", c.Name)
		}
		if h.Interval <= 0 {
			return posErrf(c.Pos, "upstream %q: health interval must be > 0", c.Name)
		}
	}
	for _, b := range c.Backends {
		if b.Host == "" {
			return posErrf(b.Pos, "upstream %q: backend %q has no host", c.Name, b.Raw)
		}
	}
	return nil
}

// parseTarget turns a `to` token into a Target. Recognized schemes: http,
// https (static), dns, k8s (dynamic). A bare host:port (no scheme) is treated as
// http static.
func parseTarget(tok string, pos cadishfile.Pos) (Target, error) {
	raw := strings.TrimSpace(tok)
	if raw == "" {
		return Target{}, posErrf(pos, "empty backend target")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	scheme, host, port, path, err := parseTargetURL(raw)
	if err != nil {
		return Target{}, posErrf(pos, "bad backend target %q: %v", tok, err)
	}
	t := Target{Raw: tok, Host: host, Port: port, Path: path, Pos: pos}
	// SSRF defense-in-depth (general): reject a link-local / cloud-metadata host
	// LITERAL (169.254.0.0/16 — incl. the 169.254.169.254 cloud IMDS — and IPv6
	// fe80::/10). A `to` target must never be able to reach the instance metadata
	// service. RFC1918 / private ranges are deliberately NOT blocked: k8s pod IPs and
	// private origins are legitimate backends.
	if isLinkLocalLiteral(host) {
		return Target{}, posErrf(pos, "backend target %q resolves to a link-local/cloud-metadata address (blocked)", tok)
	}
	switch scheme {
	case "http", "https":
		t.Scheme = SchemeStatic
		t.ConnScheme = scheme
		// For static targets the Raw URL (with scheme) is used as the httporigin
		// base directly; normalize Raw to include the synthesized scheme. http/https
		// always have numeric ports, so the canonical url.Parse succeeds here.
		if u, perr := url.Parse(raw); perr == nil {
			t.Raw = u.String()
		}
	case "dns":
		t.Scheme = SchemeDNS
		t.ConnScheme = "http"
	case "k8s":
		t.Scheme = SchemeK8s
		t.ConnScheme = "http"
		svc, ns, ok := splitServiceNamespace(t.Host)
		if !ok {
			return Target{}, posErrf(pos, "k8s target %q must be service.namespace:port "+
				"(namespace is mandatory and must be a single label)", tok)
		}
		t.Service, t.Namespace = svc, ns
	default:
		return Target{}, posErrf(pos, "unsupported backend scheme %q (want http, https, dns, or k8s)", scheme)
	}
	if t.Host == "" {
		return Target{}, posErrf(pos, "backend target %q has no host", tok)
	}
	if t.Scheme.dynamic() && t.Port == "" {
		return Target{}, posErrf(pos, "dynamic target %q must include a port (e.g. %s://%s:8080)", tok, scheme, t.Host)
	}
	return t, nil
}

// parseTargetURL extracts scheme, host, port, and path from a target token. It
// first tries url.Parse (the canonical path) and falls back to a manual split for
// the one case url.Parse rejects but cadish allows: a non-numeric (named) port on
// a dynamic target, e.g. k8s://web.prod:http.
func parseTargetURL(raw string) (scheme, host, port, path string, err error) {
	if u, perr := url.Parse(raw); perr == nil {
		return u.Scheme, u.Hostname(), u.Port(), u.Path, nil
	} else {
		err = perr
	}
	i := strings.Index(raw, "://")
	if i < 0 {
		return "", "", "", "", err
	}
	scheme = raw[:i]
	rest := raw[i+3:]
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		path = rest[j:]
		rest = rest[:j]
	}
	host = rest
	if k := strings.LastIndexByte(rest, ':'); k >= 0 {
		host, port = rest[:k], rest[k+1:]
	}
	if host == "" || port == "" {
		return "", "", "", "", err
	}
	return scheme, host, port, path, nil
}

// isLinkLocalLiteral reports whether host is an IP LITERAL in the IPv4 link-local
// range 169.254.0.0/16 (which includes the 169.254.169.254 cloud metadata endpoint) or
// the IPv6 link-local range fe80::/10. Only literals are matched — a hostname that
// merely resolves to such an address is out of scope here (DNS resolution is not done at
// parse time). This is an SSRF guard, not a private-range block: RFC1918 is allowed.
func isLinkLocalLiteral(host string) bool {
	ip := net.ParseIP(strings.Trim(host, "[]"))
	if ip == nil {
		return false
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

// splitServiceNamespace splits a k8s:// host of the form "service.namespace" into
// its two single-label parts. It rejects a bare name (no namespace) and an
// FQDN-style host with extra dots (e.g. service.namespace.svc.cluster.local) — the
// target syntax is exactly service.namespace.
func splitServiceNamespace(host string) (service, namespace string, ok bool) {
	i := strings.IndexByte(host, '.')
	if i <= 0 || i == len(host)-1 {
		return "", "", false
	}
	service, namespace = host[:i], host[i+1:]
	if strings.ContainsRune(namespace, '.') {
		return "", "", false
	}
	return service, namespace, true
}

// posErrf builds a positioned *cadishfile.ParseError, the shared diagnostic type
// (renders "file:line:col: message").
func posErrf(p cadishfile.Pos, format string, args ...any) error {
	return &cadishfile.ParseError{File: p.File, Line: p.Line, Col: p.Col, Msg: fmt.Sprintf(format, args...)}
}

// staticBaseURL returns the httporigin base URL for a single resolved endpoint
// address (ip or host). For static targets the configured Raw URL is returned
// as-is; for dynamic targets a URL is synthesized from the connection scheme,
// the resolved address, and the port.
func (t Target) endpointURL(addr string) string {
	if t.Scheme == SchemeStatic {
		return t.Raw
	}
	host := net.JoinHostPort(addr, t.Port)
	u := url.URL{Scheme: t.ConnScheme, Host: host, Path: t.Path}
	return u.String()
}
