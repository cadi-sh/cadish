// Package pipeline is cadish's request-evaluation engine: it compiles a parsed
// Cadishfile site (the semantics-free AST from internal/cadishfile) into an
// executable Pipeline and evaluates each request through the cache lifecycle.
//
// This package is PURE: it performs no network I/O, starts no goroutines, and
// owns no listeners. It turns a Request plus a few scalars (response status,
// cache-lookup outcome) into DECISIONS — structured values that the server layer
// (a later milestone) applies to net/http and the cache/origin packages. The
// split mirrors the request lifecycle:
//
//	EvalRequest  (RECV + KEY)  -> respond / purge / route / pass / cache_key / req headers
//	EvalResponse (ORIGIN/store)-> cache_ttl / storage  (needs the response status)
//	EvalDeliver  (DELIVER)     -> resp headers / strip_cookies / cors / cache-status
//
// Compile validates the directives once (returning errors that carry the
// offending source Pos) and compiles every matcher a single time; the per-request
// Eval methods are allocation-light and safe for concurrent use (a *Pipeline is
// immutable after Compile).
package pipeline

import (
	"net/http"
	"net/netip"
	"net/url"
	"strings"
)

// Request is the engine's backend-agnostic view of an HTTP request. It is
// deliberately decoupled from net/http's *http.Request so the evaluation core can
// be unit-tested without a server and reused by tooling. The server constructs
// one of these from the live request before each phase.
//
// Using net/http and net/url *types* (http.Header, url.Values) is intentional —
// it is the convenient shape for header/query access. No network I/O is implied.
type Request struct {
	// Method is the HTTP method (e.g. "GET"). Compared case-insensitively by the
	// `method` matcher; an empty Method is treated as "GET".
	Method string
	// Host is the request authority (e.g. "static.example.com" or
	// "example.com:8443"). Any :port is stripped and the value lower-cased for
	// host matching and the `host` cache_key token.
	Host string
	// Path is the URL path (e.g. "/panel/settings"), already percent-decoded by
	// the server. It is what `path` / `path_regex` matchers and the `path`
	// cache_key token see.
	Path string
	// Query holds the parsed query parameters. The `query` and `url` cache_key
	// tokens render it canonically (keys+values sorted) so semantically equal
	// queries share a cache key.
	Query url.Values
	// Header carries the request headers. May be nil (treated as empty).
	Header http.Header
	// ClientIP is the resolved client address (no port). It is the fallback for
	// the {sticky} normalizer when no sticky cookie is present.
	ClientIP string
	// RealClientIP is the trusted-proxy-resolved REAL client IP for the `ip` ACL
	// matcher (the security gate). The server resolves it via geo.ClientIP — the
	// SAME trust_proxy/XFF logic as {geo} (decision #16), so behind a CDN/LB the
	// gate ACLs the real client, not the proxy — and sets it before EvalSecurity,
	// gated by UsesSecurityGate (zero cost on non-security sites). It is the
	// zero netip.Addr (invalid) when the site runs no security gate; an `ip`
	// matcher against an invalid address matches nothing.
	RealClientIP netip.Addr
	// Device is the resolved device class for the {device} cache-key normalizer
	// ("desktop"/"mobile"/"tablet"/"bot"/…). The server computes it from the
	// User-Agent via the site's classifier (a cheap pre-pass) before EvalRequest;
	// it is "" when {device} is unused or no classifier ran.
	Device string
	// Geo is the resolved geo class for the {geo} cache-key normalizer (a country
	// code like "US"/"ES", or "unknown"). The server computes it from the real
	// client IP / a CDN country header via the site's geo source before
	// EvalRequest; it is "" when {geo} is unused or no geo source is configured.
	Geo string
	// GeoContinent is the resolved continent class for the {geo.continent} token
	// (a 2-letter code like "EU"/"NA", or "unknown"). The server derives it from
	// the resolved country via an in-tree static table (no GeoIP dependency) before
	// EvalRequest; "" when no geo granularity token/matcher is used.
	GeoContinent string
	// GeoRegion is the resolved region / subdivision class for the {geo.region}
	// token (e.g. "US-UT"/"US-TX", or "unknown"). The server reads it from a
	// configurable upstream CDN region header (no bundled GeoIP DB — region
	// granularity REQUIRES an upstream geo header) before EvalRequest; "" when no
	// geo granularity token/matcher is used or no region source is configured.
	GeoRegion string
}

// method returns the effective method, upper-cased, defaulting to GET.
func (r *Request) method() string {
	if r.Method == "" {
		return http.MethodGet
	}
	return strings.ToUpper(r.Method)
}

// normHost returns the host lower-cased with any :port removed.
func (r *Request) normHost() string {
	return normalizeHost(r.Host)
}

// headerGet returns the first value of header name (canonicalized), or "".
func (r *Request) headerGet(name string) string {
	if r.Header == nil {
		return ""
	}
	return r.Header.Get(name)
}

// headerCombined returns ALL values of a header joined as one RFC 9110 §5.3 field-value
// (comma+space), or "". This is what a compliant origin sees when a header is sent on multiple
// lines, so it is the value any CACHE-KEY-influencing reader (the `header:NAME` key token,
// `normalize { from header }`, `{tenant}` from a header) MUST use — NOT headerGet's first line.
// Reading only the first line let an attacker send a second value the origin combines/uses
// while the key captured only the first → two distinct requests collapse onto one entry and
// the attacker's response is served to the victim (cross-tenant cache poisoning).
func (r *Request) headerCombined(name string) string {
	if r.Header == nil {
		return ""
	}
	vs := r.Header.Values(name)
	switch len(vs) {
	case 0:
		return ""
	case 1:
		return vs[0]
	default:
		return strings.Join(vs, ", ")
	}
}

// cookieKV is one parsed request cookie (name + value).
type cookieKV struct {
	name  string
	value string
}

// lenientCookies parses EVERY Cookie request header line with the LENIENT rules the origin,
// the `cookie_json` matcher, and the Cadish Edge all use — split on ';', then on the first
// '=', trim, strip a surrounding pair of quotes — NOT net/http's strict Cookies()/Cookie(),
// which DROPS a cookie whose value carries JSON octets (`{ " : ,` …). The strict parser made
// the credential gate and the cache key BLIND to a JSON-valued session cookie while the origin
// still received and personalized on it — a cross-user leak (`sess={"uid":"alice"}` evaded the
// bypass, and `cache_key cookie:sess` rendered "" so every JSON session collapsed onto one
// entry). This single lenient reader is the source of truth for the gate AND the key, so they
// cannot diverge from the bytes the origin gets. Reads all header lines (multi-line safe).
func lenientCookies(h http.Header) []cookieKV {
	if h == nil {
		return nil
	}
	lines := h["Cookie"]
	if len(lines) == 0 {
		return nil
	}
	raw := strings.Join(lines, "; ")
	var out []cookieKV
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value := part, ""
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			name = strings.TrimSpace(part[:eq])
			value = strings.TrimSpace(part[eq+1:])
		}
		if name == "" {
			continue
		}
		if len(value) >= 2 && strings.HasPrefix(value, `"`) && strings.HasSuffix(value, `"`) {
			value = value[1 : len(value)-1]
		}
		out = append(out, cookieKV{name, value})
	}
	return out
}

// cookie returns the value of the named cookie, or "" if absent — read LENIENTLY (see
// lenientCookies) so a JSON/quoted cookie value the origin uses is captured in the cache key.
func (r *Request) cookie(name string) string {
	for _, c := range lenientCookies(r.Header) {
		if c.name == name {
			return c.value
		}
	}
	return ""
}

// LenientCookieValue returns the named cookie's value parsed with cadish's lenient
// cookie rules (see lenientCookies) — the value the origin and the gate see, NOT
// net/http's strict parser (which drops a JSON/quoted value). Exported so the server's
// sticky-LB affinity reader reads cookies the same way as the rest of cadish.
func LenientCookieValue(h http.Header, name string) string {
	for _, c := range lenientCookies(h) {
		if c.name == name {
			return c.value
		}
	}
	return ""
}

// cookieNames returns the names of every cookie in the request's Cookie header (in header
// order, with duplicates as sent), parsed LENIENTLY (see lenientCookies). It backs the
// name-aware credential-coverage check (BypassForCredentials): a credentialed request may only
// be cached when the key captures every cookie it carries — and the gate must SEE a JSON cookie
// the origin will use, which the strict net/http parser silently dropped.
func (r *Request) cookieNames() []string {
	cs := lenientCookies(r.Header)
	if len(cs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.name)
	}
	return out
}

// NormalizeHost is the exported canonical host normalization (lower-case, strip :port, strip
// an FQDN trailing dot) — the SAME function the `host` cache-key token and the host matchers
// use. The server uses it to forward the canonical host to the origin (host_header preserve),
// so the origin sees exactly the host the cache key captured: keying on the normalized host
// while forwarding the raw `Host: example.com:1337` let an attacker poison the `example.com`
// entry with a response generated for a port/case variant a Host-reflecting origin treats
// differently (cache poisoning). One reader = no divergence.
func NormalizeHost(host string) string { return normalizeHost(host) }

// normalizeHost lower-cases a host, strips any trailing :port, and strips an FQDN
// trailing dot. IPv6 literals in brackets are left intact except for a trailing port.
func normalizeHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	// Strip port: handle [::1]:8080 and host:8080, but not a bare IPv6 "::1".
	if strings.HasPrefix(host, "[") {
		if i := strings.LastIndex(host, "]"); i >= 0 {
			if rest := host[i+1:]; strings.HasPrefix(rest, ":") {
				host = host[:i+1]
			}
		}
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// A DNS hostname / IPv4 cannot contain a colon, so a SINGLE colon is always a
		// host:port delimiter — strip it regardless of whether the "port" is numeric. (A bare
		// IPv6 has multiple colons and is left intact; a bracketed [::1]:port is handled
		// above.) This matches net.SplitHostPort (used by the server's site-selection
		// normalizeAddr), so the cache key and routing canonicalize a host IDENTICALLY: a
		// non-numeric "port" like `example.com:zzz` no longer forks the cache key from
		// `example.com` (a cache-bust / fragmentation DoS) while still selecting the same site.
		if strings.Count(host, ":") == 1 {
			host = host[:i]
		}
	}
	// FQDN trailing dot (RFC 7230 §5.4 permits it): `example.com.` is the SAME host as
	// `example.com`. Strip it so a trailing-dot Host doesn't miss host routing/`host`
	// matchers or fork the cache key (WB1). Harmless on a bracketed IPv6 (ends in ']').
	return strings.TrimSuffix(host, ".")
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
