package tlsacme

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/acme"

	"github.com/cadi-sh/cadish/internal/geo"
)

// readyzPath mirrors the unexported server.readyzPath ("/.cadish/readyz"). tlsacme cannot
// import internal/server (server imports tlsacme — that would be an import cycle), so the
// reserved warm-readiness probe path is duplicated here as a single const; keep the two in
// sync. The :80 redirect handler special-cases it (see redirectOrServe) so the probe is
// served plain through the data-plane fallback, never 301'd to HTTPS.
const readyzPath = "/.cadish/readyz"

// Options tunes Manager construction.
type Options struct {
	// CacheDir overrides where ACME certificates are cached on disk. Empty uses
	// defaultCacheDir().
	CacheDir string
	// ACMEDirectoryURL overrides the ACME server directory (e.g. a pebble or
	// staging endpoint for tests). Empty uses autocert's default (Let's Encrypt
	// production).
	ACMEDirectoryURL string
	// ACMEHTTPClient, when non-nil, overrides the HTTP client the ACME protocol
	// uses to talk to the directory (e.g. to trust a pebble/staging CA, or to go
	// through a proxy). Empty uses the default client. Only relevant with ACME.
	ACMEHTTPClient *http.Client
	// ForceACME builds the ACME (autocert) source even when NO startup site uses
	// ACME. This is the Ingress-controller mode: TLS hosts arrive later via reconcile,
	// so the :443 listener and the autocert source must already exist at startup (the
	// source is fixed at construction — see Reload's NOTE). The HostPolicy still starts
	// empty (never an open issuer); reconcile adds hosts live. NewManager honors it.
	ForceACME bool
	// ACMEEmail is the ACME account contact used when ForceACME builds the source and
	// no startup site supplied an email. Optional (autocert works without a contact).
	ACMEEmail string
}

// hstsPolicy binds a set of hosts to an HSTS header value.
type hstsPolicy struct {
	matcher *hostMatcher
	value   string
}

// hostState is the swappable, per-reload host-policy data of a Manager: the ACME
// allow-list, the static keypair source + its host set, and the HSTS policies. It
// is published behind Manager.state (an atomic.Pointer) and is never mutated after
// it is built, so concurrent handshakes load a consistent snapshot and a reload is
// a single atomic store (the same discipline the server uses for its routing table).
type hostState struct {
	acmeHosts   *hostMatcher  // hosts eligible for ACME issuance
	static      *staticSource // static keypairs (may be empty)
	staticHosts *hostMatcher  // hosts served by a static keypair
	hsts        []hstsPolicy
	// exemptPaths are request paths (exact) that the :80 listener must NOT 301 to HTTPS
	// — they answer on plain :80 via the site pipeline instead (a health-check probe,
	// webhook, or monitoring endpoint; see SiteTLS.RedirectExcept and ADR D89). It is the
	// union of every site's `tls { http_redirect_except … }` paths, so it lives in the
	// swappable host-state and is refreshed on reload. nil/empty ⇒ no exemptions, i.e.
	// the default redirect-all-on-:80 behavior, byte-for-byte unchanged.
	exemptPaths map[string]struct{}
	// trustedProxies is the UNION of every site's `trust_proxy` CIDRs. The :80
	// HTTP→HTTPS redirect loop guard honors a client `X-Forwarded-Proto: https` ONLY
	// when the immediate socket peer is in this set (WS-B / R15, ADR D95) — otherwise
	// the header is client-spoofable and a plain :80 request could be served in
	// cleartext. Lives in the swappable host-state so a reload refreshes it. nil/empty
	// ⇒ no trusted proxy ⇒ XFP never suppresses a redirect (always redirect).
	trustedProxies []netip.Prefix
}

// Manager is the whole-server TLS coordinator. It aggregates every site's TLS
// settings into one hardened *tls.Config and the :80 challenge/redirect handler,
// dispatching certificate lookups between an ACME source (autocert) and any
// static keypairs by SNI.
//
// The acme source, the :443 listener and its *tls.Config are fixed at construction
// and NEVER rebuilt. Only the host-policy data (which hosts are ACME-eligible /
// served by a static keypair, and the HSTS set) lives behind the atomic `state`
// pointer, so Reload makes a TLS-hostname change a hot reload without reopening a
// socket or recreating the ACME client.
//
// The zero value is not usable; build one with NewManager.
type Manager struct {
	acme  acmeSource // nil when no site uses ACME (autocertSource in prod)
	state atomic.Pointer[hostState]
	// dynamic holds the BYO / cert-manager keypairs supplied OUT-OF-BAND from the
	// Cadishfile — the Ingress controller injects them from kubernetes.io/tls Secrets
	// via SetDynamicCerts. It lives behind its OWN atomic pointer (not the D58 `state`)
	// so a Secret rotation and a Cadishfile reload are independent hot swaps: neither
	// clobbers the other, and getCertificate loads a consistent snapshot of each. Never
	// nil after NewManager (an empty source until the first SetDynamicCerts).
	dynamic atomic.Pointer[staticSource]
	// hasDynamic is a lock-free fast-path gate: true only while the dynamic source holds
	// at least one keypair. getCertificate checks it before touching the dynamic source,
	// so a server with NO BYO certs (every plain `cadish run`) pays NO extra lock per
	// handshake — the dynamic lookup (and its RLock) is skipped entirely. Set by
	// SetDynamicCerts after the pointer is published.
	hasDynamic atomic.Bool
	cacheDir   string

	// redirectGated, when true, makes the :80 handler redirect HTTP→HTTPS ONLY for a
	// host that has TLS (ACME-eligible, static keypair, or BYO dynamic cert) or one
	// explicitly opted in via forceRedirect — a host with no TLS is served over plain
	// HTTP through the fallback handler instead of 301'd to a dead TLS endpoint. Set in
	// Ingress mode (Options.ForceACME), where the cluster's Ingress objects (spec.tls)
	// are the source of truth for "this host wants HTTPS". Standalone `cadish run`
	// leaves it false: Caddy-style automatic-HTTPS redirects every host, as before.
	redirectGated atomic.Bool
	// forceRedirect holds hosts that should be 301'd to HTTPS EVEN without local TLS
	// (the `cadi.sh/ssl-redirect` Ingress annotation — for operators terminating TLS
	// upstream at an LB/Cloudflare). The Ingress controller sets it each reconcile via
	// SetForceRedirectHosts. Nil/empty => no forced hosts. Only consulted when gated.
	forceRedirect atomic.Pointer[hostMatcher]
}

// DynamicCert is one in-memory BYO/cert-manager keypair (PEM bytes) to serve for a
// host set. The Ingress controller builds these from kubernetes.io/tls Secrets and
// hands them to Manager.SetDynamicCerts on every reconcile.
type DynamicCert struct {
	Hosts   []string
	CertPEM []byte
	KeyPEM  []byte
}

// buildHostState aggregates the per-site TLS configs into a hostState. A ModeStatic
// site's keypair is loaded eagerly here; a bad path is an error (so a reload with a
// broken static cert fails fast and the caller keeps the old state). It does NOT
// create the ACME source — that is Manager-lifetime state built once in NewManager.
func buildHostState(sites []SiteConfig) (*hostState, error) {
	st := &hostState{
		acmeHosts:   newHostMatcher(),
		static:      newStaticSource(),
		staticHosts: newHostMatcher(),
	}
	for _, s := range sites {
		switch s.TLS.Mode {
		case ModeACME:
			for _, h := range s.Hosts {
				st.acmeHosts.add(h)
			}
		case ModeStatic:
			if s.TLS.CertFile == "" || s.TLS.KeyFile == "" {
				return nil, fmt.Errorf("tlsacme: static TLS for %v needs both cert and key", s.Hosts)
			}
			if err := st.static.addKeyPair(s.Hosts, s.TLS.CertFile, s.TLS.KeyFile); err != nil {
				return nil, err
			}
			for _, h := range s.Hosts {
				st.staticHosts.add(h)
			}
		}
		if v := s.TLS.HSTS.HeaderValue(); v != "" {
			hm := newHostMatcher()
			for _, h := range s.Hosts {
				hm.add(h)
			}
			st.hsts = append(st.hsts, hstsPolicy{matcher: hm, value: v})
		}
		for _, p := range s.TLS.RedirectExcept {
			if p == "" {
				continue
			}
			if st.exemptPaths == nil {
				st.exemptPaths = make(map[string]struct{})
			}
			st.exemptPaths[p] = struct{}{}
		}
		// Union this site's trust_proxy CIDRs into the whole-server set the :80 loop
		// guard consults (the :80 listener is not per-site). Dedup is unnecessary —
		// geo.PeerTrusted just scans the slice; a few duplicate prefixes are harmless.
		st.trustedProxies = append(st.trustedProxies, s.TrustedProxies...)
	}
	return st, nil
}

// NewManager builds a Manager from the per-site TLS configurations of a whole
// Cadishfile. Sites with ModeOff contribute nothing to TLS. A ModeStatic site's
// keypair is loaded eagerly (a bad path is a construction error). When at least
// one site uses ACME, an autocert.Manager is created whose HostPolicy is the
// union of ACME sites' hosts — never an open issuer.
func NewManager(sites []SiteConfig, opts Options) (*Manager, error) {
	st, err := buildHostState(sites)
	if err != nil {
		return nil, err
	}
	m := &Manager{}
	m.state.Store(st)
	m.dynamic.Store(newStaticSource())
	// Gate the HTTP→HTTPS redirect in Ingress mode (ForceACME): only TLS hosts (or
	// forceRedirect opt-ins) are 301'd; non-TLS hosts are served over plain HTTP.
	// Standalone keeps the unconditional Caddy-style redirect.
	m.redirectGated.Store(opts.ForceACME)

	cacheDir := opts.CacheDir
	if cacheDir == "" {
		cacheDir = defaultCacheDir()
	}
	m.cacheDir = cacheDir

	var email string
	hasACME := false
	for _, s := range sites {
		if s.TLS.Mode == ModeACME {
			hasACME = true
			if email == "" {
				email = s.TLS.Email
			}
		}
	}
	// ForceACME (Ingress mode) builds the source even with no ACME site yet, so a
	// reconcile-added host becomes issuable without a restart. The HostPolicy is still
	// the (initially empty) live acmeHosts set — never an open issuer.
	if hasACME || opts.ForceACME {
		if email == "" {
			email = opts.ACMEEmail
		}
		m.acme = newAutocertSource(cacheDir, email, m.hostPolicy, opts.ACMEDirectoryURL, opts.ACMEHTTPClient)
	}
	return m, nil
}

// SetDynamicCerts atomically replaces the BYO / cert-manager keypair set served by
// SNI (the Ingress controller calls it every reconcile from kubernetes.io/tls
// Secrets). It is TRANSACTIONAL and fail-safe: every keypair is parsed into a fresh
// source first, and only a fully-built source is published — if ANY PEM is bad the
// error is returned and the PREVIOUS dynamic set keeps serving (no partial swap, no
// listener/tls.Config/autocert rebuild). Passing an empty slice clears the set.
func (m *Manager) SetDynamicCerts(certs []DynamicCert) error {
	src := newStaticSource()
	for _, c := range certs {
		if err := src.addKeyPairPEM(c.Hosts, c.CertPEM, c.KeyPEM); err != nil {
			return fmt.Errorf("tlsacme: dynamic cert for %v: %w", c.Hosts, err)
		}
	}
	// Publish the pointer BEFORE the gate so a reader that observes hasDynamic==true
	// always loads a source that already holds the certs.
	m.dynamic.Store(src)
	m.hasDynamic.Store(src.has())
	return nil
}

// PrepareReload builds and validates a new hostState from sites WITHOUT publishing
// it. A bad static keypair path (or a static site missing a cert/key) is returned as
// an error here, so the caller can keep serving the old state. Commit publishes the
// returned state atomically. This two-phase split lets Server.ApplyConfig validate
// every TLS change up front and commit it last, alongside the routing swap.
func (m *Manager) PrepareReload(sites []SiteConfig) (*hostState, error) {
	return buildHostState(sites)
}

// Commit atomically publishes a hostState prepared by PrepareReload. Subsequent
// hostPolicy / getCertificate / HSTSValueFor calls observe it; in-flight handshakes
// that already loaded the previous state finish on it. The acme source, listener and
// *tls.Config are untouched.
func (m *Manager) Commit(st *hostState) { m.state.Store(st) }

// Reload rebuilds the host policy (ACME allow-list, static keypairs, HSTS) from sites
// and atomically swaps it in, making a TLS-hostname change a hot reload: newly-added
// ACME hosts become issuable immediately and removed ones stop being issuable, with
// NO new ACME client, NO socket reopened and in-flight TLS connections undisturbed. A
// bad static keypair path is a fail-safe error: the old host set is kept.
//
// It is PrepareReload followed by Commit, for SIGHUP and tests; Server.ApplyConfig
// uses the two-phase form so a TLS error aborts before any state is published.
//
// NOTE: enabling ACME for the FIRST time (a config that had no ACME site at startup)
// still needs a restart — the autocert source and the acme-tls/1 ALPN advertisement
// are fixed at construction. Reload changes only the host-policy data the existing
// closures read.
func (m *Manager) Reload(sites []SiteConfig) error {
	st, err := m.PrepareReload(sites)
	if err != nil {
		return err
	}
	m.Commit(st)
	return nil
}

// NeedsTLS reports whether any site terminates TLS (ACME or static). When false,
// the server need not bind :443. The :443/:80 binding decision is made once at
// startup; this reads the current (possibly reloaded) state for diagnostics.
func (m *Manager) NeedsTLS() bool {
	return m.acme != nil || m.state.Load().static.has() || m.hasDynamic.Load()
}

// CacheDir returns the resolved ACME cache directory.
func (m *Manager) CacheDir() string { return m.cacheDir }

// HostAllowed reports whether host is eligible for ACME issuance under the
// configured policy. Exposed for testing and diagnostics.
func (m *Manager) HostAllowed(host string) bool {
	return m.state.Load().acmeHosts.matches(host)
}

// hostPolicy is the autocert.HostPolicy: issue only for configured ACME hosts. It
// loads the live host state once per call, so a reload that adds/removes an ACME host
// takes effect for the next issuance with no new ACME client.
func (m *Manager) hostPolicy(_ context.Context, host string) error {
	if m.state.Load().acmeHosts.matches(host) {
		return nil
	}
	return fmt.Errorf("tlsacme: host %q is not configured for ACME", host)
}

// secureCipherSuites is the TLS 1.2 cipher allow-list (AEAD suites with forward
// secrecy only). TLS 1.3 suites are fixed by the stdlib and always enabled.
var secureCipherSuites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
}

// TLSConfig returns a hardened *tls.Config for the :443 listener: TLS 1.2
// minimum (1.3 preferred), modern AEAD ciphers, ALPN advertising HTTP/2 and
// HTTP/1.1 (plus acme-tls/1 when ACME is active for the TLS-ALPN-01 challenge),
// and certificate resolution dispatched by SNI.
func (m *Manager) TLSConfig() *tls.Config {
	cfg := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		GetCertificate:   m.getCertificate,
		CipherSuites:     secureCipherSuites,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
	}
	if m.acme != nil {
		cfg.NextProtos = append(cfg.NextProtos, acme.ALPNProto)
	}
	return cfg
}

// getCertificate resolves the certificate for a handshake, dispatching by SNI:
//   - a TLS-ALPN-01 challenge (acme-tls/1) always goes to autocert;
//   - a host served by a static keypair uses it;
//   - otherwise ACME (autocert) handles it, if configured.
func (m *Manager) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if m.acme != nil && hasProto(hello.SupportedProtos, acme.ALPNProto) {
		return m.acme.GetCertificate(hello)
	}
	st := m.state.Load()
	name := normalizeHost(hello.ServerName)
	if st.static.has() && st.staticHosts.matches(name) {
		if c := st.static.lookup(name); c != nil {
			return c, nil
		}
	}
	// BYO / cert-manager certs (Ingress Secrets) — matched strictly by SNI. A
	// non-matching SNI is NOT served a dynamic cert (no fallback here), so an
	// unconfigured host cannot coax out a mismatched certificate. The hasDynamic gate
	// keeps this lock-free (no RLock) when no BYO certs are configured.
	if m.hasDynamic.Load() {
		if c := m.dynamic.Load().lookup(name); c != nil {
			return c, nil
		}
	}
	// No-SNI handshake (a pre-SNI / IP client): autocert cannot issue without a server name
	// (it errors "missing server name"), so when a static keypair exists, prefer its fallback
	// BEFORE the ACME branch — otherwise a mixed ACME+static deployment fails a no-SNI client
	// even though a usable static cert is configured. (A NAMED but ACME-eligible host still
	// goes to ACME below.)
	if name == "" && st.static.has() {
		return st.static.GetCertificate(hello)
	}
	if m.acme != nil {
		return m.acme.GetCertificate(hello)
	}
	if st.static.has() {
		return st.static.GetCertificate(hello)
	}
	return nil, fmt.Errorf("tlsacme: no certificate source for %q", hello.ServerName)
}

// HTTPHandler returns the handler for the :80 listener: it serves ACME HTTP-01
// challenges (when ACME is active), 301-redirects requests whose host should go to
// HTTPS (see shouldRedirect), and otherwise serves the request over plain HTTP via
// fallback (the main server handler). The server binds this on port 80. fallback may
// be nil in standalone mode, where every host redirects so it is never reached.
func (m *Manager) HTTPHandler(fallback http.Handler) http.Handler {
	redirect := m.redirectOrServe(fallback)
	if m.acme != nil {
		return m.acme.HTTPHandler(redirect)
	}
	return redirect
}

// redirectOrServe is the :80 handler body. It 301s to HTTPS when the host should be
// redirected, otherwise hands the request to fallback (plain HTTP). In standalone
// (ungated) mode every host redirects.
func (m *Manager) redirectOrServe(fallback http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// RESERVED WARM-READINESS PROBE EXEMPTION (server.readyzPath): /.cadish/readyz MUST
		// be served on plain :80 — NEVER 301'd to HTTPS. A Kubernetes httpGet probe treats
		// 2xx AND 3xx as success, so a redirect would make the probe pass REGARDLESS of warm
		// state, silently defeating the warm-readiness gate for TLS controllers and standalone
		// TLS servers (the exact rollout 502/404 it exists to prevent). So pass it straight to
		// the data-plane fallback, which answers the real 200 "ok" / 503 "warming". Checked
		// BEFORE host normalization so the probe stays Host-agnostic (kubelet sends the pod IP
		// as Host, but an operator may set httpGet.host to a TLS hostname that would otherwise
		// 301). Like the ACME-challenge and http_redirect_except exemptions it only ever SKIPS
		// a redirect, never forces one. See internal/server/handler.go serveReadyz.
		if r.URL.Path == readyzPath {
			if fallback != nil {
				fallback.ServeHTTP(w, r)
				return
			}
			// No data-plane fallback wired (never the case via BuildServers): fail CLOSED so
			// an un-warmed :80 reports NOT-ready rather than a spurious redirect/200.
			http.Error(w, "warming", http.StatusServiceUnavailable)
			return
		}
		host := normalizeHost(r.Host)
		if host == "" {
			http.Error(w, "missing host", http.StatusBadRequest)
			return
		}
		// LOOP GUARD (X-Forwarded-Proto): when a trusted upstream LB / TLS terminator
		// forwards plain HTTP to cadish:80 but sets `X-Forwarded-Proto: https`, the
		// request already reached the edge over HTTPS. Redirecting it would bounce it
		// back to the terminator, which forwards plain HTTP again → an infinite 301
		// loop. This is acute for `cadi.sh/ssl-redirect` (forceRedirect) hosts, whose
		// whole use case is upstream TLS termination. So never redirect a request that
		// arrived over HTTPS — serve it plain instead. This only ever SKIPS a redirect,
		// never forces one. The X-Forwarded-Proto signal is TRUST-GATED (R15): honored
		// only when the immediate socket peer is in `trust_proxy`, so a direct client
		// cannot forge it to be served in cleartext. The upstream must also set
		// X-Forwarded-Proto and strip any client value (see docs/tls.md,
		// docs/ingress-controller.md).
		// PROBE / DATA-PLANE EXEMPTION (D89): a path explicitly listed via
		// `tls { http_redirect_except … }` answers on plain :80 through the site pipeline
		// (its RECV `respond`/`redirect` synthetic) instead of being 301'd to HTTPS — so an
		// L4/DNS health-check probe, webhook, or monitor that hits cadish:80 directly gets
		// its real 200/503, not a 301. This only ever SKIPS a redirect for an explicitly
		// named path: it never forces one, never alters the X-Forwarded-Proto loop guard,
		// and leaves every other path 301'ing exactly as before, so no redirect loop is
		// introduced. Empty exempt set ⇒ the default redirect-all-on-:80 is unchanged.
		if m.shouldRedirect(host) && !arrivedOverHTTPS(r, m.trustedProxiesSnapshot()) && !m.redirectExempt(r.URL.Path) {
			target := "https://" + host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
			return
		}
		if fallback != nil {
			fallback.ServeHTTP(w, r)
			return
		}
		http.Error(w, "host not configured for TLS", http.StatusMisdirectedRequest)
	}
}

// arrivedOverHTTPS reports whether the request already reached a trusted upstream over
// HTTPS, per the de-facto `X-Forwarded-Proto: https` header an LB / TLS terminator sets
// when it forwards plain HTTP to cadish:80. cadish does not parse the RFC 7239
// `Forwarded:` header anywhere (only X-Forwarded-For), so only X-Forwarded-Proto is
// honored. A value may be a comma-separated list (outermost proxy first); any `https`
// token counts. Matching is case-insensitive. Consulted ONLY to SKIP a redirect (the
// loop guard) — never to force one.
//
// TRUST BOUNDARY (WS-B / R15, ADR D95): X-Forwarded-Proto is client-spoofable, and the
// full caching handler is the :80 fallback, so honoring it from ANY peer would let a
// direct client add `X-Forwarded-Proto: https` to a plain :80 request and be served in
// cleartext (no HSTS) — defeating automatic-HTTPS. So the header is honored ONLY when
// the immediate socket peer is a trusted proxy (`trust_proxy`). With no trusted
// proxies configured the peer is never trusted, so the header is ignored and the
// request is always redirected (the safe default; this also closes the standalone
// facet R10b). Behind a trusted terminator (e.g. Cloudflare), declare its network in
// `trust_proxy` so the legitimate XFP:https loop guard still suppresses the redirect.
func arrivedOverHTTPS(r *http.Request, trusted []netip.Prefix) bool {
	if !geo.PeerTrusted(r.RemoteAddr, trusted) {
		return false
	}
	for _, v := range r.Header.Values("X-Forwarded-Proto") {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "https") {
				return true
			}
		}
	}
	return false
}

// trustedProxiesSnapshot returns the current whole-server trust_proxy set from the
// swappable host-state (refreshed on reload). nil before the first state is published.
func (m *Manager) trustedProxiesSnapshot() []netip.Prefix {
	if st := m.state.Load(); st != nil {
		return st.trustedProxies
	}
	return nil
}

// shouldRedirect reports whether an HTTP request for host should be 301'd to HTTPS.
// Ungated (standalone) always redirects. Gated (Ingress) redirects only a host that
// has TLS or is opted in via the cadi.sh/ssl-redirect annotation (forceRedirect).
func (m *Manager) shouldRedirect(host string) bool {
	if !m.redirectGated.Load() {
		return true
	}
	if m.hostHasTLS(host) {
		return true
	}
	if fr := m.forceRedirect.Load(); fr != nil && fr.matches(host) {
		return true
	}
	return false
}

// redirectExempt reports whether path is on the :80 HTTP→HTTPS redirect exemption set
// (the union of every site's `tls { http_redirect_except … }` paths). Matching is exact
// on the request URL path (query string excluded); an unconfigured set ⇒ never exempt, so
// the default redirect-all-on-:80 is unchanged. It reads the live host-state so a reload
// that adds/removes an exempt path takes effect immediately on the next :80 request.
func (m *Manager) redirectExempt(path string) bool {
	st := m.state.Load()
	if st == nil || len(st.exemptPaths) == 0 {
		return false
	}
	_, ok := st.exemptPaths[path]
	return ok
}

// hostHasTLS reports whether host has a REAL, usable certificate available right now —
// a static keypair, a BYO dynamic (cert-manager) cert, or an ACME cert that has actually
// been ISSUED and cached. It is the redirect gate's source of truth (F11).
//
// ACME HostPolicy membership (st.acmeHosts) is DELIBERATELY NOT treated as "has TLS":
// eligibility is not a cert. A host can be ACME-eligible yet never issue (a non-public
// TLD, or unreachable for the HTTP-01/TLS-ALPN-01 challenge). Counting eligibility as
// TLS made the :80 gate 301 into a :443 that returns internal_error — the host went dark
// over BOTH schemes. We instead require a cert to genuinely exist; until one does, the
// host is served plain over :80 (the ACME challenge still completes via the :80 handler,
// so issuance converges, after which this returns true and the redirect kicks in).
func (m *Manager) hostHasTLS(host string) bool {
	if st := m.state.Load(); st != nil {
		if st.staticHosts != nil && st.staticHosts.matches(host) {
			return true
		}
	}
	if m.hasDynamic.Load() {
		if c := m.dynamic.Load().lookup(host); c != nil {
			return true
		}
	}
	// ACME: redirect only once a cert has truly been issued and cached for host (not on
	// mere HostPolicy eligibility).
	if m.acme != nil && m.acme.HasIssuedCert(host) {
		return true
	}
	return false
}

// SetForceRedirectHosts replaces the set of hosts 301'd to HTTPS even without local
// TLS (the cadi.sh/ssl-redirect Ingress annotation). The controller calls it each
// reconcile; an empty slice clears the set. Only consulted when the redirect is gated.
func (m *Manager) SetForceRedirectHosts(hosts []string) {
	if len(hosts) == 0 {
		m.forceRedirect.Store(nil)
		return
	}
	hm := newHostMatcher()
	for _, h := range hosts {
		hm.add(h)
	}
	m.forceRedirect.Store(hm)
}

// HSTSValueFor returns the Strict-Transport-Security header value configured for
// host, or "" if none.
func (m *Manager) HSTSValueFor(host string) string {
	host = normalizeHost(host)
	for _, p := range m.state.Load().hsts {
		if p.matcher.matches(host) {
			return p.value
		}
	}
	return ""
}

// HSTSMiddleware wraps an HTTPS handler to add the configured HSTS header for the
// request's host. It is a no-op for hosts without an HSTS policy. The server
// applies this only on the TLS listener (never on plain HTTP).
// Whether to install the middleware is decided once (at BuildServers/startup) from
// the then-current state: a site that declares HSTS at startup gets the middleware,
// which then reads the LIVE state per request so a reload can change/remove the HSTS
// value. (Adding the very first HSTS policy via reload, like enabling TLS itself,
// needs a restart since the wrapper is fixed with the listener.)
func (m *Manager) HSTSMiddleware(next http.Handler) http.Handler {
	if len(m.state.Load().hsts) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := m.HSTSValueFor(r.Host); v != "" {
			w.Header().Set("Strict-Transport-Security", v)
		}
		next.ServeHTTP(w, r)
	})
}

// hasProto reports whether protos contains want.
func hasProto(protos []string, want string) bool {
	for _, p := range protos {
		if p == want {
			return true
		}
	}
	return false
}
