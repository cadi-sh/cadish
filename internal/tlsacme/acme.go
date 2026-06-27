package tlsacme

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// New-name ACME issuance rate limit. cadish has no DNS-01, so a wildcard/on-demand site
// (`*.example.com { tls { acme } }`) issues a SEPARATE per-FQDN certificate on demand. Without
// a bound, an attacker presenting random `<rand>.example.com` SNI would drive unbounded ACME
// new-order attempts and exhaust the account's limits (Let's Encrypt: 300 new orders / 3h),
// banning real issuance/renewal. This token bucket caps the rate of GENUINELY-NEW certificate
// orders well under that, while already-issued names (served from cache) and the in-flight
// challenge handshakes bypass it entirely — so legitimate subdomains keep working and a flood
// of unknown names is refused cheaply (the handshake fails for the new name; nothing else).
const (
	newCertBurst         = 50 // immediate burst (onboarding many subdomains at once)
	newCertRefillPerHour = 20 // steady new-cert orders per hour after the burst
)

// issuanceLimiter is a tiny token bucket for new-name ACME orders. now is injectable for tests.
type issuanceLimiter struct {
	mu     sync.Mutex
	tokens float64
	last   time.Time
	now    func() time.Time
}

func newIssuanceLimiter(now func() time.Time) *issuanceLimiter {
	if now == nil {
		now = time.Now
	}
	return &issuanceLimiter{tokens: newCertBurst, last: now(), now: now}
}

// refillLocked accrues tokens for the elapsed time, capped at the burst. Caller holds mu.
func (l *issuanceLimiter) refillLocked() {
	t := l.now()
	l.tokens += (newCertRefillPerHour / 3600.0) * t.Sub(l.last).Seconds()
	if l.tokens > newCertBurst {
		l.tokens = newCertBurst
	}
	l.last = t
}

// allow consumes one token, refilling at newCertRefillPerHour. Returns false when empty.
func (l *issuanceLimiter) allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked()
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// available reports whether a token is currently available WITHOUT consuming it (a peek).
// GetCertificate uses it to skip the on-disk issued-cert probe for a name that would be
// refused anyway under an exhausted budget — so a random-SNI flood refuses each new name
// with no filesystem lookup (R41). It refills first so the peek reflects accrued tokens.
func (l *issuanceLimiter) available() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refillLocked()
	return l.tokens >= 1
}

// acmeSource is the capability the Manager needs from an ACME provider: resolve
// certificates (including the TLS-ALPN-01 challenge) and serve the HTTP-01
// challenge on :80. It is an interface so tests can inject a fake in place of a
// live issuer, and so a future DNS-01 / multi-CA provider can replace autocert
// behind the same seam.
type acmeSource interface {
	CertSource
	// HTTPHandler serves ACME HTTP-01 challenges and delegates everything else
	// to fallback (matches autocert.Manager.HTTPHandler).
	HTTPHandler(fallback http.Handler) http.Handler
	// HasIssuedCert reports whether a usable certificate for host has already been
	// ISSUED and cached (a real cert exists), WITHOUT triggering issuance. It is the
	// redirect gate's "ACME cert genuinely available" check (F11): ACME HostPolicy
	// membership alone must NOT count as "has TLS", or we'd 301 into a dead :443 for a
	// host whose cert never issues (non-public TLD / unreachable for the challenge).
	HasIssuedCert(host string) bool
}

// autocertSource is the production acmeSource: a thin, named wrapper over
// autocert.Manager so the ACME provider satisfies the same CertSource seam as
// every other certificate source (staticSource, test fakes).
type autocertSource struct {
	mgr   *autocert.Manager
	cache autocert.DirCache // the on-disk ACME cert cache, for read-only issued-cert probes
	// limiter bounds GENUINELY-NEW certificate orders (on-demand wildcard DoS guard); issued
	// memoizes names already served so the hot path skips the limiter and the disk probe. It
	// is WARMED from disk at startup (warmIssued) so a restart recognizes already-issued names
	// without a per-handshake probe, and so the limiter peek can refuse unknown names cheaply.
	limiter *issuanceLimiter
	issued  sync.Map // name -> struct{}: names known issued (in mgr's cache / on disk)
	// probes counts on-disk issued-cert probes (HasIssuedCert) — test observability for the
	// R41 guard that a rate-limited (refused) handshake performs NO filesystem lookup.
	probes atomic.Int64
}

// newAutocertSource builds an autocert-backed ACME source. policy restricts
// issuance to configured hosts (never an open issuer); cacheDir persists certs
// across restarts; email is the ACME account contact; directoryURL overrides the
// ACME server (empty = Let's Encrypt production; a pebble/staging URL for tests);
// httpClient, when non-nil, overrides the HTTP client the ACME protocol uses
// (e.g. to trust a pebble/staging CA, or to route through a proxy).
func newAutocertSource(cacheDir, email string, policy autocert.HostPolicy, directoryURL string, httpClient *http.Client) *autocertSource {
	cache := autocert.DirCache(cacheDir)
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      cache,
		HostPolicy: policy,
		Email:      email,
	}
	if directoryURL != "" || httpClient != nil {
		m.Client = &acme.Client{DirectoryURL: directoryURL, HTTPClient: httpClient}
	}
	s := &autocertSource{mgr: m, cache: cache, limiter: newIssuanceLimiter(time.Now)}
	s.warmIssued()
	return s
}

// warmIssued pre-populates the issued set from the on-disk ACME cache at startup. After a
// restart, an already-issued name is then recognized in GetCertificate WITHOUT a per-handshake
// disk probe; combined with the limiter peek, a random-SNI flood (budget exhausted) refuses
// each brand-new name with NO filesystem lookup while every genuinely-issued name still serves
// (R41). It memoizes a name ONLY when HasIssuedCert confirms a valid, host-covering cert on
// disk — so a stale, empty, or non-cert file can never falsely memoize a name (which would let
// a brand-new ACME order bypass the rate limiter). Best-effort: a missing/unreadable cache dir
// (no certs issued yet) is fine.
func (a *autocertSource) warmIssued() {
	entries, err := os.ReadDir(string(a.cache))
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// DirCache keys per-host cert blobs by the bare host (ECDSA) or host+"+rsa" (legacy
		// RSA), and also stores non-cert files like "acme_account+key" and transient HTTP-01
		// "+token" files. The "+rsa" sibling is covered via the bare-host key; any other "+"
		// file is not a host cert. Let HasIssuedCert validate the candidate before memoizing.
		if strings.HasSuffix(name, "+rsa") || strings.ContainsRune(name, '+') {
			continue
		}
		if a.HasIssuedCert(name) {
			a.issued.Store(normalizeHost(name), struct{}{})
		}
	}
}

// HasIssuedCert implements acmeSource. It reads the autocert cache directly (read-only;
// it never triggers issuance) and reports whether a currently-valid certificate for
// host is cached AND actually covers host. The cache file format matches autocert's
// DirCache: a PEM private-key block followed by one or more certificate PEM blocks,
// keyed by the bare host (ECDSA) or host+"+rsa" (legacy RSA). We honor both keys.
func (a *autocertSource) HasIssuedCert(host string) bool {
	a.probes.Add(1)
	host = normalizeHost(host)
	if host == "" {
		return false
	}
	for _, key := range []string{host, host + "+rsa"} {
		data, err := a.cache.Get(context.Background(), key)
		if err != nil || len(data) == 0 {
			continue
		}
		if certCoversHost(data, host) {
			return true
		}
	}
	return false
}

// certCoversHost reports whether the autocert-cache blob holds at least one currently
// valid leaf certificate that covers host. It skips the leading private-key PEM block
// and verifies the first certificate's validity window and host coverage.
func certCoversHost(cacheBlob []byte, host string) bool {
	rest := cacheBlob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type != "CERTIFICATE" {
			continue // the leading EC/RSA PRIVATE KEY block
		}
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return false
		}
		now := time.Now()
		if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
			return false // expired / not-yet-valid → not usable
		}
		return leaf.VerifyHostname(host) == nil
	}
}

// GetCertificate implements CertSource. It bounds GENUINELY-NEW on-demand ACME orders (the
// wildcard/on-demand DoS guard) without touching the common path: a TLS-ALPN-01 challenge
// handshake, a name already served this run, and a name already in the on-disk cache (warmed
// at startup) all pass straight through to autocert. Only a name that would trigger a
// brand-new ACME order consults the rate limiter; when the budget is exhausted the handshake
// fails for that one new name (existing certs keep serving) so a random-SNI flood cannot
// exhaust the ACME account.
//
// Ordering matters for the flood case (R41): when the new-cert budget is already spent, the
// name is refused REGARDLESS of any disk probe, and startup warming guarantees every
// genuinely-issued name is already in `issued` — so we peek the limiter BEFORE the on-disk
// probe and refuse a spent-budget name with no filesystem lookup at all.
func (a *autocertSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	// A challenge handshake is part of validating an in-flight order — never rate-limit it.
	if hasProto(hello.SupportedProtos, acme.ALPNProto) {
		return a.mgr.GetCertificate(hello)
	}
	name := normalizeHost(hello.ServerName)
	if name == "" {
		return a.mgr.GetCertificate(hello) // let autocert return its "missing server name" error
	}
	if _, ok := a.issued.Load(name); ok {
		return a.mgr.GetCertificate(hello) // already served this run / warmed from disk
	}
	// Not known-issued. If the budget is spent, this name is refused either way — and warming
	// already memoized every issued name above — so refuse WITHOUT probing the filesystem.
	if !a.limiter.available() {
		return nil, fmt.Errorf("tlsacme: new-certificate issuance rate limit reached, refusing on-demand issuance for %q (random-SNI flood guard)", name)
	}
	// Budget available: the name may still be an already-issued cert (issued out-of-band or by
	// another process sharing the cache after startup). Probe disk before ordering.
	if a.HasIssuedCert(name) {
		a.issued.Store(name, struct{}{})
		return a.mgr.GetCertificate(hello)
	}
	// A brand-new name → a new ACME order. Consume the new-cert budget now (a race may have
	// drained the last token since the peek — fail closed toward refusing the new order).
	if !a.limiter.allow() {
		return nil, fmt.Errorf("tlsacme: new-certificate issuance rate limit reached, refusing on-demand issuance for %q (random-SNI flood guard)", name)
	}
	cert, err := a.mgr.GetCertificate(hello)
	if err == nil {
		a.issued.Store(name, struct{}{})
	}
	return cert, err
}

// HTTPHandler implements acmeSource.
func (a *autocertSource) HTTPHandler(fallback http.Handler) http.Handler {
	return a.mgr.HTTPHandler(fallback)
}

// Compile-time checks that the concrete type satisfies the interfaces.
var (
	_ CertSource       = (*autocertSource)(nil)
	_ acmeSource       = (*autocertSource)(nil)
	_ ChallengeHandler = (*autocertSource)(nil)
)
