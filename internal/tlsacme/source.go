package tlsacme

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
)

// CertSource resolves the certificate for a TLS handshake. It is the seam that
// keeps the certificate provider pluggable: the default is an ACME-backed
// autocert.Manager, but a static keypair (staticSource) or a future DNS-01 /
// multi-CA provider implements the same interface.
//
// GetCertificate matches the signature of tls.Config.GetCertificate and of
// autocert.Manager.GetCertificate, so an autocert.Manager satisfies CertSource
// directly.
type CertSource interface {
	GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error)
}

// ChallengeHandler is an optional capability of a CertSource that needs to serve
// HTTP-01 challenges on :80 (ACME does; a static keypair does not).
type ChallengeHandler interface {
	// HTTPHandler returns a handler that serves ACME HTTP-01 challenge responses
	// and delegates every other request to fallback. autocert.Manager provides
	// exactly this.
	HTTPHandler(fallback http.Handler) http.Handler
}

// staticSource serves one or more preloaded keypairs, dispatching by SNI. It
// satisfies CertSource for ModeStatic sites.
type staticSource struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate // host (lowercased) → cert
	// fallback is returned ONLY when the client sends no SNI at all (an IP client
	// or a pre-SNI client) — a single-cert deployment still works. A non-empty SNI
	// that matches no configured host is refused rather than served this cert, so an
	// arbitrary/unconfigured host cannot coax out a mismatched certificate (security
	// review #8). nil means "no certificate registered".
	fallback *tls.Certificate
}

func newStaticSource() *staticSource {
	return &staticSource{certs: map[string]*tls.Certificate{}}
}

// addKeyPair loads certFile/keyFile and registers it for each host. The first
// keypair added also becomes the fallback.
func (s *staticSource) addKeyPair(hosts []string, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading keypair (%s, %s): %w", certFile, keyFile, err)
	}
	s.addCert(hosts, &cert)
	return nil
}

// addKeyPairPEM parses an IN-MEMORY PEM keypair (certPEM/keyPEM) and registers it
// for each host. It is the BYO/cert-manager path: the keypair bytes come straight
// from a kubernetes.io/tls Secret (Ingress spec.tls), never a file on disk. A bad
// PEM is an error and registers nothing — the caller keeps its previous source.
func (s *staticSource) addKeyPairPEM(hosts []string, certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("loading keypair from PEM: %w", err)
	}
	s.addCert(hosts, &cert)
	return nil
}

// addCert registers an already-parsed certificate for each host.
func (s *staticSource) addCert(hosts []string, cert *tls.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fallback == nil {
		s.fallback = cert
	}
	for _, h := range hosts {
		s.certs[normalizeHost(h)] = cert
	}
}

// has reports whether any keypair is registered.
func (s *staticSource) has() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.fallback != nil
}

// lookup returns the certificate registered for a host (honoring wildcard
// registrations), or nil when none matches. It does NOT fall back — callers decide
// whether a no-SNI handshake may use the fallback (see GetCertificate).
func (s *staticSource) lookup(host string) *tls.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	host = normalizeHost(host)
	if c, ok := s.certs[host]; ok {
		return c
	}
	// Wildcard registration "*.example.com" covers "a.example.com".
	if i := indexByte(host, '.'); i >= 0 {
		if c, ok := s.certs["*"+host[i:]]; ok {
			return c
		}
	}
	return nil
}

// GetCertificate implements CertSource. A matching host returns its keypair. A
// client that sends NO SNI (ServerName == "") gets the fallback so IP/pre-SNI
// clients of a single-cert deployment still work. A non-empty SNI that matches no
// configured host is REFUSED (security review #8) — serving it the fallback would
// hand an arbitrary host a mismatched certificate (host-confusion aid).
func (s *staticSource) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := s.lookup(hello.ServerName); c != nil {
		return c, nil
	}
	if hello.ServerName == "" {
		s.mu.RLock()
		fb := s.fallback
		s.mu.RUnlock()
		if fb != nil {
			return fb, nil
		}
	}
	return nil, fmt.Errorf("tlsacme: no static certificate for %q", hello.ServerName)
}

// indexByte is strings.IndexByte without importing strings here.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
