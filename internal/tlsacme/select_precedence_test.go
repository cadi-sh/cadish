package tlsacme

import (
	"crypto/tls"
	"testing"
)

// TestStaticSelect_ExactBeatsWildcard pins a load-bearing certificate-selection
// property that nothing else asserts: when a staticSource holds BOTH an exact
// keypair for "api.example.com" and a wildcard keypair for "*.example.com", an SNI
// of "api.example.com" must resolve to the EXACT cert (the more specific match),
// while a sibling subdomain falls to the wildcard. A regression here would silently
// serve the wrong (still-valid) cert for the exact host.
func TestStaticSelect_ExactBeatsWildcard(t *testing.T) {
	exactCert, exactKey := genSelfSignedPEM(t, "api.example.com")
	wildCert, wildKey := genSelfSignedPEM(t, "*.example.com")

	s := newStaticSource()
	// Register the WILDCARD first so a naive "first match / fallback wins" bug would
	// surface: exact precedence must hold regardless of registration order.
	if err := s.addKeyPairPEM([]string{"*.example.com"}, wildCert, wildKey); err != nil {
		t.Fatal(err)
	}
	if err := s.addKeyPairPEM([]string{"api.example.com"}, exactCert, exactKey); err != nil {
		t.Fatal(err)
	}

	// Exact SNI → exact cert (CN "api.example.com"), not the wildcard.
	got := s.lookup("api.example.com")
	if got == nil {
		t.Fatal("lookup(api.example.com) = nil, want the exact cert")
	}
	if cn := certCN(t, got); cn != "api.example.com" {
		t.Fatalf("exact host resolved to CN=%q, want api.example.com (wildcard shadowed the exact cert)", cn)
	}

	// A sibling subdomain with no exact entry → the wildcard cert.
	sib := s.lookup("img.example.com")
	if sib == nil {
		t.Fatal("lookup(img.example.com) = nil, want the wildcard cert")
	}
	if cn := certCN(t, sib); cn != "*.example.com" {
		t.Fatalf("sibling host resolved to CN=%q, want *.example.com", cn)
	}

	// A two-label-deep host is NOT covered by the one-label wildcard (consistent with
	// hostMatcher) → no cert.
	if deep := s.lookup("a.b.example.com"); deep != nil {
		t.Fatalf("lookup(a.b.example.com) = %q, want nil (one-label wildcard must not match two labels)", certCN(t, deep))
	}
}

// TestManagerSelect_StaticWildcardServesSubdomain confirms the same precedence end
// to end through Manager.getCertificate: a wildcard static keypair serves an
// arbitrary in-zone subdomain by SNI, while an out-of-zone SNI is refused (no
// fallback leak), and the exact host still wins when both are present.
func TestManagerSelect_StaticWildcardServesSubdomain(t *testing.T) {
	wildCertF, wildKeyF := genSelfSigned(t, "*.example.com")
	exactCertF, exactKeyF := genSelfSigned(t, "api.example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"*.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: wildCertF, KeyFile: wildKeyF}},
		{Hosts: []string{"api.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: exactCertF, KeyFile: exactKeyF}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}

	// In-zone subdomain → wildcard cert.
	c, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "img.example.com"})
	if err != nil {
		t.Fatalf("img.example.com: %v", err)
	}
	if cn := certCN(t, c); cn != "*.example.com" {
		t.Fatalf("img.example.com served CN=%q, want *.example.com", cn)
	}

	// Exact host → exact cert (exact beats wildcard even via the manager dispatch).
	c2, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "api.example.com"})
	if err != nil {
		t.Fatalf("api.example.com: %v", err)
	}
	if cn := certCN(t, c2); cn != "api.example.com" {
		t.Fatalf("api.example.com served CN=%q, want api.example.com", cn)
	}

	// Out-of-zone SNI → refused (no fallback to the wildcard for a host it does not cover).
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "evil.other.com"}); err == nil {
		t.Fatal("out-of-zone SNI must be refused, not served the wildcard fallback")
	}
}
