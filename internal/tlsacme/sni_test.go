package tlsacme

import (
	"crypto/tls"
	"testing"
)

// TestStaticSourceSNIFallback verifies security review #8: a non-empty SNI that
// matches no configured host is REFUSED (not served the fallback cert), while a
// matching SNI gets its cert and a no-SNI client still gets the fallback.
func TestStaticSourceSNIFallback(t *testing.T) {
	certFile, keyFile := genSelfSigned(t, "good.local")
	s := newStaticSource()
	if err := s.addKeyPair([]string{"good.local"}, certFile, keyFile); err != nil {
		t.Fatal(err)
	}

	// Matching SNI → its certificate.
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "good.local"}); err != nil {
		t.Errorf("good.local refused: %v", err)
	}
	// Unmatched non-empty SNI → hard fail (no mismatched fallback cert).
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: "evil.local"}); err == nil {
		t.Error("evil.local was served a certificate; expected handshake refusal")
	}
	// No SNI (IP / pre-SNI client) → fallback so a single-cert deployment works.
	if _, err := s.GetCertificate(&tls.ClientHelloInfo{ServerName: ""}); err != nil {
		t.Errorf("no-SNI client refused: %v", err)
	}
}
