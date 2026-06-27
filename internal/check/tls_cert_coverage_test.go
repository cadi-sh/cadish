package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// genCoverageCert writes a self-signed cert covering exactly dnsNames (its SANs)
// plus a matching key to dir, returning their basenames. Used to exercise the
// SPEC-MULTILINE-ADDR §4 static-cert coverage warning.
func genCoverageCert(t *testing.T, dir string, dnsNames ...string) (certName, keyName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writeBlock(t, filepath.Join(dir, "cert.pem"), "CERTIFICATE", der)
	writeBlock(t, filepath.Join(dir, "key.pem"), "EC PRIVATE KEY", keyDER)
	return "cert.pem", "key.pem"
}

// genCoverageCertWithIPs writes a self-signed cert carrying both DNS SANs and IP
// SANs, used to exercise Finding 4 (IP-literal coverage via cert.IPAddresses).
func genCoverageCertWithIPs(t *testing.T, dir string, dnsNames []string, ips []net.IP) (certName, keyName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: dnsNames[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writeBlock(t, filepath.Join(dir, "cert.pem"), "CERTIFICATE", der)
	writeBlock(t, filepath.Join(dir, "key.pem"), "EC PRIVATE KEY", keyDER)
	return "cert.pem", "key.pem"
}

func writeBlock(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func writeAndCheck(t *testing.T, dir, cadishfile string) *Report {
	t.Helper()
	path := filepath.Join(dir, "Cadishfile")
	if err := os.WriteFile(path, []byte(cadishfile), 0o600); err != nil {
		t.Fatalf("write Cadishfile: %v", err)
	}
	r, err := Check(path)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return r
}

// TestTLSCertCoverageWarnsOnUncoveredAddress is the loud-check half of
// SPEC-MULTILINE-ADDR: a static-cert site whose declared addresses include one
// NOT in the cert SANs must warn so the operator does not ship a cert that fails
// the real SNI handshake (the production 525). Here the cert covers a.example.com
// but the site also declares b.example.com.
func TestTLSCertCoverageWarnsOnUncoveredAddress(t *testing.T) {
	dir := t.TempDir()
	cert, key := genCoverageCert(t, dir, "a.example.com", "*.a.example.com")
	src := "a.example.com, *.a.example.com, b.example.com {\n" +
		"  tls cert " + cert + " key " + key + "\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-cert-uncovered-address"]; n != 1 {
		t.Fatalf("tls-cert-uncovered-address = %d, want 1; diags=%v", n, codes(r))
	}
}

// TestTLSCertCoverageIPSANCovered (Finding 4) ensures an IP-literal site address
// carried as a cert IP SAN is NOT falsely reported uncovered. The cert here has a
// DNS SAN plus an IP SAN; the site declares both that host and that IP literal.
func TestTLSCertCoverageIPSANCovered(t *testing.T) {
	dir := t.TempDir()
	cert, key := genCoverageCertWithIPs(t, dir, []string{"a.example.com"}, []net.IP{net.ParseIP("198.51.100.7")})
	src := "a.example.com, 198.51.100.7 {\n" +
		"  tls cert " + cert + " key " + key + "\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-cert-uncovered-address"]; n != 0 {
		t.Fatalf("tls-cert-uncovered-address = %d, want 0 (IP SAN covers the IP literal); diags=%v", n, codes(r))
	}
}

// TestTLSCertCoverageIPSANUncoveredStillWarns guards the other side: an IP literal
// address NOT in the cert's IP SANs still warns (no over-suppression).
func TestTLSCertCoverageIPSANUncoveredStillWarns(t *testing.T) {
	dir := t.TempDir()
	cert, key := genCoverageCertWithIPs(t, dir, []string{"a.example.com"}, []net.IP{net.ParseIP("198.51.100.7")})
	src := "a.example.com, 203.0.113.9 {\n" +
		"  tls cert " + cert + " key " + key + "\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-cert-uncovered-address"]; n != 1 {
		t.Fatalf("tls-cert-uncovered-address = %d, want 1 (203.0.113.9 not a SAN); diags=%v", n, codes(r))
	}
}

// TestTLSCertCoverageQuietWhenAllCovered ensures no false positive: when the cert
// SANs cover every declared address (including via a one-label wildcard), the
// warning does NOT fire. This also guards the multi-line parse fix end-to-end: the
// addresses span two lines and ALL must be seen by the coverage check.
func TestTLSCertCoverageQuietWhenAllCovered(t *testing.T) {
	dir := t.TempDir()
	cert, key := genCoverageCert(t, dir, "a.example.com", "*.a.example.com", "b.example.com", "*.b.example.com")
	src := "a.example.com, *.a.example.com,\n" +
		"b.example.com, *.b.example.com {\n" +
		"  tls cert " + cert + " key " + key + "\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-cert-uncovered-address"]; n != 0 {
		t.Fatalf("tls-cert-uncovered-address = %d, want 0 (all covered); diags=%v", n, codes(r))
	}
}
