package tlsacme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// genSelfSignedPEM returns an in-memory self-signed ECDSA keypair (cert PEM, key
// PEM) for the given DNS names — the BYO/cert-manager Secret shape (tls.crt/tls.key)
// without touching disk.
func genSelfSignedPEM(t *testing.T, dnsNames ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: firstOr(dnsNames, "localhost")},
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
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// certCN returns the leaf certificate's CommonName, so a test can prove WHICH
// keypair a handshake resolved (used to assert a rotation actually swapped certs).
func certCN(t *testing.T, c *tls.Certificate) string {
	t.Helper()
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf.Subject.CommonName
}

// TestSetDynamicCerts_ServedBySNI proves a BYO Secret cert (in-memory PEM) is served
// for its host, an unconfigured SNI is REFUSED (no dynamic fallback / host
// confusion), and the dynamic set is independent of the (empty) Cadishfile state.
func TestSetDynamicCerts_ServedBySNI(t *testing.T) {
	m, err := NewManager(nil, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := genSelfSignedPEM(t, "byo.example.com")
	if err := m.SetDynamicCerts([]DynamicCert{{Hosts: []string{"byo.example.com"}, CertPEM: certPEM, KeyPEM: keyPEM}}); err != nil {
		t.Fatalf("SetDynamicCerts: %v", err)
	}

	got, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "byo.example.com"})
	if err != nil {
		t.Fatalf("byo host getCertificate: %v", err)
	}
	if cn := certCN(t, got); cn != "byo.example.com" {
		t.Fatalf("served wrong cert CN=%q", cn)
	}

	// Unconfigured SNI: no ACME, no static, no matching dynamic → refused (not the
	// dynamic cert as a fallback).
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "evil.example.com"}); err == nil {
		t.Fatal("unconfigured SNI must be refused, not served a dynamic cert")
	}
}

// TestDynamic_FastPathGate proves the lock-free gate: with no BYO certs the dynamic
// lookup is skipped (gate false) and static/ACME still serve; adding a cert flips the
// gate true; clearing it flips it back false.
func TestDynamic_FastPathGate(t *testing.T) {
	cert, key := genSelfSigned(t, "static.example.com")
	m, err := NewManager([]SiteConfig{
		{Hosts: []string{"static.example.com"}, TLS: SiteTLS{Mode: ModeStatic, CertFile: cert, KeyFile: key}},
	}, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if m.hasDynamic.Load() {
		t.Fatal("gate must be false with no BYO certs (zero-cost when absent)")
	}
	// The no-dynamic path still serves the static host and refuses an unknown SNI.
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "static.example.com"}); err != nil {
		t.Fatalf("static host must serve with no dynamic certs: %v", err)
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "nope.example.com"}); err == nil {
		t.Fatal("unknown SNI must still be refused with no dynamic certs")
	}

	certPEM, keyPEM := genSelfSignedPEM(t, "byo.example.com")
	if err := m.SetDynamicCerts([]DynamicCert{{Hosts: []string{"byo.example.com"}, CertPEM: certPEM, KeyPEM: keyPEM}}); err != nil {
		t.Fatal(err)
	}
	if !m.hasDynamic.Load() {
		t.Fatal("gate must be true after a BYO cert is added")
	}
	// Clearing the set flips the gate back off.
	if err := m.SetDynamicCerts(nil); err != nil {
		t.Fatal(err)
	}
	if m.hasDynamic.Load() {
		t.Fatal("gate must be false again after clearing the dynamic set")
	}
}

// TestSetDynamicCerts_RotationHotSwap proves rotating a Secret (re-issuing the
// keypair for the same host) hot-swaps the served cert — same Manager, no listener /
// tls.Config / autocert rebuild — and an existing other host keeps serving.
func TestSetDynamicCerts_RotationHotSwap(t *testing.T) {
	m, err := NewManager(nil, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	cert1, key1 := genSelfSignedPEM(t, "rotate.example.com")
	otherCert, otherKey := genSelfSignedPEM(t, "other.example.com")
	if err := m.SetDynamicCerts([]DynamicCert{
		{Hosts: []string{"rotate.example.com"}, CertPEM: cert1, KeyPEM: key1},
		{Hosts: []string{"other.example.com"}, CertPEM: otherCert, KeyPEM: otherKey},
	}); err != nil {
		t.Fatal(err)
	}
	dynBefore := m.dynamic.Load()

	// Re-issue rotate.example.com (a NEW serial) and re-apply with the same other host.
	cert2, key2 := genSelfSignedPEM(t, "rotate.example.com")
	if err := m.SetDynamicCerts([]DynamicCert{
		{Hosts: []string{"rotate.example.com"}, CertPEM: cert2, KeyPEM: key2},
		{Hosts: []string{"other.example.com"}, CertPEM: otherCert, KeyPEM: otherKey},
	}); err != nil {
		t.Fatal(err)
	}
	if m.dynamic.Load() == dynBefore {
		t.Fatal("dynamic source pointer should have been swapped on rotation")
	}

	got, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "rotate.example.com"})
	if err != nil {
		t.Fatalf("after rotation: %v", err)
	}
	// Each issuance uses a fresh key, so the served cert bytes must now differ from
	// the first keypair — proving the rotation actually swapped the served cert.
	if string(got.Certificate[0]) == string(mustCert(t, cert1, key1).Certificate[0]) {
		t.Fatal("rotation did not change the served certificate bytes")
	}
	// Untouched host keeps serving.
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "other.example.com"}); err != nil {
		t.Fatalf("other host must keep serving across rotation: %v", err)
	}
}

func mustCert(t *testing.T, certPEM, keyPEM []byte) tls.Certificate {
	t.Helper()
	c, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestSetDynamicCerts_BadPEMFailSafe proves a bad PEM is a fail-safe error: the
// previous dynamic set keeps serving, nothing is partially swapped.
func TestSetDynamicCerts_BadPEMFailSafe(t *testing.T) {
	m, err := NewManager(nil, Options{CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	good, goodKey := genSelfSignedPEM(t, "keep.example.com")
	if err := m.SetDynamicCerts([]DynamicCert{{Hosts: []string{"keep.example.com"}, CertPEM: good, KeyPEM: goodKey}}); err != nil {
		t.Fatal(err)
	}

	// A batch with one garbage PEM must be rejected wholesale.
	newGood, newGoodKey := genSelfSignedPEM(t, "new.example.com")
	err = m.SetDynamicCerts([]DynamicCert{
		{Hosts: []string{"new.example.com"}, CertPEM: newGood, KeyPEM: newGoodKey},
		{Hosts: []string{"bad.example.com"}, CertPEM: []byte("not a pem"), KeyPEM: []byte("nope")},
	})
	if err == nil {
		t.Fatal("a bad PEM in the batch must return an error")
	}
	// Old set kept: keep.example.com still serves; the half-applied new host does NOT.
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "keep.example.com"}); err != nil {
		t.Fatalf("old dynamic cert must keep serving after a failed swap: %v", err)
	}
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "new.example.com"}); err == nil {
		t.Fatal("a rejected batch must not partially apply new.example.com")
	}
}

// TestForceACME_StartsTLSCapableWithNoHosts proves Ingress-mode startup: ForceACME
// builds the autocert source with ZERO ACME hosts (NeedsTLS true so :443 binds), an
// unknown-SNI handshake fails cleanly (no panic, no open issuer), and a reconcile
// (Reload) that adds a host makes it issuable live — same source, no restart.
func TestForceACME_StartsTLSCapableWithNoHosts(t *testing.T) {
	m, err := NewManager(nil, Options{CacheDir: t.TempDir(), ForceACME: true, ACMEEmail: "ops@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.NeedsTLS() {
		t.Fatal("ForceACME must make the manager TLS-capable so the server binds :443")
	}
	if m.acme == nil {
		t.Fatal("ForceACME must build the autocert source at startup")
	}
	acmeBefore := m.acme
	if m.HostAllowed("late.example.com") {
		t.Fatal("HostPolicy must start empty (never an open issuer)")
	}
	// Unknown-SNI handshake must fail cleanly (HostPolicy rejects before any network).
	if _, err := m.getCertificate(&tls.ClientHelloInfo{ServerName: "unknown.example.com"}); err == nil {
		t.Fatal("unknown SNI with an empty allow-list must fail (not issue)")
	}

	// A reconcile adds an ACME host (Cadishfile path → Reload). It becomes issuable
	// immediately, with the SAME autocert source.
	if err := m.Reload([]SiteConfig{
		{Hosts: []string{"late.example.com"}, TLS: SiteTLS{Mode: ModeACME, Email: "ops@example.com"}},
	}); err != nil {
		t.Fatalf("reload add: %v", err)
	}
	if m.acme != acmeBefore {
		t.Fatal("Reload must NOT rebuild the autocert source")
	}
	if !m.HostAllowed("late.example.com") {
		t.Fatal("the reconcile-added host must be issuable without a restart")
	}
}
