package check

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cadi-sh/cadish/internal/tlsacme"
)

// genMismatchedKeypair writes cert.pem (signed by key A, SANs cover host) and
// key.pem holding a DIFFERENT key B. Both files are present and individually valid
// PEM, and the cert SANs cover the host — so the existence and coverage passes are
// quiet — but the pair does not match, which is exactly what fails tls.X509KeyPair
// at run time.
func genMismatchedKeypair(t *testing.T, dir, host string) (certName, keyName string) {
	t.Helper()
	keyA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey A: %v", err)
	}
	keyB, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey B: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: host},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &keyA.PublicKey, keyA)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(keyB) // the WRONG key for this cert
	if err != nil {
		t.Fatalf("marshal key B: %v", err)
	}
	writeBlock(t, filepath.Join(dir, "cert.pem"), "CERTIFICATE", der)
	writeBlock(t, filepath.Join(dir, "key.pem"), "EC PRIVATE KEY", keyDER)
	return "cert.pem", "key.pem"
}

// TestTLSKeypairMismatchWarns is the check↔run fidelity guard for a static keypair:
// a present-but-mismatched cert/key pair (which `cadish run` rejects at startup via
// tls.LoadX509KeyPair) must be surfaced by `cadish check`, instead of passing clean
// and only blowing up at boot. It also confirms run really does reject it, so the
// two stay in lockstep.
func TestTLSKeypairMismatchWarns(t *testing.T) {
	dir := t.TempDir()
	cert, key := genMismatchedKeypair(t, dir, "a.example.com")
	src := "a.example.com {\n" +
		"  tls cert " + cert + " key " + key + "\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-keypair-invalid"]; n != 1 {
		t.Fatalf("tls-keypair-invalid = %d, want 1; diags=%v", n, codes(r))
	}
	// The coverage warning must NOT fire (the cert DOES cover the host) — this is a
	// pairing failure, not a coverage failure.
	if n := codes(r)["tls-cert-uncovered-address"]; n != 0 {
		t.Fatalf("tls-cert-uncovered-address = %d, want 0 (cert covers host)", n)
	}

	// Lockstep: `run` (NewManager → buildHostState → tls.LoadX509KeyPair) must reject
	// the SAME keypair, proving check now catches what run chokes on.
	if _, err := tlsacme.NewManager([]tlsacme.SiteConfig{
		{Hosts: []string{"a.example.com"}, TLS: tlsacme.SiteTLS{
			Mode:     tlsacme.ModeStatic,
			CertFile: filepath.Join(dir, cert),
			KeyFile:  filepath.Join(dir, key),
		}},
	}, tlsacme.Options{CacheDir: t.TempDir()}); err == nil {
		t.Fatal("run (NewManager) must reject a mismatched keypair — the divergence check exists to pre-empt")
	}
}

// TestTLSKeypairGarbageCertWarns covers the other half of the gap: a present but
// UNPARSEABLE cert (garbage bytes) also passes the structural pre-flight (which
// never loads it) and crashes run; check must warn. The coverage pass is silent on
// garbage (certDNSNames returns nil), so this pass is the only signal.
func TestTLSKeypairGarbageCertWarns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cert.pem"), []byte("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A valid key alongside the garbage cert.
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyDER, _ := x509.MarshalECPrivateKey(keyA)
	writeBlock(t, filepath.Join(dir, "key.pem"), "EC PRIVATE KEY", keyDER)

	src := "a.example.com {\n" +
		"  tls cert cert.pem key key.pem\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-keypair-invalid"]; n != 1 {
		t.Fatalf("tls-keypair-invalid = %d, want 1 for a garbage cert; diags=%v", n, codes(r))
	}
}

// TestTLSKeypairValidIsQuiet guards against a false positive: a matching, valid
// keypair must NOT warn.
func TestTLSKeypairValidIsQuiet(t *testing.T) {
	dir := t.TempDir()
	cert, key := genCoverageCert(t, dir, "a.example.com")
	src := "a.example.com {\n" +
		"  tls cert " + cert + " key " + key + "\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-keypair-invalid"]; n != 0 {
		t.Fatalf("tls-keypair-invalid = %d, want 0 for a valid pair; diags=%v", n, codes(r))
	}
}

// TestTLSKeypairAbsentDeferred confirms the pass stays quiet when files are ABSENT
// (deploy-time precondition already covered by fileExistenceWarnings) — it must not
// double-report or hard-fail a config authored for a different deploy host.
func TestTLSKeypairAbsentDeferred(t *testing.T) {
	dir := t.TempDir()
	src := "a.example.com {\n" +
		"  tls cert /nope/cert.pem key /nope/key.pem\n" +
		"  upstream u { to http://127.0.0.1:9 }\n" +
		"}\n"
	r := writeAndCheck(t, dir, src)
	if n := codes(r)["tls-keypair-invalid"]; n != 0 {
		t.Fatalf("tls-keypair-invalid = %d, want 0 when files are absent (deferred to existence pass)", n)
	}
}
